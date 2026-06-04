"""
Backend fingerprinting from a single HTTP response.

We only inspect what the response already gave us — no extra requests, no
deeper crawling. The label is a coarse hint to help route verification
(e.g. nginx + java/atlassian → check vendor advisory, not rpm).

Returned labels:
  java                — generic Java servlet container (JSESSIONID)
  java/atlassian      — Atlassian product, sub-product unknown
  java/jira           — Jira
  java/confluence     — Confluence
  java/bitbucket      — Bitbucket
  java/tomcat         — Tomcat (Apache-Coyote server)
  java/jetty          — Jetty
  php                 — generic PHP
  php/wordpress       — WordPress
  php/drupal          — Drupal
  php/laravel         — Laravel
  node                — Node.js (Express / connect.sid)
  python              — Python (gunicorn/uvicorn)
  python/django       — Django
  asp.net             — Microsoft IIS / ASP.NET
  ruby                — Ruby (passenger / _session_id)
  unknown             — no signal matched
"""

from __future__ import annotations

import re
from collections.abc import Mapping

import httpx

# Cookie name → backend label. Most specific first.
_COOKIE_RULES: tuple[tuple[str, str], ...] = (
    ("BITBUCKETSESSIONID", "java/bitbucket"),
    ("JIRA-SESSIONID", "java/jira"),
    ("CONFLUENCE.SESSIONID", "java/confluence"),
    ("CONFLUENCESID", "java/confluence"),
    ("ATLASSIAN.XSRF.TOKEN", "java/atlassian"),
    ("JSESSIONID", "java"),
    ("ASP.NET_SessionId", "asp.net"),
    (".ASPXAUTH", "asp.net"),
    ("PHPSESSID", "php"),
    ("laravel_session", "php/laravel"),
    ("connect.sid", "node"),
    ("django_session", "python/django"),
    ("sessionid", "python/django"),
    ("_session_id", "ruby"),
    ("_rails_session", "ruby"),
)

_XPOWERED_RULES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"servlet|jsp", re.I), "java"),
    (re.compile(r"php", re.I), "php"),
    (re.compile(r"express", re.I), "node"),
    (re.compile(r"asp\.net", re.I), "asp.net"),
)

_SERVER_RULES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"apache-coyote", re.I), "java/tomcat"),
    (re.compile(r"jetty", re.I), "java/jetty"),
    (re.compile(r"gunicorn|uvicorn|werkzeug", re.I), "python"),
    (re.compile(r"passenger", re.I), "ruby"),
    (re.compile(r"iis", re.I), "asp.net"),
)

_BODY_RULES: tuple[tuple[re.Pattern, str], ...] = (
    # Java / vendor apps
    (re.compile(r'meta\s+name=["\']ajs-version-number["\']', re.I), "java/atlassian"),
    (re.compile(r'content=["\']Atlassian Confluence', re.I), "java/confluence"),
    (re.compile(r'content=["\']Atlassian Jira', re.I), "java/jira"),
    (re.compile(r'content=["\']Atlassian Bitbucket', re.I), "java/bitbucket"),
    (re.compile(r";jsessionid=", re.I), "java"),
    # PHP / CMS
    (re.compile(r'content=["\']WordPress', re.I), "php/wordpress"),
    (re.compile(r'content=["\']Drupal', re.I), "php/drupal"),
    # Python
    (re.compile(r"csrfmiddlewaretoken", re.I), "python/django"),
    # Default install pages — the host is just running the OS-packaged web server
    # with no real site configured. Useful signal: "you're looking at a default
    # install, the OS package is the only thing here."
    (re.compile(r"rocky-poweredby", re.I), "default/rocky-test-page"),
    (re.compile(r"HTTP Server Test Page powered by:?\s*Rocky", re.I), "default/rocky-test-page"),
    (re.compile(r"HTTP Server Test Page powered by:?\s*CentOS", re.I), "default/centos-test-page"),
    (re.compile(r"HTTP Server Test Page powered by:?\s*AlmaLinux", re.I), "default/alma-test-page"),
    (re.compile(r"<title>\s*Welcome to nginx", re.I), "default/nginx-welcome"),
    (re.compile(r"<title>\s*Apache HTTP Server Test Page", re.I), "default/apache-test-page"),
    (re.compile(r"<title>\s*Welcome to CentOS", re.I), "default/centos-welcome"),
    (re.compile(r"<title>\s*Test Page for the Nginx", re.I), "default/nginx-welcome"),
)

_BODY_BYTE_LIMIT = 16384
_TEXTUAL_PREFIXES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml",
    "application/javascript",
)


def _safe_body(response: httpx.Response) -> str:
    ctype = response.headers.get("Content-Type", "").lower()
    if ctype and not ctype.startswith(_TEXTUAL_PREFIXES):
        return ""
    try:
        text = response.text or ""
    except Exception:
        return ""
    return text[:_BODY_BYTE_LIMIT]


def _cookie_names(response: httpx.Response) -> set[str]:
    names: set[str] = set()
    try:
        names.update(response.cookies.keys())
    except Exception:
        pass
    # Belt-and-braces: also parse Set-Cookie raw, in case httpx's jar choked.
    for value in _multi_header(response.headers, "set-cookie"):
        head = value.split(";", 1)[0]
        if "=" in head:
            names.add(head.split("=", 1)[0].strip())
    return {n.lower() for n in names if n}


def _multi_header(headers: Mapping[str, str], name: str) -> list[str]:
    if hasattr(headers, "get_list"):
        try:
            return list(headers.get_list(name))  # type: ignore[attr-defined]
        except Exception:
            pass
    raw = headers.get(name, "")
    return [raw] if raw else []


def detect_backend(response: httpx.Response) -> str:
    cookies = _cookie_names(response)
    for marker, label in _COOKIE_RULES:
        if marker.lower() in cookies:
            return label

    xp = response.headers.get("X-Powered-By", "")
    for pat, label in _XPOWERED_RULES:
        if pat.search(xp):
            return label

    server = response.headers.get("Server", "")
    for pat, label in _SERVER_RULES:
        if pat.search(server):
            return label

    body = _safe_body(response)
    if body:
        for pat, label in _BODY_RULES:
            if pat.search(body):
                return label

    return "unknown"
