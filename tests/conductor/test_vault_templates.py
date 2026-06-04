"""Phase D1 — Vault template stripping + template_executor unit tests.

Tests:
 1. embeddable_text() strips EXEC-TEMPLATE block correctly.
 2. embeddable_text() is idempotent on content without a template block.
 3. load_template() parses a valid EXEC-TEMPLATE block from inline content.
 4. render_payload() substitutes ctx values correctly.
 5. render_payload() raises NeedsSession when requires_session=True and 'session' absent.
 6. render_payload() raises MissingContext when a placeholder key is absent.
 7. embeddable_text() stripping ensures EXEC-TEMPLATE does not appear in embedded text.
"""
from __future__ import annotations

import textwrap


# ── Test 1: embeddable_text strips EXEC-TEMPLATE block ───────────────────────


def test_embeddable_text_strips_template_block():
    from apps.conductor.qwen.vault_embedder import embeddable_text

    raw = textwrap.dedent("""
        # Concept Title
        Some prose about the vulnerability.
        <!-- EXEC-TEMPLATE-START -->
        ```yaml
        execution_template:
          engine_id: access_control
          method: GET
        ```
        <!-- EXEC-TEMPLATE-END -->
        More prose after the template.
    """).strip()

    result = embeddable_text(raw)
    assert "EXEC-TEMPLATE-START" not in result
    assert "EXEC-TEMPLATE-END" not in result
    assert "execution_template" not in result
    assert "Concept Title" in result
    assert "Some prose" in result
    assert "More prose after" in result


# ── Test 2: embeddable_text is idempotent on template-free content ────────────


def test_embeddable_text_passthrough_no_template():
    from apps.conductor.qwen.vault_embedder import embeddable_text

    raw = "# Plain concept\n\nNo template here."
    assert embeddable_text(raw) == raw


# ── Test 3: load_template() parses valid block ────────────────────────────────


def test_load_template_parses_valid_block(tmp_path, monkeypatch):
    """load_template() returns an ExecutionTemplate when a valid block is present."""
    import apps.conductor.template_executor as te

    # Point vault path to a temp dir with one concept file
    concept_dir = tmp_path / "concepts"
    concept_dir.mkdir()
    concept_file = concept_dir / "concept-nosql-injection.md"
    concept_file.write_text(textwrap.dedent("""
        # NoSQL Injection
        Prose content here.
        <!-- EXEC-TEMPLATE-START -->
        ```yaml
        execution_template:
          engine_id: access_control
          method: GET
          endpoint_pattern: "/user/lookup"
          payload_template:
            user: "{{username}}'||'1'=='1"
          success_condition:
            status_codes: [200]
            response_contains: "administrator"
          requires_session: false
        ```
        <!-- EXEC-TEMPLATE-END -->
    """))

    # Monkeypatch VAULT_PATH so loader finds our temp file
    monkeypatch.setattr(te, "_SCAN_DIRS", [concept_dir])

    tmpl = te.load_template("CONCEPT-NOSQL-INJECTION")
    assert tmpl is not None
    assert tmpl.engine_id == "access_control"
    assert tmpl.method == "GET"
    assert tmpl.endpoint_pattern == "/user/lookup"
    assert "user" in tmpl.payload_template
    assert tmpl.requires_session is False
    assert tmpl.success_condition["status_codes"] == [200]


# ── Test 4: render_payload() substitutes ctx values ──────────────────────────


def test_render_payload_substitutes_context(tmp_path, monkeypatch):
    import apps.conductor.template_executor as te

    concept_dir = tmp_path / "concepts"
    concept_dir.mkdir()
    (concept_dir / "concept-nosql-injection.md").write_text(textwrap.dedent("""
        <!-- EXEC-TEMPLATE-START -->
        ```yaml
        execution_template:
          engine_id: access_control
          method: GET
          endpoint_pattern: "/user/lookup"
          payload_template:
            user: "{{username}}'||'1'=='1"
          success_condition:
            status_codes: [200]
          requires_session: false
        ```
        <!-- EXEC-TEMPLATE-END -->
    """))
    monkeypatch.setattr(te, "_SCAN_DIRS", [concept_dir])

    tmpl = te.load_template("CONCEPT-NOSQL-INJECTION")
    assert tmpl is not None

    payload = te.render_payload(tmpl, {"username": "wiener"})
    assert payload == {"user": "wiener'||'1'=='1"}


# ── Test 5: render_payload raises NeedsSession ────────────────────────────────


def test_render_payload_raises_needs_session(tmp_path, monkeypatch):
    import apps.conductor.template_executor as te

    concept_dir = tmp_path / "concepts"
    concept_dir.mkdir()
    (concept_dir / "concept-js-spider.md").write_text(textwrap.dedent("""
        <!-- EXEC-TEMPLATE-START -->
        ```yaml
        execution_template:
          engine_id: js_spider
          method: GET
          endpoint_pattern: "/user/lookup"
          payload_template:
            user: "{{username}}"
          success_condition:
            status_codes: [200]
          requires_session: true
        ```
        <!-- EXEC-TEMPLATE-END -->
    """))
    monkeypatch.setattr(te, "_SCAN_DIRS", [concept_dir])

    tmpl = te.load_template("CONCEPT-JS-SPIDER")
    assert tmpl is not None
    assert tmpl.requires_session is True

    import pytest
    with pytest.raises(te.NeedsSession):
        te.render_payload(tmpl, {"username": "wiener"})  # no session key


# ── Test 6: render_payload raises MissingContext ──────────────────────────────


def test_render_payload_raises_missing_context(tmp_path, monkeypatch):
    import apps.conductor.template_executor as te

    concept_dir = tmp_path / "concepts"
    concept_dir.mkdir()
    (concept_dir / "concept-access-control.md").write_text(textwrap.dedent("""
        <!-- EXEC-TEMPLATE-START -->
        ```yaml
        execution_template:
          engine_id: access_control
          method: GET
          endpoint_pattern: "{{endpoint}}"
          payload_template:
            id: "{{username}}"
          success_condition:
            status_codes: [200]
          requires_session: false
        ```
        <!-- EXEC-TEMPLATE-END -->
    """))
    monkeypatch.setattr(te, "_SCAN_DIRS", [concept_dir])

    tmpl = te.load_template("CONCEPT-ACCESS-CONTROL")
    assert tmpl is not None

    import pytest
    with pytest.raises(te.MissingContext):
        te.render_payload(tmpl, {})  # no username, no endpoint


# ── Test 7: embeddable_text ensures template absent from embedding input ──────


def test_embeddable_text_template_not_in_embedding():
    """Core constraint: EXEC-TEMPLATE block must not enter the embedding."""
    from apps.conductor.qwen.vault_embedder import embeddable_text

    # Simulate a document with BOTH prose (signal) and a YAML template (noise)
    prose = "NoSQL injection MongoDB filter bypass category parameter operator."
    template_yaml = """
<!-- EXEC-TEMPLATE-START -->
```yaml
execution_template:
  engine_id: access_control
  method: GET
  endpoint_pattern: "/user/lookup"
  payload_template:
    user: "unique_template_marker_xyz123"
  success_condition:
    status_codes: [200]
  requires_session: false
```
<!-- EXEC-TEMPLATE-END -->
    """.strip()

    raw_with_template    = prose + "\n\n" + template_yaml
    raw_without_template = prose

    stripped = embeddable_text(raw_with_template)
    clean    = embeddable_text(raw_without_template)

    # Stripped version should not contain template-specific content
    assert "unique_template_marker_xyz123" not in stripped
    # Both should produce the same embeddable text
    assert stripped == clean
