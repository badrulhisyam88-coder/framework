# Categorization Pipeline Trace — V2.3 Live Investigation

**Date:** 2026-05-28
**Trigger:** Exploitation tab sidebar shows "Uncategorized: 14" during live V2.3 investigation
against PortSwigger lab. Read-only trace of the full categorization pipeline.

---

## 1. What "Uncategorized: 14" means

The sidebar category tree (element `#category-tree`, visible only when
`_activePhase === 'exploitation'`) is populated in `workspace.js:444–476`.
Each category button renders `cat.stage_count` as a badge:

```
workspace.js:452–455
  var capBadge = cat.capture_count > 0
    ? '... N captures ...'
    : '<span class="text-xs text-[#656d76]">' + cat.stage_count + '</span>';
```

`stage_count = len(flat_cards)` computed at `routes.py:738`. `flat_cards` is
the result of `_collect_with_parent(cat_node["id"])` (`routes.py:723`), a DFS
walk from the Uncategorized category node through every descendant topology
node that `_node_to_stage_card()` converts to a non-None card.

**Card types counted:**
- `ntype == "finding"` (non-ghost) → `"stage"` card (`routes.py:651–658`)
- `ntype in ("finding","action")` with `ghost_state == "ghost"` → `"ready"` card (`routes.py:632–648`)
- `ntype == "execution_stage"` → `"stage"` card (`routes.py:660–669`)
- `ntype == "outcome"` → `"stage"` or `"warning"` card (`routes.py:671–689`)
- `ntype == "capture"` → `"capture"` card (`routes.py:691–708`)
- `ntype` in `{surface, category, exploitation_path}` → `None` (transparent, `routes.py:710`)

Uncategorized findings have **zero suggestions** registered in
`suggestions/catalog.py` → no ghost actions → no `"ready"` cards. And no
operator-triggered probe runs exist against them (no Execute button) → no
execution stages. Therefore:

```
stage_count = number of uncategorized findings × 1 stage card each
            = 14 (this investigation)
```

---

## 2. Root cause — FINDING_TYPE_TO_CATEGORY gap

**File:** `apps/investigation_workspace/categories/catalog.py:95–133`

```python
FINDING_TYPE_TO_CATEGORY: dict[str, Category] = {
    "missing_csp_header":              SECURITY_MISCONFIGURATION,
    "missing_hsts_header":             SECURITY_MISCONFIGURATION,
    "missing_x_frame_options":         SECURITY_MISCONFIGURATION,
    "missing_x_content_type_options":  SECURITY_MISCONFIGURATION,
    "missing_referrer_policy":         SECURITY_MISCONFIGURATION,
    "missing_permissions_policy":      SECURITY_MISCONFIGURATION,
    "weak_csp_directive":              SECURITY_MISCONFIGURATION,
    "verbose_error_response":          INFORMATION_DISCLOSURE,
    "server_version_leaked":           INFORMATION_DISCLOSURE,
    "directory_listing":               INFORMATION_DISCLOSURE,
    "stack_trace_leaked":              INFORMATION_DISCLOSURE,
    "http_service_detected":           INFRASTRUCTURE_EXPOSURE,
    "open_port_detected":              INFRASTRUCTURE_EXPOSURE,
    "service_banner_disclosed":        INFRASTRUCTURE_EXPOSURE,
    "sqli":                            SQL_INJECTION,
    ...
    "login_form_detected":             AUTHENTICATION,
    "api_exposure":                    API_SECURITY,
    "api_idor":                        API_SECURITY,
    "api_bola":                        API_SECURITY,
}
```

`for_finding_type()` at line 136–138:

```python
def for_finding_type(finding_type: str) -> Category:
    return FINDING_TYPE_TO_CATEGORY.get(finding_type or "", UNCATEGORIZED)
```

Any finding_type absent from this dict returns `UNCATEGORIZED`. The dict was
written to mirror the suggestion catalog's finding_types. The scanner
normalizer outputs and secondary recon probe outputs were never added.

---

## 3. The 14 uncategorized items

The 14 are one stage card per finding in the Uncategorized category node for
this investigation. Each is a finding whose `finding_type` is absent from
`FINDING_TYPE_TO_CATEGORY`. The finding_id for probe findings is deterministic:
`SHA-256(probe_id + "|" + target + "|" + path + "|" + finding_type)[:12]`
prefixed with `"fnd_"` (`probe/finding_id.py:28–47`). Exact finding_ids for a
specific lab target require querying:

```sql
SELECT finding_id, finding_type, title, severity
FROM normalized_findings
WHERE investigation_id = '<id>'
  AND finding_type NOT IN (
    'missing_csp_header','missing_hsts_header','missing_x_frame_options',
    'missing_x_content_type_options','missing_referrer_policy',
    'missing_permissions_policy','weak_csp_directive',
    'verbose_error_response','server_version_leaked','directory_listing',
    'stack_trace_leaked','http_service_detected','open_port_detected',
    'service_banner_disclosed','sqli','sqli_error_based','sqli_blind',
    'command_injection','xss','xss_reflected','xss_stored','xss_dom',
    'auth_bypass','weak_credentials','default_credentials',
    'login_form_detected','api_exposure','api_idor','api_bola'
  );
```

### 3a. Finding_types from probe/passive.py

| finding_type | probe | line | condition |
|---|---|---|---|
| `verbose_banner_disclosed` | `passive_probe` | `passive.py:218` | Server/X-Powered-By header contains version string |
| `waf_cdn_detected` | `passive_probe` | `passive.py:310` | Any of 9 WAF/CDN signature headers present (cf-ray, x-amz-cf-id, x-served-by, x-cache, x-akamai-transformed, x-sucuri-id, x-iinfo, x-cdn, x-amz-cf-pop) |
| `http_methods_advertised` | `passive_probe` | `passive.py:372` | OPTIONS response includes Allow header |

`_PROBE_ID = "passive_probe"` (`passive.py:23`). One finding per condition
per target root. Expected finding_id pattern:
`generate_finding_id("passive_probe", target, "/", finding_type)`.

### 3b. Finding_types from probe/fingerprint_recon.py

| finding_type | probe | line | condition |
|---|---|---|---|
| `framework_fingerprinted` | `fingerprint_recon` | `fingerprint_recon.py:149` | One finding **per distinct framework** with ≥1 signal (cookie name, HTML comment, asset path pattern). Multiple frameworks → multiple findings. |
| `stack_trace_disclosed` | `fingerprint_recon` | `fingerprint_recon.py:182` | 404/error-trigger response body matches `_STACK_TRACE` regex |
| `custom_404_handler` | `fingerprint_recon` | `fingerprint_recon.py:208` | Non-existent path returns HTTP 200 — PortSwigger labs virtually always trigger this |

`_PROBE_ID = "fingerprint_recon"` (inferred from `generate_finding_id` call
at `fingerprint_recon.py:166`). `framework_fingerprinted` finding_id uses the
framework name as a distinguishing suffix:
`generate_finding_id("fingerprint_recon", target, root_path, f"framework_fingerprinted_{fw}")`.

### 3c. Finding_types from probe/wellknown_recon.py

| finding_type | probe | line | condition |
|---|---|---|---|
| `wellknown_file_disclosed` | `wellknown_recon` | `wellknown_recon.py:120` | One finding per accessible path in `WELLKNOWN_PATHS` (`wellknown_recon.py:17–25`): `/robots.txt`, `/sitemap.xml`, `/humans.txt`, `/security.txt`, `/.well-known/security.txt`, `/.well-known/openapi.json`, `/.well-known/change-password` |
| `sensitive_file_disclosed` | `wellknown_recon` | `wellknown_recon.py:161` | One finding per accessible path in `SENSITIVE_FILE_PATHS` (`wellknown_recon.py:27–41`): `/.env`, `/.git/config`, `/.git/HEAD`, `/.DS_Store`, `/backup.*`, `/config.*`, `/dump.sql`, `/database.sql`, `/web.config.bak` |

`_PROBE_ID = "wellknown_recon"` (`wellknown_recon.py:62`). `/robots.txt` is
the most common hit on PortSwigger labs. Each accessible path produces a
separate finding. Expected:
`generate_finding_id("wellknown_recon", target, path, "wellknown_file_disclosed")`.

### 3d. Finding_types from probe/cors_recon.py

| finding_type | probe | line | condition |
|---|---|---|---|
| `permissive_cors` | `cors_recon` | `cors_recon.py:94` | CORS preflight returns permissive Access-Control-Allow-Origin |

### 3e. Finding_types from scanner_orchestration/normalization/nmap_normalizer.py

The nmap **scanner orchestration** normalizer (not the conductor V2 nmap engine)
produces these via `_classify_service()` at `nmap_normalizer.py:108–117`:

| finding_type | source line | service/condition |
|---|---|---|
| `service_exposure` | `nmap_normalizer.py:12–14` | One per open port for: http (port 80), https (port 443), ssh, vnc, rdp, mysql, mssql, postgresql |
| `cleartext_transmission` | `nmap_normalizer.py:14–16` | ftp, telnet, or ports 21/23 — **reference scenario includes port 23 (telnet), so this fires** |
| `smb_exposure` | `nmap_normalizer.py:16` | smb service detected |
| `open_port` | `nmap_normalizer.py:117` | Fallback for any port not matching `_HIGH_INTEREST_SERVICES` or port-based rules |
| `information_disclosure` | `nmap_normalizer.py:136` | NSE script fallback when `script_id` doesn't match `_NSE_MAP` |
| `tls_weakness` | `nmap_normalizer.py:122` | NSE `ssl-cert` or `ssl-dh-params` script |
| `known_vulnerability` | `nmap_normalizer.py:128` | NSE `vuln` script |

For a PortSwigger lab with the reference scenario (port 23 + HTTP/HTTPS):
- `service_exposure` × 2 (port 80 http, port 443 https) = 2 findings
- `cleartext_transmission` × 1 (port 23 telnet) = 1 finding

These have no `probe_id`-based finding_ids — they use the NormalizedFinding
model (`scanner_orchestration/normalization/models.py`), which gets its ID
from the DB insert.

### 3f. Finding_types from conductor V2 engines (exploitation phase, if reached)

| finding_type | engine | line | condition |
|---|---|---|---|
| `service_detected` | `nmap_engine` | `nmap_engine.py:249` | Conductor V2 nmap engine; reads `service_detected` findings from DB (`metasploit_recipe_engine.py:93`) — note mismatch with nmap_normalizer output below |
| `zap_endpoint_discovered` | `zap_engine` | `zap_engine.py:185` | ZAP spider run |
| `zap_alert` | `zap_engine` | `zap_engine.py:216` | ZAP passive/active scan alert |
| `msf_session_opened` | `metasploit_recipe_engine` | `metasploit_recipe_engine.py:341` | MSF session opened |
| `msf_module_success` | `metasploit_recipe_engine` | `metasploit_recipe_engine.py:344` | MSF module succeeded, no session |

These only appear if the exploitation phase has run these engines. Not expected
in a fresh V2.3 verification session.

---

## 4. Frontend grouping logic

### 4a. Topology category node emission

**File:** `apps/investigation_workspace/branch/topology_v2.py`

```
serialize_topology(view) → {nodes, edges, meta}
  ↓ line 93
  _group_findings_by_category(view)       # all DISCOVERY nodes, NO phase filter
  ↓ line 437–460
    for branch in view.branches:
      for discovery in branch.root.children:
        cat = for_finding_type(discovery.finding_type or "")  # catalog.py:136
        → by_cat[cat.category_id].append(discovery)
  ↓ line 96
  _emit_category_node(cat, len(discoveries), nodes)  # topology_v2.py:413
    → type="category", data.category_id = cat.category_id
  ↓ line 102
  edges: surface → category → finding (synthesized topology)
```

`_group_findings_by_category()` at `topology_v2.py:437` includes ALL findings
across ALL branches with NO phase filter. Recon-phase findings appear in the
category tree alongside enumeration-phase findings.

### 4b. Sidebar rendering

**File:** `frontend/static/js/workspace.js`

```
_renderCategories(data)                   # workspace.js:444
  ↓
  cats = data.categories                  # line 446
  ↓ line 449–476
  #category-tree innerHTML = cats.map(...)
    cat.stage_count as capBadge           # line 455
    cat.label as button text              # line 468
  tree.classList.remove('hidden')         # line 475  ← only when _activePhase === 'exploitation'
  ↓ line 499
  _renderExploitCategoryTabs(cats)        # separate horizontal tabs in Exploitation pane
```

The sidebar category tree at `#category-tree` is **always populated** from
`data.categories` on every polling cycle, but **hidden except when the
Exploitation tab is active** (`workspace.js:74` via `setActivePhase()`).

The horizontal `#exploit-cat-tabs` buttons (`workspace.js:161–196`) show only
`cat.label` with no count badge — they are a filter for the React Flow mindmap
and do not display `stage_count`.

### 4c. Exploit tree category filtering

**File:** `frontend/static/js/workspace.js:238–269`

```js
function _filterTreeByCategory(treeData, categorySlug) {
  // Finding nodes carry category_id from server; match directly.
  matchedFindingIds = nodes where data.kind==='finding' AND data.category_id===categorySlug
  // Collect child action nodes of matched findings
  return {filteredNodes, filteredEdges}
}
```

The React Flow mindmap filters by `category_id` on the **finding node**, not
on action nodes. Action nodes inherit their parent finding's category. If the
operator selects the "Uncategorized" tab in `#exploit-cat-tabs`, only findings
with `category_id = "uncategorized"` and their action children are shown.

### 4d. workspace-data.json categories construction

**File:** `apps/investigation_workspace/api/routes.py:712–744`

```python
cat_nodes = [n for n in nodes if n.get("type") == "category"]  # line 715
for cat_node in cat_nodes:
    flat_cards  = _collect_with_parent(cat_node["id"])          # line 723
    stage_tree  = _build_stage_tree(flat_cards)                 # line 724
    categories.append({
        "slug":          cat_slug,
        "label":         cat_label,
        "stage_count":   len(flat_cards),                       # line 738
        "capture_count": capture_count,
        "stage_tree":    stage_tree,
        ...
    })
```

`_collect_with_parent()` is a DFS from the category node, yielding one card
per renderable topology node (`routes.py:558–599`). `_node_to_stage_card()`
at `routes.py:624–710` maps node types to card types; `category` and
`exploitation_path` nodes return `None` (transparent/skip).

---

## 5. Exploit topology node generation path

### 5a. Full pipeline

```
Investigation start
  → WorkspaceView.from_db(investigation_id)
  → serialize_topology(view)                    topology_v2.py:76
      → _group_findings_by_category(view)       topology_v2.py:437
      → _emit_category_node(cat, ...)           topology_v2.py:413
      → _emit_node(disc, ...)                   topology_v2.py:761
      → _emit_exploitation_paths(disc, ...)     topology_v2.py:681
      → _emit_subtree(disc, ...)                topology_v2.py:797
      → _overlay_execution_runs(runs, ...)      topology_v2.py:202
      → _emit_ghost_actions(view, runs, ...)    topology_v2.py:476
  → _build_workspace_data(topology, ...)        routes.py:531
      → _build_exploit_tree(nodes, edges, ...)  routes.py:844
```

### 5b. Finding node fields

Emitted at `routes.py:891–905` inside `_build_exploit_tree()`:

```python
{
    "kind":          "finding",
    "label":         d.get("title", "Finding"),
    "sub_label":     d.get("finding_type", ""),
    "category_id":   _cat_for_type(d.get("finding_type", "")).category_id,  # line 897
    "finding_id":    fid,
    "node_id":       node["id"],
    "execute_url":   None,
    "executed":      False,
    "guidance_only": False,
    "action_kind":   "",
}
```

`category_id` is computed at node-build time via `for_finding_type()` from
`categories/catalog.py:136`. Action nodes do **not** carry their own
`category_id` — they inherit the parent finding's category via the tree
structure.

### 5c. Exploit tree phase filter

`routes.py:882–884`:

```python
if phase_map and phase_map.get(fid) == "recon":
    continue
```

Recon-phase findings are **excluded from the exploit tree** (the React Flow
mindmap in the Exploitation pane). They are **not excluded** from the sidebar
category tree (`_group_findings_by_category()` has no phase filter at
`topology_v2.py:449`). This is why "Uncategorized: 14" appears even though the
mindmap may show fewer nodes — all recon findings (including uncategorized
ones) count in the sidebar.

---

## 6. Finding-to-engine/category mapping catalog

Three independent mappings. All have the same set of recognized finding_types.
Uncategorized finding_types fall through all three.

### 6a. Category mapping

**File:** `apps/investigation_workspace/categories/catalog.py:95–133`

28 finding_types across 8 categories. See §2 above for full dict.

### 6b. Suggestions mapping (ghost actions / Execute buttons)

**File:** `apps/investigation_workspace/suggestions/catalog.py:210–226`

```python
SUGGESTIONS: dict[str, tuple[SuggestionSpec, ...]] = {
    "missing_csp_header":  _CSP_SUGGESTIONS,        # 2 probes
    "missing_hsts_header": _HSTS_SUGGESTIONS,        # 2 guidance-only
    "missing_referrer_policy": _REFERRER_SUGGESTIONS,# 1 guidance-only
    "http_service_detected":   _HTTP_SVC_SUGGESTIONS,# 2 (1 probe + 1 guidance)
    "sqli":                _SQLI_SUGGESTIONS,         # () — empty (engine handles)
    "sqli_error_based":    _SQLI_SUGGESTIONS,
    "sqli_blind":          _SQLI_SUGGESTIONS,
    "command_injection":   _CMDI_SUGGESTIONS,         # () — empty (engines handle)
    "api_exposure":        _API_SUGGESTIONS + _API_ENUM_SUGGESTIONS,  # 5 probes
    "api_idor":            _API_SUGGESTIONS + _API_ENUM_SUGGESTIONS,
    "api_bola":            _API_SUGGESTIONS + _API_ENUM_SUGGESTIONS,
}
```

`for_finding_type(finding_type)` at `catalog.py:229` returns `()` for any
type absent from `SUGGESTIONS`. No ghost actions → no Execute buttons → no
operator-triggered execution stages in the topology.

### 6c. Exploitation path binding

**File:** `apps/investigation_workspace/exploitation_paths/bindings.py:22–66`

33 finding_types mapped to exploitation path IDs. `for_finding_type()` at
`bindings.py:69–86` returns `[EXPLOIT_UNCATEGORIZED]` for any unbound type:

```python
if not ids:
    return [EXPLOIT_UNCATEGORIZED]
```

Uncategorized findings DO receive an `exploitation_path` node in the topology
(the `EXPLOIT_UNCATEGORIZED` placeholder). However, `exploitation_path` nodes
return `None` from `_node_to_stage_card()` (`routes.py:710`), so they are
transparent and do not contribute to `stage_count`.

### 6d. V2 engine dispatch (conductor layer)

The conductor V2 engines are dispatched by `ExecutionOrchestrator` based on
finding_type queries in each engine's `run()` method. They are independent of
the three workspace-layer mappings above. No engine dispatches against the
uncategorized finding_types — engines target `login_form_detected`,
`command_injection`, `missing_csp_header`, `sqli`, `api_exposure/idor/bola`,
`service_detected`.

---

## 7. Gaps and surprises

### Gap 1 — nmap_normalizer emits finding_types not in any workspace map

`nmap_normalizer.py:_classify_service()` at line 108 maps service names to:
`service_exposure`, `cleartext_transmission`, `smb_exposure`, `open_port`.

The `FINDING_TYPE_TO_CATEGORY` dict instead has `http_service_detected`,
`open_port_detected`, `service_banner_disclosed` — all three absent from the
nmap normalizer and from all other active code paths. These three entries in
`FINDING_TYPE_TO_CATEGORY` are **dead**: no probe or normalizer emits them.

The nmap normalizer is the recon-phase scanner, not the conductor V2 nmap
engine. The conductor V2 `nmap_engine.py:249` emits `service_detected` (also
absent from the category map). So nmap produces findings in 2 paths, both
uncategorized.

Summary of the finding_type mismatch:

| What nmap produces | What the map expects | Status |
|---|---|---|
| `service_exposure` (nmap_normalizer) | `http_service_detected` | map entry is dead |
| `cleartext_transmission` (nmap_normalizer) | `open_port_detected` | map entry is dead |
| `service_detected` (V2 nmap_engine) | `service_banner_disclosed` | map entry is dead |

### Gap 2 — `stack_trace_leaked` vs `stack_trace_disclosed`

`FINDING_TYPE_TO_CATEGORY` maps `stack_trace_leaked` → `INFORMATION_DISCLOSURE`
(`catalog.py:111`). The fingerprint probe emits `stack_trace_disclosed`
(`fingerprint_recon.py:182`). These are two different strings. The map entry
`stack_trace_leaked` is never emitted by any active probe. The probe's output
`stack_trace_disclosed` is always UNCATEGORIZED.

### Gap 3 — `verbose_banner_disclosed` vs `server_version_leaked`

`FINDING_TYPE_TO_CATEGORY` maps `server_version_leaked` → `INFORMATION_DISCLOSURE`
(`catalog.py:107`). The passive probe emits `verbose_banner_disclosed`
(`passive.py:218`). Same naming-mismatch pattern as Gap 2 — map entry is dead,
probe output is always UNCATEGORIZED.

### Gap 4 — SUGGESTIONS and FINDING_TYPE_TO_CATEGORY are inconsistently maintained

`SUGGESTIONS` has 11 keys; `FINDING_TYPE_TO_CATEGORY` has 28 keys. There is
no shared source of truth. Adding a new finding_type to the suggestion catalog
does not automatically add it to the category map and vice versa. Three types
appear in `SUGGESTIONS` with empty tuples (`sqli*`, `command_injection`) because
engines handle them — but those types ARE in the category map. Uncategorized
types lack entries in both.

### Gap 5 — EXPLOIT_UNCATEGORIZED path placeholder is always emitted for uncategorized findings

`bindings.py:77–78`: every unbound finding_type gets `EXPLOIT_UNCATEGORIZED`
as its exploitation path node. This is by design ("the operator always sees
the hierarchy") but the `#exploit-cat-tabs` filter tab labeled "Uncategorized"
only appears if the `cats` array contains an uncategorized entry. It does when
there are uncategorized findings in the topology. An operator clicking the
"Uncategorized" tab in the mindmap sees the uncategorized findings' L1 nodes —
but since they have no suggestions, the L1 nodes have no Arm/Execute buttons.
The tab is navigable but not actionable.

### Gap 6 — `framework_fingerprinted` produces multiple findings per investigation

`fingerprint_recon.py:164–170`: one finding per distinct framework with
corroborating signals, with the framework name baked into the finding_id:
`generate_finding_id(..., f"framework_fingerprinted_{fw}")`. Each framework
is a separate finding → separate stage card in the UNCATEGORIZED sidebar. A
PortSwigger lab running a recognizable framework (e.g., Node.js/Express) may
surface 2+ `framework_fingerprinted` findings.

### Gap 7 — `wellknown_file_disclosed` produces one finding per accessible path

`wellknown_recon.py:93–141`: iterates `WELLKNOWN_PATHS` (7 paths) and emits
one finding per 2xx response. PortSwigger labs commonly expose `/robots.txt`
and sometimes `/sitemap.xml`. Each is a separate uncategorized finding in the
sidebar count.

---

## 8. Expected breakdown of the 14 for a PortSwigger HTTP lab

Estimated based on reference scenario (port 23 + HTTP/HTTPS + typical lab
fingerprint). Exact counts require live DB query (§3 above).

| finding_type | probe/normalizer | min | max | notes |
|---|---|---|---|---|
| `service_exposure` | nmap_normalizer | 2 | 2 | port 80 http + port 443 https |
| `cleartext_transmission` | nmap_normalizer | 1 | 1 | port 23 telnet (reference scenario) |
| `custom_404_handler` | fingerprint_recon | 1 | 1 | PortSwigger catch-all routing confirmed |
| `framework_fingerprinted` | fingerprint_recon | 1 | 3 | per framework signal cluster |
| `verbose_banner_disclosed` | passive_probe | 0 | 1 | if server version header present |
| `waf_cdn_detected` | passive_probe | 0 | 1 | if CDN header present |
| `http_methods_advertised` | passive_probe | 0 | 1 | if OPTIONS supported |
| `wellknown_file_disclosed` | wellknown_recon | 1 | 3 | /robots.txt + /sitemap.xml common |
| `sensitive_file_disclosed` | wellknown_recon | 0 | 1 | uncommon on PortSwigger |
| `permissive_cors` | cors_recon | 0 | 1 | lab-dependent |
| `stack_trace_disclosed` | fingerprint_recon | 0 | 1 | only if error pages leak |

**Sum range: 6–15.** 14 is comfortably within this range.

To get the exact 14 with finding_id per item, run the SQL in §3 against
`/app/data/validation.db` with the investigation's ID.
