# V2.5 Closeout — Operator Live Verification Checklist

Milestone gate for V2.5 (Qwen AI branch spawning). Steps 0–8 must pass before
V2.6 begins. Steps verified by operator; not simulated.

---

## Prerequisites

- [ ] Qwen (Ollama) is reachable: `curl http://localhost:8000/admin/qwen/ping`
      → `{"status":"ok"}` (or check `response_ms` field)
- [ ] Lab target is accessible from the browser
- [ ] `OLLAMA_BASE_URL` is set in the environment before `docker compose up`
      (WSL2: export in `~/.bashrc`, re-source before compose)

---

## Step 0 — Container health

- [ ] `docker compose ps` shows backend container as healthy / running
- [ ] `/admin/qwen/ping` returns `{"status":"ok","model":"qwen2.5:7b",...}`
- [ ] No ImportError or startup errors in `docker compose logs backend`

---

## Step 1 — Active investigation in Exploitation phase

- [ ] Start a new investigation against the lab target (or reuse an existing one)
- [ ] Recon and Enumeration phases complete (findings visible in the DB)
- [ ] Click "Start Exploitation" — phase badge shows **EXPLOITATION**
- [ ] V2 engine cards are visible in the Exploitation tab

---

## Step 2 — Qwen toggle button visible

- [ ] Open the Exploitation tab
- [ ] Floating button (💬) is visible in the bottom-right corner
      (`#qwen-toggle` is `display:block`, not hidden)
- [ ] Button is only visible on the Exploitation tab, not on Recon or Enumeration

---

## Step 3 — Chat window opens

- [ ] Click the 💬 button
- [ ] `#qwen-window` div becomes visible (sliding or instant reveal)
- [ ] Chat input field (`#qwen-input`) is present and focused
- [ ] Send button (`#qwen-send`) is present

---

## Step 4 — Qwen responds with ACTION block

- [ ] Type a directive, for example:
      _"What findings do you see? Suggest an exploit approach."_
- [ ] Click Send (or press Enter)
- [ ] Response appears in `#qwen-history` within the 90s timeout window
- [ ] If Qwen suggests a technique, an ACTION block appears at the end of the
      response (format: `ACTION: {"engine_id": "...", "reason": "..."}`)
- [ ] Approval card renders below the response:
      heading **"QWEN WANTS TO RUN"** with engine label and reason text

---

## Step 5 — Approval card content

- [ ] Card shows engine label (human-readable name, e.g. "Credential Brute")
- [ ] Card shows Qwen's reason text
- [ ] **Approve** button has `data-engine` attribute set to the engine_id
- [ ] **Skip** button is present

---

## Step 6 — Operator clicks Approve

- [ ] Click **Approve**
- [ ] POST dispatched to `/finding/{id}/suggest/{engine}/execute`
- [ ] Chat appends status: "Running..." or "Dispatched"
- [ ] No 4xx/5xx error shown in browser console or chat UI

---

## Step 7 — Mindmap updates

- [ ] After polling (up to 10s), the exploitation mindmap updates
- [ ] A new node appears under the **AI Actions** category
- [ ] Node label begins with "Qwen: " followed by the action_kind
- [ ] Branch state badge shows the current engine state (armed / running / succeeded / exhausted)

---

## Step 8 — Right panel shows result

- [ ] Click the AI node in the mindmap
- [ ] Right panel opens (detail side panel)
- [ ] Panel shows the branch result:
      - **Succeeded**: artifact type visible, key fields displayed
      - **Exhausted**: exhaustion record visible with `payloads_tried` count
- [ ] No blank or error panel

---

## Report

Fill in after verification:

| Step | Result | Notes |
|------|--------|-------|
| 0. Container health | PASS / FAIL | |
| 1. Exploitation phase active | PASS / FAIL | |
| 2. Toggle visible | PASS / FAIL | |
| 3. Chat window opens | PASS / FAIL | |
| 4. Qwen ACTION block | PASS / FAIL | |
| 5. Approval card content | PASS / FAIL | |
| 6. Approve dispatches | PASS / FAIL | |
| 7. Mindmap updates | PASS / FAIL | |
| 8. Right panel result | PASS / FAIL | |

**Gate status:** OPEN / CLOSED  
**Date verified:**  
**Operator notes:**
