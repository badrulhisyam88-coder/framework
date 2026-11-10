## Standards (synced from framework_final/standards/AGENTS.master.md; edit there, then run bin/sync-standards)

### Start
- New system: run `~/Developer/framework_final/bin/new-project <name>` first. Never start from an empty folder.
- Existing system: extend it. Reuse before creating, make the smallest change, ask if two placements are valid. Read in order: AGENTS.md, docs/STATUS.md, docs/PLAN.md, docs/SPEC.md, docs/ARCHITECTURE.md, docs/DECISIONS.md. If `graphify-out/` exists, query it before scanning code.

### Workflow (every change)
1. **Spec**: docs/SPEC.md says what and why, scope and non-goals. For a new system the owner says OK before any code.
2. **Plan**: docs/PLAN.md lists phases and tasks. No code without a task there. Not in the plan? Add the task first.
3. **Task**: each task has Goal, Acceptance, Files (the only files it may touch) and Verify. Need more files? Update the task and say why.
4. **Build test-first**: red, then green, one small slice at a time. Never break what already works.
5. **Verify**: run `scripts/verify.sh`. If there is a UI, open it in a browser. Check security (inputs, auth, secrets). Simplify your own code.
6. **PR**: work on a branch, merge only with `scripts/merge.sh` (it waits for green CI). Never commit or push to main.
7. **Handoff**: update docs/STATUS.md (done, next, open). Record choices in docs/DECISIONS.md as `proposed`; the owner accepts them. Never edit accepted decisions.

### Rules
- Facts come from files, not memory. Never invent features, prices, customers, integrations or endpoints. Unknown: write `TODO(owner)` and ask.
- One writer per branch. Use a branch or git worktree, keep the diff small and inside the task's Files.
- Never commit secrets, .env files, databases, logs or runtime state. Never print tokens.
- Free models and workers by default. Use paid ones (Claude, Codex) only when the owner asks.
- Production repos are listed in ~/Developer/REGISTRY.md: hotfix branch only, the owner merges.
- Stop and ask when scope is unclear, two architectures are valid, an action is destructive, or tests cannot be made green.
- Keep docs short and current: one topic per file. If a doc and the code disagree, fix the doc or flag it.
