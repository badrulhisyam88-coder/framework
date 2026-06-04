# Module Pattern

/apps/module-name/

api/
services/
repositories/
models/
tasks/
tests/

## Rules
- business logic inside services/
- API routes inside api/
- repositories handle DB access
- tasks contain background jobs
- modules must not access core internals directly