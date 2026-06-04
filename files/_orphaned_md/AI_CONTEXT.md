# AI Context

## Project
- Name: ai-assist-tool
- Inherits From: AI-Factory-Base
- Base Version: v0.4

## Stack Summary
- Backend: FastAPI, Python 3.12, Pydantic Settings, standard JSON logging
- Frontend: React responsive web
- Docker: single backend service with Docker Compose

## Active Ports
- Backend API: 8000

## Docker Usage
- Start: docker compose up --build -d
- Logs: docker compose logs -f
- Stop: docker compose down

## Validation Commands
- Install dependencies: .venv/bin/pip install -e .[dev]
- Tests: .venv/bin/pytest
- Lint: .venv/bin/ruff check .
- Health check: curl http://localhost:8000/health

## Health Endpoint
- GET /health
- GET /api/v1/health

## Protected Infrastructure Rules
- This project inherits from AI-Factory-Base.
- Core infrastructure should not be redesigned.
- New systems should extend via modules only.
- Keep business logic out of protected infrastructure.
- Use SDK interfaces for core capabilities.

## Architecture Workflow
- Keep core infrastructure in core/.
- Keep stable application interfaces in sdk/.
- Add application behavior under apps/<module-name>/.
- Keep deployment changes in deployment/.
- Keep observability changes in observability/.

## Module Extension Rules
- API routes belong in api/.
- Business logic belongs in services/.
- Database access belongs in repositories/.
- Data models belong in models/.
- Background jobs belong in tasks/.
- Module tests belong in tests/.
- Modules must not access core internals directly.
