#!/usr/bin/env python3

import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

# =========================================================
# AI Factory Base Initializer v0.4
# Full Operational Provisioning + Preflight Validation
# =========================================================

CURRENT_DIR = Path(__file__).resolve().parent
BASE_VERSION = "v0.4"
PYTHON_VERSION = "3.12"
BACKEND_PORT = 8000

EXCLUDED_ITEMS = {
    ".env",
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".DS_Store",
}


# =========================================================
# Utilities
# =========================================================

def run_command(command, cwd=None, check=True):
    print(f"\n>> {' '.join(command)}\n")

    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
    )

    if check and result.returncode != 0:
        print(f"\nERROR: Command failed -> {' '.join(command)}\n")
        sys.exit(result.returncode)

    return result


def command_exists(command):
    return shutil.which(command) is not None


def is_port_open(host="localhost", port=8000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((host, port)) == 0


def open_file(path: Path):
    if sys.platform.startswith("linux"):
        command = "xdg-open"
    elif sys.platform == "darwin":
        command = "open"
    elif sys.platform == "win32":
        command = "cmd"
    else:
        return

    if command != "cmd" and not command_exists(command):
        return

    if command == "cmd":
        subprocess.Popen(
            ["cmd", "/c", "start", "", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return

    subprocess.Popen(
        [command, str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# =========================================================
# Preflight Validation
# =========================================================

def validate_environment():
    print("\n========================================")
    print("PREFLIGHT VALIDATION")
    print("========================================\n")

    # Python version check — must match pyproject.toml requires-python
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 12):
        print(f"ERROR: Python 3.12+ required. Found {major}.{minor}\n")
        sys.exit(1)
    print(f"OK: python3 ({major}.{minor})")

    required_commands = [
        "git",
        "curl",
    ]

    for command in required_commands:
        if not command_exists(command):
            print(f"ERROR: Required command missing -> {command}")
            sys.exit(1)

        print(f"OK: {command}")

    # Docker validation
    if not command_exists("docker"):
        print("\nERROR: Docker not found inside this WSL distro.\n")
        print("Enable Docker Desktop WSL integration.\n")
        print("Docker Desktop -> Settings -> Resources -> WSL Integration\n")
        sys.exit(1)

    print("OK: docker")

    # Docker daemon validation
    result = subprocess.run(
        ["docker", "ps"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("\nERROR: Docker daemon is not accessible.\n")
        print("Make sure Docker Desktop is running.\n")
        sys.exit(1)

    print("OK: docker daemon")

    # Port validation
    if is_port_open(port=BACKEND_PORT):
        print(f"\nERROR: Port {BACKEND_PORT} already in use.\n")
        print(f"Stop existing containers/services using port {BACKEND_PORT}.\n")
        sys.exit(1)

    print(f"OK: port {BACKEND_PORT} available")

    print("\nPreflight validation successful.\n")


# =========================================================
# Project Setup
# =========================================================

def ask_project_name():
    print("========================================")
    print("AI FACTORY INITIALIZER")
    print("========================================\n")

    while True:
        project_name = input("Project name: ").strip()

        if not project_name:
            print("Project name cannot be empty.\n")
            continue

        return project_name


def copy_factory_base(destination: Path):
    print("\n[1/12] Copying validated AI Factory Base...\n")

    shutil.copytree(
        CURRENT_DIR,
        destination,
        ignore=shutil.ignore_patterns(*EXCLUDED_ITEMS),
    )


def replace_project_identity(project_path: Path, project_name: str):
    print("[2/12] Replacing project identity...\n")

    fixed_targets = [
        "README.md",
        "docker-compose.yml",
        "pyproject.toml",
        ".env.example",
        "core/config/settings.py",
    ]

    # Include all test files so assertions against the project name
    # stay consistent with the updated default in core/config/settings.py.
    tests_dir = project_path / "tests"
    test_targets = [
        str(p.relative_to(project_path))
        for p in tests_dir.rglob("*.py")
    ] if tests_dir.exists() else []

    replacement_targets = fixed_targets + test_targets

    # Derive name variants from the project name the developer typed.
    # e.g. "my-forex-system" → slug="my-forex-system", pretty="my forex system"
    # e.g. "My Forex System" → slug="my-forex-system", pretty="My Forex System"
    pretty_name = project_name.replace("-", " ")
    slug = project_name.lower().replace(" ", "-")

    for relative_file in replacement_targets:
        file_path = project_path / relative_file

        if not file_path.exists():
            continue

        content = file_path.read_text(encoding="utf-8")

        content = content.replace("AI-Factory-Core", project_name)
        content = content.replace("ai-factory-core", slug)
        content = content.replace("AI Factory Core", pretty_name)

        file_path.write_text(content, encoding="utf-8")


def generate_ai_context(project_path: Path, project_name: str):
    print("[3/12] Generating AI continuity context...\n")

    context = f"""# AI Context

## Project
- Name: {project_name}
- Inherits From: AI-Factory-Base
- Base Version: {BASE_VERSION}

## Stack Summary
- Backend: FastAPI, Python {PYTHON_VERSION}, Pydantic Settings, standard JSON logging
- Frontend: React responsive web
- Docker: single backend service with Docker Compose

## Active Ports
- Backend API: {BACKEND_PORT}

## Docker Usage
- Start: docker compose up --build -d
- Logs: docker compose logs -f
- Stop: docker compose down

## Validation Commands
- Install dependencies: .venv/bin/pip install -e .[dev]
- Tests: .venv/bin/pytest
- Lint: .venv/bin/ruff check .
- Health check: curl http://localhost:{BACKEND_PORT}/health

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
"""

    (project_path / "AI_CONTEXT.md").write_text(context, encoding="utf-8")


def remove_existing_git(project_path: Path):
    print("[4/12] Removing existing git history...\n")

    git_dir = project_path / ".git"

    if git_dir.exists():
        shutil.rmtree(git_dir)


def initialize_git(project_path: Path):
    print("[5/12] Initializing new git repository...\n")

    # Verify git identity is configured before attempting commit.
    name_check = subprocess.run(
        ["git", "config", "user.name"],
        capture_output=True,
        text=True,
    )
    email_check = subprocess.run(
        ["git", "config", "user.email"],
        capture_output=True,
        text=True,
    )

    if not name_check.stdout.strip() or not email_check.stdout.strip():
        print("ERROR: git user.name and user.email are not configured.\n")
        print("Run the following before retrying:\n")
        print('  git config --global user.name "Your Name"')
        print('  git config --global user.email "you@example.com"\n')
        sys.exit(1)

    run_command(["git", "init"], cwd=project_path)
    run_command(["git", "add", "."], cwd=project_path)
    run_command(
        ["git", "commit", "-m", "initial factory initialization"],
        cwd=project_path,
    )


# =========================================================
# Python Environment
# =========================================================

def create_virtual_environment(project_path: Path):
    print("[6/12] Creating Python virtual environment...\n")

    run_command(
        ["python3", "-m", "venv", ".venv"],
        cwd=project_path,
    )


def install_dependencies(project_path: Path):
    print("[7/12] Installing dependencies...\n")

    pip_path = project_path / ".venv" / "bin" / "pip"

    run_command(
        [str(pip_path), "install", "-e", ".[dev]"],
        cwd=project_path,
    )


# =========================================================
# Validation
# =========================================================

def run_pytest(project_path: Path):
    print("[8/12] Running pytest...\n")

    pytest_path = project_path / ".venv" / "bin" / "pytest"

    run_command(
        [str(pytest_path)],
        cwd=project_path,
    )


def run_ruff(project_path: Path):
    print("[9/12] Running ruff...\n")

    ruff_path = project_path / ".venv" / "bin" / "ruff"

    run_command(
        [str(ruff_path), "check", "."],
        cwd=project_path,
    )


# =========================================================
# Docker Runtime
# =========================================================

def start_docker(project_path: Path):
    print("[10/12] Starting Docker environment...\n")

    run_command(
        ["docker", "compose", "up", "--build", "-d"],
        cwd=project_path,
    )


def validate_health():
    print("[11/12] Validating health endpoint...\n")

    max_wait = 60
    interval = 3
    deadline = time.time() + max_wait
    url = f"http://localhost:{BACKEND_PORT}/health"

    while time.time() < deadline:
        result = subprocess.run(
            ["curl", "-sf", url],
            capture_output=True,
            text=True,
        )

        # -f makes curl return non-zero for HTTP 4xx/5xx.
        # Presence of "status" in body confirms we hit the right endpoint.
        if result.returncode == 0 and '"status"' in result.stdout:
            print("\nHealth Response:\n")
            print(result.stdout)
            return

        remaining = max(0, int(deadline - time.time()))
        print(f"  Waiting for container... ({remaining}s remaining)")
        time.sleep(interval)

    print(f"\nERROR: Health endpoint not ready after {max_wait}s.\n")
    sys.exit(1)


# =========================================================
# Success
# =========================================================

def open_ai_context(project_path: Path):
    print("[12/12] Opening AI continuity context...\n")

    open_file(project_path / "AI_CONTEXT.md")


def print_success(project_name: str, project_path: Path):
    print("\n========================================")
    print("FACTORY INITIALIZATION COMPLETE")
    print("========================================\n")

    print(f"Project: {project_name}")
    print(f"Location: {project_path}\n")

    print("Application running at:\n")
    print(f"http://localhost:{BACKEND_PORT}/health\n")

    print("Useful commands:\n")
    print(f"cd {project_path}")
    print("source .venv/bin/activate")
    print("docker compose logs -f")
    print("docker compose down")
    print("AI continuity context: AI_CONTEXT.md")
    print()


# =========================================================
# Main
# =========================================================

def main():
    validate_environment()

    project_name = ask_project_name()

    destination = CURRENT_DIR.parent / project_name

    if destination.exists():
        print(f"\nERROR: {destination} already exists.\n")
        sys.exit(1)

    copy_factory_base(destination)

    # All post-copy steps run inside a try block so that any failure
    # triggers automatic cleanup of the partially-provisioned directory.
    # Developers can re-run factory_init.py cleanly after fixing the issue.
    try:
        replace_project_identity(destination, project_name)
        generate_ai_context(destination, project_name)
        remove_existing_git(destination)
        initialize_git(destination)
        create_virtual_environment(destination)
        install_dependencies(destination)
        run_pytest(destination)
        run_ruff(destination)
        start_docker(destination)
        validate_health()
    except (Exception, SystemExit) as exc:
        print(f"\nProvisioning failed. Cleaning up {destination}...\n")
        shutil.rmtree(destination, ignore_errors=True)
        code = exc.code if isinstance(exc, SystemExit) else 1
        sys.exit(code if isinstance(code, int) and code != 0 else 1)

    open_ai_context(destination)
    print_success(project_name, destination)


if __name__ == "__main__":
    main()
