#!/bin/bash
# Run this from the PARENT directory that contains both:
#   - AI-Factory-Core/  (source of generated files)
#   - ai-assist-tool/   (provisioned project)
#
# Usage: bash copy_to_project.sh

set -e

SRC="$(pwd)/AI-Factory-Core/ai-assist-tool-generated"
DST="$(pwd)/ai-assist-tool"

# If you ran this script from inside AI-Factory-Core, adjust:
# SRC is wherever the generated files folder is.
# Simplest: just copy each file manually as shown below.

echo "=== Copying generated files to ai-assist-tool ==="

# 1. Docker + compose + pyproject
cp deployment/docker/Dockerfile "$DST/deployment/docker/Dockerfile"
cp docker-compose.yml "$DST/docker-compose.yml"
cp pyproject.toml "$DST/pyproject.toml"

# 2. Core app.py (extends base)
cp core/api/app.py "$DST/core/api/app.py"

# 3. App structure
mkdir -p "$DST/apps/validation/api"
mkdir -p "$DST/apps/validation/engines"
mkdir -p "$DST/apps/validation/adapters"
mkdir -p "$DST/apps/validation/plugins"
mkdir -p "$DST/apps/validation/repositories"
mkdir -p "$DST/apps/validation/models"
mkdir -p "$DST/apps/validation/services"
mkdir -p "$DST/apps/validation/tasks"
mkdir -p "$DST/apps/validation/tests"

touch "$DST/apps/__init__.py"
touch "$DST/apps/validation/__init__.py"
touch "$DST/apps/validation/services/__init__.py"
touch "$DST/apps/validation/tasks/__init__.py"
touch "$DST/apps/validation/tests/__init__.py"

# 4. Core validation files
cp apps/validation/database.py            "$DST/apps/validation/database.py"
cp apps/validation/models/__init__.py     "$DST/apps/validation/models/__init__.py"
cp apps/validation/repositories/__init__.py "$DST/apps/validation/repositories/__init__.py"

# 5. Adapters
cp apps/validation/adapters/nmap.py       "$DST/apps/validation/adapters/nmap.py"
touch "$DST/apps/validation/adapters/__init__.py"

# 6. Engines
cp apps/validation/engines/fingerprint_normalizer.py "$DST/apps/validation/engines/fingerprint_normalizer.py"
cp apps/validation/engines/nvd_sync.py               "$DST/apps/validation/engines/nvd_sync.py"
cp apps/validation/engines/cve_matcher.py            "$DST/apps/validation/engines/cve_matcher.py"
touch "$DST/apps/validation/engines/__init__.py"

# 7. Services
cp apps/validation/services/scanner.py              "$DST/apps/validation/services/scanner.py"
cp apps/validation/services/correlator.py           "$DST/apps/validation/services/correlator.py"
cp apps/validation/services/change_detector.py      "$DST/apps/validation/services/change_detector.py"
cp apps/validation/services/executor.py             "$DST/apps/validation/services/executor.py"

# 8. Plugins
cp apps/validation/plugins/ssh.py        "$DST/apps/validation/plugins/ssh.py"
cp apps/validation/plugins/web.py        "$DST/apps/validation/plugins/web.py"
cp apps/validation/plugins/telnet.py     "$DST/apps/validation/plugins/telnet.py"
cp apps/validation/plugins/smb.py        "$DST/apps/validation/plugins/smb.py"
cp apps/validation/plugins/sqli.py       "$DST/apps/validation/plugins/sqli.py"
cp apps/validation/plugins/generic.py    "$DST/apps/validation/plugins/generic.py"
touch "$DST/apps/validation/plugins/__init__.py"

# 9. API routers
cp apps/validation/api/__init__.py        "$DST/apps/validation/api/__init__.py"
cp apps/validation/api/discovery.py       "$DST/apps/validation/api/discovery.py"
cp apps/validation/api/queue.py           "$DST/apps/validation/api/queue.py"
cp apps/validation/api/findings.py        "$DST/apps/validation/api/findings.py"
cp apps/validation/api/changes.py         "$DST/apps/validation/api/changes.py"
cp apps/validation/api/history.py         "$DST/apps/validation/api/history.py"
cp apps/validation/api/settings_router.py "$DST/apps/validation/api/settings_router.py"

# 10. Frontend
mkdir -p "$DST/frontend/templates/partials"
mkdir -p "$DST/frontend/static/css"
mkdir -p "$DST/frontend/static/js"

cp frontend/templates/base.html             "$DST/frontend/templates/base.html"
cp frontend/templates/discovery.html        "$DST/frontend/templates/discovery.html"
cp frontend/templates/queue.html            "$DST/frontend/templates/queue.html"
cp frontend/templates/findings.html         "$DST/frontend/templates/findings.html"
cp frontend/templates/finding_detail.html   "$DST/frontend/templates/finding_detail.html"
cp frontend/templates/changes.html          "$DST/frontend/templates/changes.html"
cp frontend/templates/history.html          "$DST/frontend/templates/history.html"
cp frontend/templates/settings.html         "$DST/frontend/templates/settings.html"
cp frontend/templates/partials/queue_row.html "$DST/frontend/templates/partials/queue_row.html"
cp frontend/static/css/main.css             "$DST/frontend/static/css/main.css"

# 11. Config
mkdir -p "$DST/config/credentials"
mkdir -p "$DST/config/fingerprints"
mkdir -p "$DST/config/validation_profiles"
mkdir -p "$DST/data"

cp config/credentials/ssh_defaults.yaml        "$DST/config/credentials/ssh_defaults.yaml"
cp config/fingerprints/service_map.yaml        "$DST/config/fingerprints/service_map.yaml"
cp config/validation_profiles/ssh.yaml         "$DST/config/validation_profiles/ssh.yaml"

echo ""
echo "=== Done. Next steps ==="
echo ""
echo "1. Download HTMX and place it at:"
echo "   ai-assist-tool/frontend/static/js/htmx.min.js"
echo "   (https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js)"
echo ""
echo "2. Update .env or docker-compose environment:"
echo "   TOOL_NVD_API_KEY=your_key_here  (optional, increases NVD rate limits)"
echo ""
echo "3. Build and run:"
echo "   cd ai-assist-tool"
echo "   docker compose up --build"
echo ""
echo "4. Open browser:"
echo "   http://localhost:8000"
echo ""
echo "5. First run — sync CVE database from Settings page"
