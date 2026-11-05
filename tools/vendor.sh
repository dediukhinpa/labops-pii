#!/usr/bin/env bash
# Обёртка над vendor.py: tools/vendor.sh <каталог проекта> [тег|коммит] [части]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:?использование: vendor.sh <каталог проекта> [тег|коммит] [guard,service,media,ts]}"
REF="${2:-origin/prod}"  # базовая ветка библиотеки - prod
PARTS="${3:-guard,service,media}"

echo "labops-pii: вендорим $REF ($PARTS) в $DEST/vendor/labops-pii"
exec python3 "$HERE/vendor.py" --dest "$DEST" --ref "$REF" --parts "$PARTS"
