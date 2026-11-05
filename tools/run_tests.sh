#!/usr/bin/env bash
# Прогон всех наборов тестов. Каждый набор — отдельный процесс: профиль настроек задаётся
# переменной окружения и не должен смешиваться (детекторы создаются один раз на процесс).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
if [ ! -x "$PY" ]; then
  echo "нет интерпретатора: $PY (создайте .venv или задайте PYTHON)" >&2
  exit 1
fi
cd "$ROOT/python"
SUITES=(
  tests/labops_pseudonymizer
  tests/pragmatika_pseudonymizer
  tests/pragmatika_guard
  tests/webapp_v2_guard
  tests/media
  tests/core
  tests/test_reference_snapshots.py
  tests/test_vendor.py
)
for suite in "${SUITES[@]}"; do
  if [ ! -e "$suite" ]; then
    echo "пропуск (нет набора): $suite"
    continue
  fi
  echo "=== $suite"
  "$PY" -m pytest "$suite" -q -p no:cacheprovider "$@"
done
