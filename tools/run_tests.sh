#!/usr/bin/env bash
# Прогон всех наборов тестов. Каждый набор — отдельный процесс с собственным набором
# переменных окружения (профилей нет, см. python/tests/env_sets.py).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
if [ ! -x "$PY" ]; then
  echo "нет интерпретатора: $PY (создайте .venv или задайте PYTHON)" >&2
  exit 1
fi
cd "$ROOT/python"
# Набор тестов: "<каталог или файл>[:<набор переменных окружения>]". Профилей в библиотеке
# нет: бывшие комбинации задаются наборами переменных из tests/env_sets.py, а раннер передаёт
# их процессу pytest через env. Каждый набор - отдельный процесс (детекторы создаются один
# раз на процесс, наборы переменных нельзя смешивать).
SUITES=(
  tests/labops_pseudonymizer:labops
  tests/sqlite_v2_pseudonymizer:sqlite_v2
  tests/sqlite_v2_guard:sqlite_v2
  tests/webapp_v2_guard:webapp_v2
  tests/media
  tests/core
  tests/test_reference_snapshots.py
  tests/test_profile_snapshots.py
  tests/test_vendor.py
)
for entry in "${SUITES[@]}"; do
  suite="${entry%%:*}"
  env_set=""
  if [[ "$entry" == *:* ]]; then
    env_set="${entry##*:}"
  fi
  if [ ! -e "$suite" ]; then
    echo "пропуск (нет набора): $suite"
    continue
  fi
  env_vars=()
  if [ -n "$env_set" ]; then
    mapfile -t env_vars < <("$PY" tests/env_sets.py "$env_set")
  fi
  echo "=== $suite ${env_set:+(набор переменных: $env_set)}"
  env ${env_vars[@]+"${env_vars[@]}"} "$PY" -m pytest "$suite" -q -p no:cacheprovider "$@"
done

# TS-часть: тесты и строгая проверка типов (пропуск, если bun не установлен)
if command -v bun >/dev/null 2>&1; then
  echo "=== ts"
  cd "$ROOT/ts"
  [ -d node_modules ] || bun install --frozen-lockfile
  bun test
  bun run typecheck
else
  echo "пропуск (нет bun): ts"
fi
