"""Набор переменных окружения проекта-источника (sqlite_v2): см. tests/env_sets.py."""

from tests.env_sets import ensure_env_set

# Набор воспроизводит поведение исходной копии, поэтому переменные задаются до импорта кода
ensure_env_set("sqlite_v2")
