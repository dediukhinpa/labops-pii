"""Набор переменных окружения проекта-источника (pragmatika): см. tests/env_sets.py."""

from tests.env_sets import ensure_env_set

# Набор воспроизводит поведение исходной копии, поэтому переменные задаются до импорта кода
ensure_env_set("pragmatika")
