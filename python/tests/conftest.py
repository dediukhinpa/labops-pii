"""Корневые настройки: наборы с разными переменными окружения нельзя смешивать в процессе."""

from __future__ import annotations

import pytest

# Наборы, которые воспроизводят бывшие профили собственным набором переменных (env_sets.py)
ENV_SET_SUITES = ("labops_pseudonymizer", "pragmatika_pseudonymizer", "pragmatika_guard",
                  "webapp_v2_guard")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Падает, если в одном запуске собрано больше одного набора со своими переменными.

    Переменные окружения задаются на процесс, детекторы создаются один раз; смешение даёт
    ложные падения. Запускайте через tools/run_tests.sh.
    """
    present = {s for s in ENV_SET_SUITES if any(f"/tests/{s}/" in str(i.fspath) for i in items)}
    if len(present) > 1:
        raise pytest.UsageError(
            f"в одном процессе несколько наборов с разными переменными: {sorted(present)}; "
            "запускайте tools/run_tests.sh"
        )
