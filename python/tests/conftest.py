"""Корневые настройки: наборы разных профилей нельзя смешивать в одном процессе."""

from __future__ import annotations

import pytest

PROFILE_SUITES = ("labops_pseudonymizer", "pragmatika_pseudonymizer", "pragmatika_guard",
                  "webapp_v2_guard")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Падает, если в одном запуске собрано больше одного набора с собственным профилем.

    Профиль задаётся переменной окружения на процесс, детекторы создаются один раз;
    смешение даёт ложные падения. Запускайте через tools/run_tests.sh.
    """
    present = {s for s in PROFILE_SUITES if any(f"/tests/{s}/" in str(i.fspath) for i in items)}
    if len(present) > 1:
        raise pytest.UsageError(
            f"в одном процессе несколько наборов с разными профилями: {sorted(present)}; "
            "запускайте tools/run_tests.sh"
        )
