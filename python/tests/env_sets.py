"""Наборы переменных окружения, воспроизводящие поведение бывших профилей (до 1.0.0).

Профилей в библиотеке больше нет: каждая бывшая комбинация задаётся переменными. Здесь они
записаны один раз и используются тест-раннером (`tools/run_tests.sh`), conftest наборов и
`tools/reference_snapshot.py`. Те же блоки приведены в `docs/MIGRATION.md` для потребителей.

Запуск как скрипт печатает набор построчно (`KEY=VALUE`) для `env` в bash:
    python python/tests/env_sets.py sqlite_v2
"""

from __future__ import annotations

import os
import sys
from collections.abc import MutableMapping
from typing import Any

# Слова белого списка - нейтральные примеры: «вектрик» (название продукта, которое детектор
# иначе принимает за ФИО) во всех наборах, «орловъ» (торговая марка «С.ОРЛОВЪ»: с инициалом
# guard видел в ней ФИО) в наборе sqlite_v2. Настоящие слова потребитель задаёт у себя.
_ALLOWED_WORDS_BASE = "вектрик"
_ALLOWED_WORDS_SQLITE_V2 = "вектрик,орловъ"
# 90 суток в часах
_SQLITE_V2_RETENTION_HOURS = "2160"

_LABOPS: dict[str, str] = {
    "PSEUDONYMIZER_STORE": "memory",
    "PSEUDONYMIZER_KEY_SCHEME": "v3",
    "PSEUDONYMIZER_RETENTION_HOURS": "24",
    "PSEUDONYMIZER_MASK_LEGAL_ENTITY": "on",
    "PSEUDONYMIZER_ADDRESS_MASK": "off",
    "PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY": "off",
    "PSEUDONYMIZER_ENABLE_DELETE_THREADS": "on",
    "PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID": "on",
    "PSEUDONYMIZER_ENABLE_CASE_LABELS": "on",
    "PII_GUARD_NAMES_MODE": "off",
    "PII_GUARD_ADDRESS_MODE": "off",
    "PII_ALLOWED_WORDS": _ALLOWED_WORDS_BASE,
}

ENV_SETS: dict[str, dict[str, str]] = {
    "labops": _LABOPS,
    # Набор edge (guard на edge-узле) совпадает с labops: сервис у них общий
    "edge": dict(_LABOPS),
    "sqlite_v2": {
        "PSEUDONYMIZER_STORE": "sqlite",
        "PSEUDONYMIZER_KEY_SCHEME": "v2",
        "PSEUDONYMIZER_RETENTION_HOURS": _SQLITE_V2_RETENTION_HOURS,
        "PSEUDONYMIZER_MASK_LEGAL_ENTITY": "off",
        "PSEUDONYMIZER_ADDRESS_MASK": "on",
        "PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY": "on",
        "PSEUDONYMIZER_ENABLE_DELETE_THREADS": "off",
        "PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID": "off",
        "PSEUDONYMIZER_ENABLE_CASE_LABELS": "off",
        "PII_GUARD_NAMES_MODE": "log_only",
        "PII_GUARD_ADDRESS_MODE": "log_only",
        "PII_ALLOWED_WORDS": _ALLOWED_WORDS_SQLITE_V2,
    },
}

# Все переменные, которыми управляют наборы: перед применением набора они сбрасываются
MANAGED_KEYS = tuple(sorted({key for values in ENV_SETS.values() for key in values}))
# Прежняя переменная профиля: в набор попадать не должна, она вызывает ошибку старта
LEGACY_KEY = "LABOPS_PII_PROFILE"


def apply_env_set(name: str, environ: MutableMapping[str, str] | None = None) -> None:
    """Задаёт набор переменных (прежние значения управляемых ключей сбрасываются).

    Args:
        name: Имя набора (labops, edge, sqlite_v2).
        environ: Куда писать (по умолчанию os.environ).

    Raises:
        KeyError: Нет такого набора.
    """
    target = os.environ if environ is None else environ
    values = ENV_SETS[name]
    for key in MANAGED_KEYS:
        target.pop(key, None)
    target.pop(LEGACY_KEY, None)
    target.update(values)


def use_env_set(monkeypatch: Any, name: str) -> None:
    """Задаёт набор в тесте через monkeypatch (после теста окружение восстанавливается)."""
    for key in (*MANAGED_KEYS, LEGACY_KEY):
        monkeypatch.delenv(key, raising=False)
    for key, value in ENV_SETS[name].items():
        monkeypatch.setenv(key, value)


def ensure_env_set(name: str, environ: MutableMapping[str, str] | None = None) -> None:
    """Применяет набор, если раннер его ещё не задал; чужое значение - ошибка.

    Raises:
        RuntimeError: Переменная набора уже задана другим значением (смешение наборов в одном
            процессе дало бы ложные падения).
    """
    target = os.environ if environ is None else environ
    clash = {k: target[k] for k, v in ENV_SETS[name].items() if k in target and target[k] != v}
    if clash:
        raise RuntimeError(
            f"набор «{name}»: переменные заданы иначе ({', '.join(sorted(clash))}); "
            "запускайте tools/run_tests.sh"
        )
    target.update(ENV_SETS[name])


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ENV_SETS:
        sys.exit(f"использование: env_sets.py {{{'|'.join(ENV_SETS)}}}")
    for _key, _value in ENV_SETS[sys.argv[1]].items():
        print(f"{_key}={_value}")
