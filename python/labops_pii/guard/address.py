"""Режим проверки адресов (этап 187, часть Г): PII_GUARD_ADDRESS_MODE.

Сам шаблон «улица + номер дома» и «индекс + улица» общий с псевдонимизатором и живёт в
labops_pii.pii_patterns (копия shared/pii_patterns.py). Здесь только тип находки и режим,
по образцу labops_pii.guard.names: off / log_only / enforce, по умолчанию log_only.
"""

from __future__ import annotations

import os
from enum import Enum

from labops_pii.profiles import get_profile

# Переменная окружения режима и тип находки (он же метка метрики из закрытого списка)
ADDRESS_MODE_ENV = "PII_GUARD_ADDRESS_MODE"
ADDRESS_TYPE = "address"


class AddressMode(str, Enum):
    """Режим проверки адресов."""

    OFF = "off"
    LOG_ONLY = "log_only"
    ENFORCE = "enforce"


DEFAULT_ADDRESS_MODE = AddressMode.LOG_ONLY


def default_address_mode() -> AddressMode:
    """Режим адресов по умолчанию для активного профиля (pragmatika - log_only, иначе off)."""
    return AddressMode(get_profile().guard_address_mode)


def parse_address_mode(raw: str | None) -> AddressMode:
    """Разбирает значение PII_GUARD_ADDRESS_MODE строго.

    Пусто или не задано - режим по умолчанию (log_only). Неизвестное значение - ошибка:
    приложение при старте не запускается, чтобы опечатка не стала молча выключенной защитой.

    Raises:
        ValueError: Значение не из off / log_only / enforce.
    """
    if raw is None or not raw.strip():
        return default_address_mode()
    try:
        return AddressMode(raw.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in AddressMode)
        raise ValueError(f"{ADDRESS_MODE_ENV} должна быть одним из: {allowed}") from exc


def address_mode() -> AddressMode:
    """Режим из окружения на момент вызова.

    Неизвестное значение здесь (минуя проверку при старте) трактуется как enforce:
    детектор не бросает исключений посреди проверки, при сомнении безопаснее отказать.
    """
    try:
        return parse_address_mode(os.environ.get(ADDRESS_MODE_ENV))
    except ValueError:
        return AddressMode.ENFORCE
