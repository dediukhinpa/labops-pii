"""Режим проверки адресов (этап 187, часть Г): PII_GUARD_ADDRESS_MODE.

Сам шаблон «улица + номер дома» и «индекс + улица» общий с псевдонимизатором и живёт в
labops_pii.pii_patterns (копия shared/pii_patterns.py). Здесь только тип находки и режим,
по образцу labops_pii.guard.names: off / log_only / enforce, по умолчанию off.
"""

from __future__ import annotations

import os
from enum import Enum


# Переменная окружения режима и тип находки (он же метка метрики из закрытого списка)
ADDRESS_MODE_ENV = "PII_GUARD_ADDRESS_MODE"
ADDRESS_TYPE = "address"


class AddressMode(str, Enum):
    """Режим проверки адресов."""

    OFF = "off"
    LOG_ONLY = "log_only"
    ENFORCE = "enforce"


# Нейтральное значение по умолчанию: адреса в guard не ищутся, пока потребитель не задал
# PII_GUARD_ADDRESS_MODE (log_only или enforce)
DEFAULT_ADDRESS_MODE = AddressMode.OFF


def default_address_mode() -> AddressMode:
    """Режим адресов по умолчанию (когда PII_GUARD_ADDRESS_MODE не задана)."""
    return DEFAULT_ADDRESS_MODE


def parse_address_mode(raw: str | None) -> AddressMode:
    """Разбирает значение PII_GUARD_ADDRESS_MODE строго.

    Пусто или не задано - режим по умолчанию (off). Неизвестное значение - ошибка:
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
