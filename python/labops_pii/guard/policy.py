"""Политика отказа: какие находки блокируют запрос, а какие только наблюдаются.

Особых режимов два: ФИО (PII_GUARD_NAMES_MODE) и адрес (PII_GUARD_ADDRESS_MODE). Остальные
типы (телефон, почта, ИНН, СНИЛС, карта, счёт) блокируют всегда. Все маршруты (чат, поиск,
зрение, страницы) берут решение отсюда, чтобы режим работал единообразно.
"""

from __future__ import annotations

from dataclasses import dataclass

from labops_pii.guard.address import ADDRESS_TYPE, AddressMode, address_mode
from labops_pii.guard.names import NAME_TYPE, NamesMode, names_mode


@dataclass(frozen=True)
class Findings:
    """Находки, разделённые по политике (только имена типов, значений нет)."""

    blocking: frozenset[str]  # причина отказа
    observed: frozenset[str]  # только журнал и метрика, запрос идёт дальше


def split_findings(
    found: set[str] | frozenset[str],
    mode: NamesMode | None = None,
    addr_mode: AddressMode | None = None,
) -> Findings:
    """Делит находки на блокирующие и наблюдаемые.

    Args:
        found: Типы находок детектора.
        mode: Режим ФИО; по умолчанию из окружения.
        addr_mode: Режим адреса; по умолчанию из окружения.

    Returns:
        Для «name» и «address» по своему режиму: log_only - в observed; enforce - блокирует;
        off - отбрасывается (детектор его и не ищет; страховка для прямых вызовов).
        Остальные типы блокируют всегда.
    """
    modes = {
        NAME_TYPE: (mode or names_mode()).value,
        ADDRESS_TYPE: (addr_mode or address_mode()).value,
    }
    blocking: set[str] = set()
    observed: set[str] = set()
    for pii_type in found:
        policy = modes.get(pii_type, "enforce")
        if policy == "enforce":
            blocking.add(pii_type)
        elif policy == "log_only":
            observed.add(pii_type)
    return Findings(blocking=frozenset(blocking), observed=frozenset(observed))
