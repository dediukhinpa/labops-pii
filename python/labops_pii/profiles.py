"""Профили настроек: значения по умолчанию трёх проектов-потребителей.

Один код, различия только в настройках. Профиль выбирается переменной LABOPS_PII_PROFILE
(`labops`, `pragmatika`, `webapp_v2`); явные переменные окружения сервиса (PSEUDONYMIZER_*,
PII_GUARD_*) всегда главнее значений профиля.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace

PROFILE_ENV = "LABOPS_PII_PROFILE"
PROFILE_LABOPS = "labops"
PROFILE_PRAGMATIKA = "pragmatika"
PROFILE_WEBAPP_V2 = "webapp_v2"
DEFAULT_PROFILE = PROFILE_LABOPS

STORE_MEMORY = "memory"
STORE_SQLITE = "sqlite"
# Схема шифрования строк SQLite при записи. v2: ключи не зависят от префикса треда, файл
# читается и прежним кодом Прагматики. v3: ключи выводятся по префиксу треда (labops).
KEY_SCHEME_V2 = "v2"
KEY_SCHEME_V3 = "v3"

HOURS_PER_DAY = 24
GUARD_MODE_OFF = "off"
GUARD_MODE_LOG_ONLY = "log_only"
GUARD_MODE_ENFORCE = "enforce"

# Форма сервисного API (какие маршруты и поля есть у профиля)
SURFACE_LABOPS = "labops"
SURFACE_PRAGMATIKA = "pragmatika"


@dataclass(frozen=True, slots=True)
class Profile:
    """Значения по умолчанию одного проекта.

    Attributes:
        name: Имя профиля.
        store_backend: Хранилище таблицы замен: memory или sqlite.
        key_scheme: Схема ключей SQLite при записи (v2 или v3).
        retention_hours: Срок хранения замен треда без обращений, часов (0 - без удаления).
        mask_legal_entity_requisites: Маскировать ли названия организаций.
        mask_addresses: Маскировать ли адреса (улица + дом, индекс).
        expose_boot_id: Отдавать ли boot_id в /health (клиент по нему узнаёт о потере памяти).
        enable_delete_threads: Есть ли маршрут DELETE /threads/{id}.
        enable_inflect_signatory: Есть ли маршрут POST /inflect_signatory.
        accept_case_labels: Принимает ли /pseudonymize флаг case_labels (падежные метки).
        guard_names_mode: Режим проверки ФИО в guard по умолчанию.
        guard_address_mode: Режим проверки адресов в guard по умолчанию.
        contacts: Белый список имён по умолчанию (дополняется файлом контактов сервиса).
    """

    name: str
    store_backend: str
    key_scheme: str
    retention_hours: int
    mask_legal_entity_requisites: bool
    mask_addresses: bool
    expose_boot_id: bool
    enable_delete_threads: bool
    enable_inflect_signatory: bool
    accept_case_labels: bool
    guard_names_mode: str
    guard_address_mode: str
    contacts: tuple[str, ...] = ()


PROFILES: dict[str, Profile] = {
    # labops-ai-assistant: память 24 ч, юрлица маскируются, адреса не маскировались до сведения
    PROFILE_LABOPS: Profile(
        name=PROFILE_LABOPS,
        store_backend=STORE_MEMORY,
        key_scheme=KEY_SCHEME_V3,
        retention_hours=HOURS_PER_DAY,
        mask_legal_entity_requisites=True,
        mask_addresses=False,
        expose_boot_id=True,
        enable_delete_threads=True,
        enable_inflect_signatory=False,
        accept_case_labels=True,
        guard_names_mode=GUARD_MODE_OFF,
        guard_address_mode=GUARD_MODE_OFF,
    ),
    # pragmatika-ai: SQLite + Fernet, 90 дней, юрлица не маскируются, адреса и ФИО в guard
    PROFILE_PRAGMATIKA: Profile(
        name=PROFILE_PRAGMATIKA,
        store_backend=STORE_SQLITE,
        key_scheme=KEY_SCHEME_V2,
        retention_hours=90 * HOURS_PER_DAY,
        mask_legal_entity_requisites=False,
        mask_addresses=True,
        expose_boot_id=False,
        enable_delete_threads=False,
        enable_inflect_signatory=True,
        accept_case_labels=False,
        guard_names_mode=GUARD_MODE_LOG_ONLY,
        guard_address_mode=GUARD_MODE_LOG_ONLY,
    ),
    # web-app-v2: своего псевдонимизатора не было (план: общий сервис labops); guard искал
    # только цифровые типы, поэтому ФИО и адреса в guard выключены
    PROFILE_WEBAPP_V2: Profile(
        name=PROFILE_WEBAPP_V2,
        store_backend=STORE_MEMORY,
        key_scheme=KEY_SCHEME_V3,
        retention_hours=HOURS_PER_DAY,
        mask_legal_entity_requisites=True,
        mask_addresses=False,
        expose_boot_id=True,
        enable_delete_threads=True,
        enable_inflect_signatory=False,
        accept_case_labels=True,
        guard_names_mode=GUARD_MODE_OFF,
        guard_address_mode=GUARD_MODE_OFF,
    ),
}


def get_profile(name: str | None = None, env: Mapping[str, str] | None = None) -> Profile:
    """Профиль по имени; без имени - из LABOPS_PII_PROFILE в env, затем из окружения процесса.

    Args:
        name: Имя профиля или None.
        env: Словарь переменных (по умолчанию окружение процесса).

    Returns:
        Профиль.

    Raises:
        ValueError: Неизвестное имя профиля (опечатка не должна молча менять защиту).
    """
    source = os.environ if env is None else env
    chosen = (name or source.get(PROFILE_ENV) or os.environ.get(PROFILE_ENV) or "").strip()
    chosen = chosen.lower() or DEFAULT_PROFILE
    try:
        return PROFILES[chosen]
    except KeyError as exc:
        known = ", ".join(sorted(PROFILES))
        raise ValueError(f"{PROFILE_ENV}: неизвестный профиль «{chosen}», есть: {known}") from exc


def with_overrides(profile: Profile, **changes: object) -> Profile:
    """Копия профиля с изменёнными полями (для тестов и нестандартных развёртываний)."""
    return replace(profile, **changes)  # type: ignore[arg-type]
