"""Ошибки конфигурации, общие для сервисов (псевдонимизатор, guard, media)."""

from __future__ import annotations

import os
from collections.abc import Mapping

# Переменная прежних профилей (до 1.0.0): больше не читается, её наличие - ошибка старта
LEGACY_PROFILE_ENV = "LABOPS_PII_PROFILE"
MIGRATION_DOC = "docs/MIGRATION.md"


class ConfigError(RuntimeError):
    """Ошибка конфигурации: сервис не должен стартовать."""


def reject_legacy_profile(env: Mapping[str, str] | None = None) -> None:
    """Прерывает старт, если задана прежняя переменная профиля.

    Профили удалены в 1.0.0: молча игнорировать переменную нельзя, потому что сервис стартовал
    бы с нейтральными значениями вместо настроек профиля (другое маскирование, другая схема
    ключей SQLite).

    Args:
        env: Окружение (по умолчанию os.environ).

    Raises:
        ConfigError: Переменная LABOPS_PII_PROFILE задана непустым значением.
    """
    source = os.environ if env is None else env
    if source.get(LEGACY_PROFILE_ENV, "").strip():
        raise ConfigError(
            f"{LEGACY_PROFILE_ENV} больше не поддерживается (с 1.0.0): уберите её и задайте "
            f"переменные окружения явно, таблица соответствия в {MIGRATION_DOC}"
        )
