"""Настройки pii-guard из окружения: апстримы и режим работы.

Апстрим выбирается путём запроса: `/u/<имя>/v1/messages` уходит на адрес, заданный для
`<имя>` в PII_GUARD_UPSTREAMS. Адрес апстрима клиент передать не может (только имя из
закрытого списка), поэтому guard нельзя превратить в открытый прокси.
"""

import os
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

UPSTREAMS_ENV = "PII_GUARD_UPSTREAMS"
MODE_ENV = "PII_GUARD_MODE"
# Апстримы, которым можно видеть почту аккаунта подписки в шаблоне CLI «# userEmail»
# (detector.strip_account_email): провайдер и так знает логин своего аккаунта
ACCOUNT_EMAIL_UPSTREAMS_ENV = "PII_GUARD_ACCOUNT_EMAIL_UPSTREAMS"
DEFAULT_ACCOUNT_EMAIL_UPSTREAMS = "anthropic"
# Подписка и ключ API ходят в один и тот же API; китайские провайдеры добавляются конфигом
DEFAULT_UPSTREAMS = "anthropic=https://api.anthropic.com"
UPSTREAM_NAME_RE = re.compile(r"[a-z0-9-]{1,32}")
# Открытый http допустим только к loopback (тесты, локальная разведка); наружу - только https
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
UPSTREAM_PREFIX = "/u/"


class GuardMode(StrEnum):
    """Режим реакции на находку."""

    # Находка -> 422, запрос не уходит (боевой режим)
    BLOCK = "block"
    # Находка -> только запись в журнал, запрос уходит (на время выкатки)
    LOG = "log"


DEFAULT_MODE = GuardMode.BLOCK


@dataclass(frozen=True, slots=True)
class Upstream:
    """Апстрим, на который guard пересылает проверенные запросы.

    Attributes:
        name: Имя в пути запроса (`/u/<name>/...`).
        base_url: Базовый адрес без завершающего «/» (может содержать путь).
        allow_account_email: Почта аккаунта в шаблоне CLI «# userEmail» не находка.
    """

    name: str
    base_url: str
    allow_account_email: bool = False


def _validate_url(name: str, url: str) -> str:
    """Проверяет адрес апстрима и убирает завершающий «/».

    Raises:
        ValueError: Адрес без схемы/хоста, с query/фрагментом/учётными данными или
            открытый http не к loopback.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"{UPSTREAMS_ENV}: у апстрима «{name}» нужен адрес http(s)://хост")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError(f"{UPSTREAMS_ENV}: адрес «{name}» не должен содержать query и логин")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        raise ValueError(f"{UPSTREAMS_ENV}: апстрим «{name}» вне loopback должен быть https")
    return url.rstrip("/")


def parse_upstreams(
    raw: str | None, account_email_raw: str | None = None
) -> dict[str, Upstream]:
    """Разбирает список апстримов `имя=адрес,имя=адрес`.

    Args:
        raw: Значение PII_GUARD_UPSTREAMS; None или пусто - только Anthropic API.
        account_email_raw: Значение PII_GUARD_ACCOUNT_EMAIL_UPSTREAMS (имена через запятую);
            None - «anthropic», пустая строка - ни одного.

    Returns:
        Апстримы по имени.

    Raises:
        ValueError: Неверный формат, имя или адрес, повтор имени.
    """
    source = raw.strip() if raw is not None and raw.strip() else DEFAULT_UPSTREAMS
    result: dict[str, Upstream] = {}
    for item in source.split(","):
        entry = item.strip()
        if not entry:
            raise ValueError(f"{UPSTREAMS_ENV}: пустой элемент списка")
        name, sep, url = entry.partition("=")
        name = name.strip()
        if not sep or UPSTREAM_NAME_RE.fullmatch(name) is None:
            raise ValueError(f"{UPSTREAMS_ENV}: элемент должен быть вида имя=адрес, имя [a-z0-9-]")
        if name in result:
            raise ValueError(f"{UPSTREAMS_ENV}: имя «{name}» повторено")
        result[name] = Upstream(name=name, base_url=_validate_url(name, url.strip()))
    source_names = (
        DEFAULT_ACCOUNT_EMAIL_UPSTREAMS if account_email_raw is None else account_email_raw
    )
    for item in source_names.split(","):
        name = item.strip()
        if not name:
            continue
        if name not in result:
            raise ValueError(f"{ACCOUNT_EMAIL_UPSTREAMS_ENV}: апстрим «{name}» не настроен")
        result[name] = Upstream(name=name, base_url=result[name].base_url, allow_account_email=True)
    return result


def parse_mode(raw: str | None) -> GuardMode:
    """Разбирает PII_GUARD_MODE (по умолчанию block).

    Raises:
        ValueError: Значение не из block/log (опечатка не должна молча отключать защиту).
    """
    if raw is None or not raw.strip():
        return DEFAULT_MODE
    try:
        return GuardMode(raw.strip().lower())
    except ValueError as exc:
        raise ValueError(f"{MODE_ENV} должна быть block или log") from exc


def load_upstreams() -> dict[str, Upstream]:
    """Апстримы из окружения процесса."""
    return parse_upstreams(
        os.environ.get(UPSTREAMS_ENV), os.environ.get(ACCOUNT_EMAIL_UPSTREAMS_ENV)
    )


def load_mode() -> GuardMode:
    """Режим из окружения процесса."""
    return parse_mode(os.environ.get(MODE_ENV))


def split_upstream_path(path: str) -> tuple[str, str] | None:
    """Делит путь `/u/<имя>/<остаток>` на имя и остаток (с ведущим «/»).

    Args:
        path: Путь запроса.

    Returns:
        (имя, остаток) или None, если путь не под префиксом апстрима.
    """
    if not path.startswith(UPSTREAM_PREFIX):
        return None
    name, sep, rest = path[len(UPSTREAM_PREFIX):].partition("/")
    if not sep or UPSTREAM_NAME_RE.fullmatch(name) is None:
        return None
    return name, "/" + rest
