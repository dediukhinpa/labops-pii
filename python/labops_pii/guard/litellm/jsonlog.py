"""JSON-логи pii-guard: форматтер, ASGI-middleware запросов и настройка логирования.

Одна запись - одна JSON-строка в stdout. В лог не попадают никогда: тела запросов и ответов,
найденные значения ПДн, фрагменты текста, смещения и длины совпадений, query-строки, заголовки
авторизации. Маршрут пишется только из закрытого списка (произвольный путь запроса сам может
нести ПДн), а у обычных записей `logging` в `msg` идёт шаблон сообщения ДО подстановки
аргументов (аргументы не пишутся).

Код отказа (`code`) - короткая метка причины из фиксированного словаря: категории ПДн
(phone, email, inn, ...) или технические причины (content_encoding, body_too_large, ...).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
import time
from collections.abc import Awaitable, Callable, MutableMapping
from datetime import datetime, timezone
from typing import Any, TextIO

SERVICE_NAME = "pii-guard"
HTTP_LOGGER_NAME = "pii_guard.http"

EVENT_LOG = "log"
EVENT_HTTP_REQUEST = "http_request"
EVENT_DENIED = "pii_guard_denied"
EVENT_REJECTED = "http_request_rejected"
EVENT_FAILED = "pii_guard_failed"
EVENT_SERVICE_STARTED = "service_started"
# Метаданные картинок маршрута зрения (mime, размер, префикс sha256); в таблицу классов не входит
EVENT_VISION_IMAGES = "vision_images"
# Отметка запроса маршрута страниц сайтов (только route, без содержимого)
EVENT_WEBPAGE_REQUEST = "webpage_request"
# Находка, которая только наблюдается (ФИО или адрес в режиме log_only): запрос не отклонён.
# Вне таблицы классов: severity берётся по уровню записи (info)
EVENT_PII_OBSERVED = "pii_guard_observed"

# Класс события; значения совпадают с core/src/adapters/telemetry/severity.ts (парити-тест
# разбирает строки ниже, поэтому формат строго `    "событие": "класс",`).
EVENT_SEVERITY: dict[str, str] = {
    "pii_guard_denied": "warning",
    "pii_guard_failed": "serious",
    "service_started": "info",
    "http_request": "info",
    "http_request_rejected": "warning",
}

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_SERIOUS = "serious"

# Коды, которые ставит не обработчик, а сам middleware
CODE_UPSTREAM_5XX = "upstream_5xx"
CODE_UNHANDLED = "unhandled_error"

# Маршруты, которые можно писать как есть; всё остальное - "unmatched"
KNOWN_ROUTES = frozenset(
    {"/v1/messages", "/search/v1/messages", "/vision/v1/messages", "/webpage/v1/messages",
     "/_guard/healthz", "/_guard/metrics"}
)
UNMATCHED_ROUTE = "unmatched"

REQUEST_ID_HEADER = b"x-request-id"
REQUEST_ID_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")

HTTP_FAILED_FROM = 500
HTTP_REJECTED_FROM = 400
HTTP_INTERNAL_ERROR = 500
# Нестандартный код «клиент закрыл соединение»
HTTP_CLIENT_CLOSED = 499
# Страховочный предел длины шаблона сообщения: шаблоны статические и короткие
MAX_MSG_CHARS = 300
MS_IN_SECOND = 1000.0
DURATION_DIGITS = 1
# Ключ словаря scope["state"], в который обработчик кладёт итог запроса
STATE_KEY = "guard_log"

LEVEL_NAMES: dict[int, str] = {
    logging.DEBUG: "info",
    logging.INFO: "info",
    logging.WARNING: "warning",
    logging.ERROR: "error",
    logging.CRITICAL: "critical",
}

# Поля, которые форматтер берёт из `extra` записи (остальное в лог не попадает)
# pii_types - только имена видов ПДн (маршрут публичных страниц), не значения
EXTRA_FIELDS = (
    "request_id", "code", "route", "status", "duration_ms", "exc_type", "images", "pii_types",
)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def parse_request_id(value: str | None) -> str | None:
    """Проверяет значение X-Request-Id.

    Args:
        value: Значение заголовка или None.

    Returns:
        Само значение, если оно подходит под [A-Za-z0-9_-]{8,64}, иначе None.
    """
    if value is None or REQUEST_ID_RE.fullmatch(value) is None:
        return None
    return value


def known_route(path: str) -> str:
    """Возвращает путь, если он из закрытого списка, иначе "unmatched"."""
    return path if path in KNOWN_ROUTES else UNMATCHED_ROUTE


def mark_denied(scope: Scope, code: str) -> None:
    """Помечает запрос как отказ guard с кодом причины (значения ПДн сюда не передавать).

    Args:
        scope: ASGI scope запроса.
        code: Короткий код причины.
    """
    scope.setdefault("state", {})[STATE_KEY] = {"kind": EVENT_DENIED, "code": code}


def mark_failed(scope: Scope, code: str, exc: BaseException | None = None) -> None:
    """Помечает запрос как внутренний сбой guard (из исключения берётся только тип).

    Args:
        scope: ASGI scope запроса.
        code: Короткий код причины.
        exc: Исключение или None.
    """
    scope.setdefault("state", {})[STATE_KEY] = {
        "kind": EVENT_FAILED,
        "code": code,
        "exc_type": type(exc).__name__ if exc is not None else None,
    }


def _level_severity(levelno: int) -> str:
    """Класс по уровню записи, у которой нет события из таблицы."""
    if levelno >= logging.ERROR:
        return SEVERITY_SERIOUS
    if levelno >= logging.WARNING:
        return SEVERITY_WARNING
    return SEVERITY_INFO


def severity_of(event: str, levelno: int) -> str:
    """Класс события: из таблицы, иначе по уровню записи."""
    return EVENT_SEVERITY.get(event) or _level_severity(levelno)


def _format_ts(created: float) -> str:
    """Время записи: ISO UTC с миллисекундами и суффиксом Z."""
    moment = datetime.fromtimestamp(created, tz=timezone.utc)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


class JsonFormatter(logging.Formatter):
    """Пишет запись одной JSON-строкой с фиксированным белым списком полей."""

    def format(self, record: logging.LogRecord) -> str:
        """Собирает JSON-строку; аргументы сообщения и текст исключения не пишутся."""
        event = getattr(record, "event", None)
        payload: dict[str, Any] = {
            "ts": _format_ts(record.created),
            "level": LEVEL_NAMES.get(record.levelno, "info"),
            "severity": severity_of(event or EVENT_LOG, record.levelno),
            "event": event or EVENT_LOG,
            "service": SERVICE_NAME,
        }
        extras = {name: getattr(record, name, None) for name in EXTRA_FIELDS}
        if extras["exc_type"] is None and record.exc_info and record.exc_info[0] is not None:
            extras["exc_type"] = record.exc_info[0].__name__
        for name, value in extras.items():
            if value is not None:
                payload[name] = value
        # msg - шаблон до подстановки args; у событий с явным именем он не нужен
        if event is None and isinstance(record.msg, str):
            payload["msg"] = record.msg[:MAX_MSG_CHARS]
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class _GuardJsonHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Метка нашего обработчика: повторная настройка не плодит дубли."""


def configure_logging(level: int | str = logging.INFO, stream: TextIO | None = None) -> None:
    """Подключает к корневому логгеру JSON-обработчик (в stdout) и убирает дубли uvicorn.

    Чужие обработчики корневого логгера не трогаются; свой заменяется, а не добавляется.

    Args:
        level: Уровень корневого логгера.
        stream: Поток вывода; по умолчанию stdout.
    """
    root = logging.getLogger()
    for old in [h for h in root.handlers if isinstance(h, _GuardJsonHandler)]:
        root.removeHandler(old)
    handler = _GuardJsonHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    # Текстовые логи uvicorn заменяются нашими JSON-записями через корневой логгер
    for name in ("uvicorn", "uvicorn.error"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False


def log_event(
    logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any
) -> None:
    """Пишет именованное событие; `fields` - только поля из EXTRA_FIELDS."""
    logger.log(level, event, extra={"event": event, **fields})


class JsonLogMiddleware:
    """Чистый ASGI-middleware: одно событие на запрос после ответа.

    Тело запроса и ответа не читается и не буферизуется: `receive` передаётся как есть, а
    `send` лишь подсматривает код статуса.

    Args:
        app: Следующее приложение ASGI.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app
        self._logger = logging.getLogger(HTTP_LOGGER_NAME)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        started = time.perf_counter()
        raw = next((v for k, v in scope["headers"] if k == REQUEST_ID_HEADER), None)
        request_id = parse_request_id(raw.decode("latin-1") if raw is not None else None)
        scope.setdefault("state", {})
        status: int | None = None
        exc_type: str | None = None
        cancelled = False

        async def spy_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self._app(scope, receive, spy_send)
        except asyncio.CancelledError:
            cancelled = True
            raise
        except Exception as exc:
            exc_type = type(exc).__name__
            status = HTTP_INTERNAL_ERROR
            raise
        finally:
            if cancelled and status is None:
                status = HTTP_CLIENT_CLOSED
            duration = round((time.perf_counter() - started) * MS_IN_SECOND, DURATION_DIGITS)
            self._emit(scope, request_id, status or HTTP_INTERNAL_ERROR, duration, exc_type)

    def _emit(
        self,
        scope: Scope,
        request_id: str | None,
        status: int,
        duration: float,
        exc_type: str | None,
    ) -> None:
        """Пишет итоговое событие запроса."""
        path = scope.get("path")
        fields: dict[str, Any] = {
            "request_id": request_id,
            "route": known_route(path if isinstance(path, str) else ""),
            "status": status,
            "duration_ms": duration,
        }
        outcome = scope.get("state", {}).get(STATE_KEY) or {}
        kind = outcome.get("kind")
        if exc_type is not None:
            fields["code"] = CODE_UNHANDLED
            fields["exc_type"] = exc_type
            log_event(self._logger, EVENT_FAILED, logging.ERROR, **fields)
        elif kind == EVENT_FAILED:
            fields["code"] = outcome.get("code")
            fields["exc_type"] = outcome.get("exc_type")
            log_event(self._logger, EVENT_FAILED, logging.ERROR, **fields)
        elif kind == EVENT_DENIED:
            fields["code"] = outcome.get("code")
            log_event(self._logger, EVENT_DENIED, logging.WARNING, **fields)
        elif status >= HTTP_FAILED_FROM:
            # 5xx от апстрима, прошедший через guard как есть
            fields["code"] = CODE_UPSTREAM_5XX
            log_event(self._logger, EVENT_FAILED, logging.ERROR, **fields)
        elif status >= HTTP_REJECTED_FROM:
            # 4xx апстрима, прошедший через guard как есть (например 429): не отказ по ПДн
            log_event(self._logger, EVENT_REJECTED, logging.WARNING, **fields)
        else:
            log_event(self._logger, EVENT_HTTP_REQUEST, logging.INFO, **fields)
