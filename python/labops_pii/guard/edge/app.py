"""Прокси-фильтр ПДн между CLI-песочницей на узле edge и API модели.

Вторая линия защиты (первая - псевдонимизация в РФ): CLI ходит сюда через
переменную базового адреса API (http://127.0.0.1:<порт>/u/<апстрим>); guard проверяет тело
и адрес запроса и пересылает их в апстрим БАЙТ-В-БАЙТ (блоки thinking с подписью не меняются),
а ответ (в том числе SSE-поток) отдаёт без буферизации.

Тело запроса читается целиком (иначе его нельзя проверить). Режим fail closed: сбой
проверки -> 503, сбой апстрима -> 502, непроверенное в апстрим не уходит. Заголовки
authorization (OAuth подписки) и x-api-key пересылаются как есть и в журнал не попадают.
В журнал идут только маршрут, имя апстрима, код и типы находок (jsonlog.py).
"""

import asyncio
import logging
import os
from collections.abc import AsyncIterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response

from labops_pii.errors import reject_legacy_profile
from labops_pii.guard.address import ADDRESS_MODE_ENV, parse_address_mode
from labops_pii.guard.detector import BodyNotJsonError, BodyTooLargeError
from labops_pii.guard.edge.config import (
    GuardMode,
    Upstream,
    load_mode,
    load_upstreams,
    split_upstream_path,
)
from labops_pii.guard.edge.jsonlog import (
    EVENT_SERVICE_STARTED,
    JsonLogMiddleware,
    configure_logging,
    log_event,
    mark_denied,
    mark_failed,
    mark_observed,
    mark_upstream,
)
from labops_pii.guard.names import NAMES_MODE_ENV, parse_names_mode
from labops_pii.guard.policy import split_findings
from labops_pii.guard.proxy import (
    SCAN_WORKERS,
    Slot,
    SlotStreamingResponse,
    forward_headers,
    has_identity_encoding,
    max_body_bytes,
    read_body,
    scan_request,
    send_unless_disconnected,
    stream_upstream,
    upstream_client,
)
from labops_pii.guard.proxy import error_response as _error

logger = logging.getLogger("pii_guard")

HTTP_PII = 422
HTTP_NOT_FOUND = 404
HTTP_UNSUPPORTED_MEDIA = 415
HTTP_TOO_LARGE = 413
HTTP_GUARD_FAILURE = 503
HTTP_BAD_GATEWAY = 502
# Нестандартный код «клиент закрыл соединение»: в журнале отличает отмену от сбоя.
HTTP_CLIENT_CLOSED = 499
# Метка отказа по ПДн в тексте ошибки: CLI печатает сообщение API в итог хода, по ней
# edge/worker отличают отказ guard (ход -> pii_request_rejected) от прочих ошибок API.
PII_REJECTED_CODE = "pii_request_rejected"
# Коды причин отказа для журнала (категории ПДн берутся из detector, значения - никогда)
CODE_UNKNOWN_ROUTE = "unknown_route"
CODE_UNKNOWN_UPSTREAM = "unknown_upstream"
CODE_GUARD_BUSY = "guard_busy"
CODE_CONTENT_ENCODING = "content_encoding"
CODE_BODY_TOO_LARGE = "body_too_large"
CODE_BODY_NOT_JSON = "body_not_json"
CODE_SCAN_FAILURE = "scan_failure"
CODE_UPSTREAM_FAILURE = "upstream_failure"
CODE_CLIENT_DISCONNECTED = "client_disconnected"
# Предел запросов в полёте. Слот занят от чтения тела до конца отдачи ответа: всё это время
# тело (до 8 МиБ) живёт в памяти. Ходов на узле немного, предел - страховка памяти юнита.
MAX_INFLIGHT_REQUESTS = 16
# Сколько запрос ждёт свободный слот, прежде чем получить 503. Тело к этому моменту не
# читается, поэтому очередь памяти не копит.
SLOT_WAIT_SECONDS = 15.0
HTTP_BUSY = 503
RETRY_AFTER_SECONDS = 5
# SDK CLI повторяет 5xx и часть 4xx; на отказ guard повтор бессмыслен (тело то же), а 503
# сбоя проверки с повторами растянул бы ход на минуты. Заголовок SDK понимает напрямую.
NO_RETRY_HEADERS = {"x-should-retry": "false"}

def _has_dot_segment(path: str) -> bool:
    """Есть ли в пути сегмент «.» или «..»."""
    return any(segment in (".", "..") for segment in path.split("/"))


def create_app(
    upstreams: Mapping[str, Upstream] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    max_inflight: int = MAX_INFLIGHT_REQUESTS,
    slot_wait_seconds: float = SLOT_WAIT_SECONDS,
    mode: GuardMode | None = None,
) -> FastAPI:
    """Создаёт приложение.

    Args:
        upstreams: Апстримы по имени. По умолчанию из PII_GUARD_UPSTREAMS.
        transport: Транспорт httpx (для тестов).
        max_inflight: Предел одновременно обрабатываемых запросов (память под тела).
        slot_wait_seconds: Сколько запрос ждёт слот до ответа 503.
        mode: Реакция на находку. По умолчанию из PII_GUARD_MODE (block).

    Returns:
        Приложение FastAPI.

    Raises:
        ValueError: Недопустимые MAX_BODY_BYTES, PII_GUARD_UPSTREAMS или PII_GUARD_MODE.
        ConfigError: Задана прежняя LABOPS_PII_PROFILE.
    """
    reject_legacy_profile()
    # Неизвестный режим ФИО или адресов - ошибка старта, как в guard.litellm: раньше edge их не
    # проверял, и опечатка молча давала режим по умолчанию
    parse_names_mode(os.environ.get(NAMES_MODE_ENV))
    parse_address_mode(os.environ.get(ADDRESS_MODE_ENV))
    routes = dict(upstreams) if upstreams is not None else load_upstreams()
    guard_mode = mode if mode is not None else load_mode()
    max_body = max_body_bytes()
    client = upstream_client(transport)
    scan_pool = ThreadPoolExecutor(max_workers=SCAN_WORKERS, thread_name_prefix="pii-scan")
    inflight = asyncio.Semaphore(max_inflight)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        """Закрывает пул соединений при остановке."""
        log_event(logger, EVENT_SERVICE_STARTED, code=guard_mode.value)
        yield
        scan_pool.shutdown(wait=False, cancel_futures=True)
        await client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    # Внешний слой: пишет одну JSON-строку на запрос (тело не читает)
    app.add_middleware(JsonLogMiddleware)

    @app.get("/_guard/healthz")
    async def healthz() -> dict[str, str]:
        """Проверка живости самого фильтра (до апстрима не ходит)."""
        return {"status": "ok", "mode": guard_mode.value}

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def proxy(path: str, request: Request) -> Response:
        """Выбирает апстрим, берёт слот запроса в полёте и проксирует запрос."""
        raw = request.scope.get("raw_path")
        raw_path = raw.decode("latin-1") if isinstance(raw, bytes) else request.url.path
        # Имя апстрима берётся из сырого пути: «%2F» в имени не должен менять маршрут
        split = split_upstream_path(raw_path)
        if split is None:
            mark_denied(request.scope, CODE_UNKNOWN_ROUTE)
            return _error(HTTP_NOT_FOUND, "not_found_error", "not found")
        name, _ = split
        upstream = routes.get(name)
        if upstream is None:
            mark_denied(request.scope, CODE_UNKNOWN_UPSTREAM)
            return _error(HTTP_NOT_FOUND, "not_found_error", "unknown upstream")
        mark_upstream(request.scope, name)
        # Остаток пути для апстрима - из разобранного пути (как его увидит и сканер)
        decoded = split_upstream_path(request.url.path)
        rest = decoded[1] if decoded is not None else "/"
        if decoded is None or decoded[0] != name or _has_dot_segment(rest):
            # «..» и «.» в пути могли бы увести запрос за базовый путь апстрима
            mark_denied(request.scope, CODE_UNKNOWN_ROUTE)
            return _error(HTTP_NOT_FOUND, "not_found_error", "not found")
        try:
            await asyncio.wait_for(inflight.acquire(), timeout=slot_wait_seconds)
        except TimeoutError:
            mark_denied(request.scope, CODE_GUARD_BUSY)
            return _error(
                HTTP_BUSY, "overloaded_error", "pii guard is busy, retry later",
                headers={"retry-after": str(RETRY_AFTER_SECONDS)}, code=CODE_GUARD_BUSY,
            )
        slot = Slot(inflight)
        try:
            response = await _handle(upstream, rest, request, slot)
        except BaseException:
            slot.release()
            raise
        if not isinstance(response, SlotStreamingResponse):
            # Отказ или ошибка: ответ маленький, слот нужен только до этого момента
            slot.release()
        return response

    def _too_large(request: Request) -> Response:
        mark_denied(request.scope, CODE_BODY_TOO_LARGE)
        return _error(HTTP_TOO_LARGE, "request_too_large", "request body too large")

    async def _handle(upstream: Upstream, rest: str, request: Request, slot: Slot) -> Response:
        """Проверяет тело и адрес на ПДн и проксирует запрос в апстрим."""
        if not has_identity_encoding(request):
            # Сжатое тело не прочитать, а пропустить непроверенным нельзя
            mark_denied(request.scope, CODE_CONTENT_ENCODING)
            return _error(
                HTTP_UNSUPPORTED_MEDIA, "invalid_request_error", "content-encoding not supported"
            )
        body = await read_body(request, max_body)
        if body is None:
            return _too_large(request)
        try:
            found = await scan_request(
                scan_pool, body, rest, request.url.query, max_body, upstream.allow_account_email
            )
        except BodyTooLargeError:
            # Страховка: детектор получил тот же предел, но непроверенное тело не пропускаем
            return _too_large(request)
        except BodyNotJsonError:
            mark_denied(request.scope, CODE_BODY_NOT_JSON)
            return _error(
                HTTP_UNSUPPORTED_MEDIA, "invalid_request_error", "request body must be json"
            )
        except Exception as exc:  # noqa: BLE001 - fail closed на любой сбой проверки
            mark_failed(request.scope, CODE_SCAN_FAILURE, exc)
            return _error(
                HTTP_GUARD_FAILURE, "api_error", "pii guard failure", headers=NO_RETRY_HEADERS
            )

        # ФИО и адрес решает их собственный режим (log_only только наблюдает), как на маршрутах
        # guard.litellm: раньше edge блокировал любую находку, и log_only работал как enforce
        findings = split_findings(found)
        if guard_mode is GuardMode.LOG:
            blocking: frozenset[str] = frozenset()
            observed = findings.blocking | findings.observed
        else:
            blocking, observed = findings.blocking, findings.observed
        if observed and not blocking:
            # Код - только имена категорий (phone, email, inn, ...), без значений
            mark_observed(request.scope, "+".join(sorted(observed)))
        if blocking:
            types = sorted(blocking)
            mark_denied(request.scope, "+".join(types))
            return _error(
                HTTP_PII,
                "invalid_request_error",
                f"{PII_REJECTED_CODE}: request contains personal data: {', '.join(types)}",
                headers=NO_RETRY_HEADERS,
                code=PII_REJECTED_CODE,
                pii_types=types,
            )

        return await _forward(request, upstream, rest, body, slot)

    async def _forward(
        request: Request, upstream: Upstream, rest: str, body: bytes, slot: Slot
    ) -> Response:
        """Пересылает проверенное тело в апстрим как есть и отдаёт ответ потоком."""
        url = httpx.URL(upstream.base_url + rest, query=request.url.query.encode())
        try:
            upstream_req = client.build_request(
                request.method, url, headers=forward_headers(request), content=body
            )
            sent = await send_unless_disconnected(request, client, upstream_req)
        except Exception as exc:  # noqa: BLE001 - fail closed
            mark_failed(request.scope, CODE_UPSTREAM_FAILURE, exc)
            return _error(HTTP_BAD_GATEWAY, "api_error", "upstream unavailable")
        if sent is None:
            mark_denied(request.scope, CODE_CLIENT_DISCONNECTED)
            return Response(status_code=HTTP_CLIENT_CLOSED)
        return stream_upstream(sent, slot)

    return app


def _configure_logging() -> None:
    """Настраивает JSON-логи в stdout: только метаданные, уровень из LOG_LEVEL."""
    configure_logging(os.environ.get("LOG_LEVEL", "INFO").upper())
    # Журнал запросов httpx дублирует наш (и без аргументов бесполезен): только предупреждения
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def build_app() -> FastAPI:
    """Фабрика для uvicorn (`--factory`): настройка читается при старте, не при импорте."""
    _configure_logging()
    return create_app()
