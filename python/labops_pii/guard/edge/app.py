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
from typing import Any
from urllib.parse import unquote, unquote_plus

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.types import Receive, Scope, Send

from labops_pii.errors import reject_legacy_profile
from labops_pii.guard.detector import (
    DEFAULT_MAX_SCAN_BYTES,
    BodyNotJsonError,
    BodyTooLargeError,
    find_pii_types,
    scan_body,
)
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

logger = logging.getLogger("pii_guard")

MAX_BODY_ENV = "MAX_BODY_BYTES"
# Единственный предел размера: он же передаётся детектору как предел сканирования.
DEFAULT_MAX_BODY = DEFAULT_MAX_SCAN_BYTES
UPSTREAM_TIMEOUT_ENV = "UPSTREAM_TIMEOUT_SECONDS"
DEFAULT_UPSTREAM_TIMEOUT = 600.0
CONNECT_TIMEOUT = 10.0

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
# Проверка идёт в отдельных потоках, чтобы не занимать цикл событий. Потоков немного:
# проверка грузит процессор, а очередь сверх этого только копит память под тела.
SCAN_WORKERS = 4
# Кодирование тела, при котором содержимое можно читать как есть
IDENTITY_ENCODINGS = frozenset({"", "identity"})
# Как часто проверять, не ушёл ли клиент, пока апстрим молчит (до первого заголовка).
DISCONNECT_POLL_SECONDS = 0.5

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

# Заголовки, которые не пересылаются дальше (hop-by-hop и пересчитываемые)
SKIP_REQUEST_HEADERS = frozenset(
    {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "te",
     "upgrade", "proxy-authorization", "proxy-authenticate", "trailer"}
)
SKIP_RESPONSE_HEADERS = frozenset(
    {"content-length", "connection", "keep-alive", "transfer-encoding", "te", "upgrade",
     "trailer", "content-encoding"}
)


def _error(
    status: int,
    kind: str,
    message: str,
    headers: Mapping[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    """Формирует ошибку в формате API модели (type=error, error.type, error.message)."""
    payload: dict[str, Any] = {
        "type": "error",
        "error": {"type": kind, "message": message},
    }
    payload.update(extra)
    return JSONResponse(status_code=status, content=payload, headers=dict(headers or {}))


class _Slot:
    """Слот запроса в полёте: освобождается ровно один раз, с любой стороны."""

    def __init__(self, semaphore: asyncio.Semaphore) -> None:
        self._semaphore: asyncio.Semaphore | None = semaphore

    def release(self) -> None:
        """Возвращает слот (повторный вызов ничего не делает)."""
        semaphore, self._semaphore = self._semaphore, None
        if semaphore is not None:
            semaphore.release()


class _SlotStreamingResponse(StreamingResponse):
    """Потоковый ответ, который держит слот до конца отдачи (в том числе при обрыве)."""

    def __init__(self, *args: Any, slot: _Slot, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._slot = slot

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Отдаёт ответ и освобождает слот, даже если клиент оборвал соединение."""
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._slot.release()


async def _send_unless_disconnected(
    request: Request,
    client: httpx.AsyncClient,
    upstream_req: httpx.Request,
) -> httpx.Response | None:
    """Отправляет запрос в апстрим и отменяет его, если клиент ушёл раньше ответа.

    Без этого запрос убитого хода (рубильник edge, отмена пользователем) продолжал бы
    исполняться у провайдера и тратить подписку впустую.

    Args:
        request: Входящий запрос (источник сигнала об отключении клиента).
        client: Клиент httpx к апстриму.
        upstream_req: Подготовленный запрос к апстриму.

    Returns:
        Ответ апстрима (поток открыт) или None, если клиент отключился.

    Raises:
        Exception: Любая ошибка апстрима пробрасывается вызывающему.
    """
    task = asyncio.ensure_future(client.send(upstream_req, stream=True))
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=DISCONNECT_POLL_SECONDS)
            if done:
                return task.result()
            if await request.is_disconnected():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return None
    except BaseException:
        # Отмена самого обработчика (сервер оборвал запрос): апстрим тоже отменяем.
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raise


def _has_dot_segment(path: str) -> bool:
    """Есть ли в пути сегмент «.» или «..»."""
    return any(segment in (".", "..") for segment in path.split("/"))


def _max_body_bytes() -> int:
    """Читает предел тела из MAX_BODY_BYTES.

    Raises:
        ValueError: Значение не целое или не больше нуля (приложение не запускается).
    """
    raw = os.environ.get(MAX_BODY_ENV)
    if raw is None:
        return DEFAULT_MAX_BODY
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{MAX_BODY_ENV} должна быть целым числом байт") from exc
    if value <= 0:
        raise ValueError(f"{MAX_BODY_ENV} должна быть больше нуля")
    return value


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
    routes = dict(upstreams) if upstreams is not None else load_upstreams()
    guard_mode = mode if mode is not None else load_mode()
    max_body = _max_body_bytes()
    timeout = httpx.Timeout(
        float(os.environ.get(UPSTREAM_TIMEOUT_ENV, DEFAULT_UPSTREAM_TIMEOUT)),
        connect=CONNECT_TIMEOUT,
    )
    client = httpx.AsyncClient(timeout=timeout, transport=transport)
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

    async def _scan(body: bytes, path: str, query: str, allow_account_email: bool) -> set[str]:
        """Проверяет тело (должно быть JSON) и адрес запроса в пуле потоков.

        Адрес проверяется после раскодирования %-последовательностей, в том числе Unicode:
        ПДн в пути или в строке запроса так же недопустимы, как в теле.
        """
        loop = asyncio.get_running_loop()
        found: set[str] = set()
        if body:
            found |= await loop.run_in_executor(
                scan_pool, scan_body, body, max_body, True, allow_account_email
            )
        address = unquote(path) + "\n" + unquote_plus(query)
        found |= await loop.run_in_executor(scan_pool, find_pii_types, address)
        return found

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
        slot = _Slot(inflight)
        try:
            response = await _handle(upstream, rest, request, slot)
        except BaseException:
            slot.release()
            raise
        if not isinstance(response, _SlotStreamingResponse):
            # Отказ или ошибка: ответ маленький, слот нужен только до этого момента
            slot.release()
        return response

    async def _read_body(request: Request) -> bytes | Response:
        """Читает тело целиком с проверкой предела; при отказе возвращает ответ-ошибку."""
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > max_body:
            mark_denied(request.scope, CODE_BODY_TOO_LARGE)
            return _error(HTTP_TOO_LARGE, "request_too_large", "request body too large")
        chunks: list[bytes] = []
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > max_body:
                mark_denied(request.scope, CODE_BODY_TOO_LARGE)
                return _error(HTTP_TOO_LARGE, "request_too_large", "request body too large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _handle(upstream: Upstream, rest: str, request: Request, slot: _Slot) -> Response:
        """Проверяет тело и адрес на ПДн и проксирует запрос в апстрим."""
        encoding = request.headers.get("content-encoding", "").strip().lower()
        if encoding not in IDENTITY_ENCODINGS:
            # Сжатое тело не прочитать, а пропустить непроверенным нельзя
            mark_denied(request.scope, CODE_CONTENT_ENCODING)
            return _error(
                HTTP_UNSUPPORTED_MEDIA, "invalid_request_error", "content-encoding not supported"
            )
        body = await _read_body(request)
        if isinstance(body, Response):
            return body
        try:
            found = await _scan(body, rest, request.url.query, upstream.allow_account_email)
        except BodyTooLargeError:
            # Страховка: детектор получил тот же предел, но непроверенное тело не пропускаем
            mark_denied(request.scope, CODE_BODY_TOO_LARGE)
            return _error(HTTP_TOO_LARGE, "request_too_large", "request body too large")
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

        if found:
            types = sorted(found)
            # Код - только имена категорий (phone, email, inn, ...), без значений
            code = "+".join(types)
            if guard_mode is GuardMode.LOG:
                mark_observed(request.scope, code)
            else:
                mark_denied(request.scope, code)
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
        request: Request, upstream: Upstream, rest: str, body: bytes, slot: _Slot
    ) -> Response:
        """Пересылает проверенное тело в апстрим как есть и отдаёт ответ потоком."""
        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in SKIP_REQUEST_HEADERS
        }
        url = httpx.URL(upstream.base_url + rest, query=request.url.query.encode())
        try:
            upstream_req = client.build_request(
                request.method, url, headers=headers, content=body
            )
            sent = await _send_unless_disconnected(request, client, upstream_req)
        except Exception as exc:  # noqa: BLE001 - fail closed
            mark_failed(request.scope, CODE_UPSTREAM_FAILURE, exc)
            return _error(HTTP_BAD_GATEWAY, "api_error", "upstream unavailable")
        if sent is None:
            mark_denied(request.scope, CODE_CLIENT_DISCONNECTED)
            return Response(status_code=HTTP_CLIENT_CLOSED)
        response = sent

        async def body_iter() -> AsyncIterator[bytes]:
            """Отдаёт ответ апстрима кусками, не накапливая (SSE идёт без задержки)."""
            try:
                async for part in response.aiter_raw():
                    yield part
            finally:
                await response.aclose()

        resp_headers = {
            k: v for k, v in response.headers.items() if k.lower() not in SKIP_RESPONSE_HEADERS
        }
        # aiter_raw отдаёт байты как есть, поэтому content-encoding оставляем
        if "content-encoding" in response.headers:
            resp_headers["content-encoding"] = response.headers["content-encoding"]
        return _SlotStreamingResponse(
            body_iter(), status_code=response.status_code, headers=resp_headers, slot=slot
        )

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
