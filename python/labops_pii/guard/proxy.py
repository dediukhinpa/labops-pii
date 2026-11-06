"""Общая механика прокси-фильтров ПДн (guard.litellm и guard.edge).

Слот запроса в полёте, чтение тела с пределом, проверка тела и адреса в пуле потоков,
пересылка в апстрим с отменой при уходе клиента и потоковая отдача ответа. Решения о
маршрутах, режимах и формате журнала остаются в приложениях: здесь только то, что у обоих
шлюзов должно работать одинаково (раньше это жило двумя копиями и расходилось).
"""

import asyncio
import os
from collections.abc import AsyncIterator, Mapping
from concurrent.futures import Executor
from typing import Any
from urllib.parse import unquote, unquote_plus

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.types import Receive, Scope, Send

from labops_pii.guard.detector import DEFAULT_MAX_SCAN_BYTES, find_pii_types, scan_body

MAX_BODY_ENV = "MAX_BODY_BYTES"
# Единственный предел размера: он же передаётся детектору как предел сканирования.
DEFAULT_MAX_BODY = DEFAULT_MAX_SCAN_BYTES
UPSTREAM_TIMEOUT_ENV = "UPSTREAM_TIMEOUT_SECONDS"
DEFAULT_UPSTREAM_TIMEOUT = 600.0
CONNECT_TIMEOUT = 10.0
# Проверка идёт в отдельных потоках, чтобы не занимать цикл событий. Потоков немного:
# проверка грузит процессор, а очередь сверх этого только копит память под тела.
SCAN_WORKERS = 4
# Кодирование тела, при котором содержимое можно читать как есть
IDENTITY_ENCODINGS = frozenset({"", "identity"})
# Как часто проверять, не ушёл ли клиент, пока апстрим молчит (до первого заголовка).
DISCONNECT_POLL_SECONDS = 0.5

# Заголовки, которые не пересылаются дальше (hop-by-hop и пересчитываемые)
SKIP_REQUEST_HEADERS = frozenset(
    {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "te",
     "upgrade", "proxy-authorization", "proxy-authenticate", "trailer"}
)
SKIP_RESPONSE_HEADERS = frozenset(
    {"content-length", "connection", "keep-alive", "transfer-encoding", "te", "upgrade",
     "trailer", "content-encoding"}
)


def error_response(
    status: int,
    kind: str,
    message: str,
    headers: Mapping[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    """Формирует ошибку в формате API модели (type=error, error.type, error.message).

    Args:
        status: HTTP-код.
        kind: Тип ошибки API (error.type).
        message: Текст ошибки (без значений ПДн).
        headers: Дополнительные заголовки ответа.
        **extra: Поля верхнего уровня (code, pii_types и т. п.).

    Returns:
        JSON-ответ.
    """
    payload: dict[str, Any] = {
        "type": "error",
        "error": {"type": kind, "message": message},
    }
    payload.update(extra)
    return JSONResponse(status_code=status, content=payload, headers=dict(headers or {}))


class Slot:
    """Слот запроса в полёте: освобождается ровно один раз, с любой стороны.

    Держит один или несколько семафоров (общий слот и, например, слот маршрута зрения):
    все они живут ровно столько же, сколько запрос.
    """

    def __init__(self, *semaphores: asyncio.Semaphore) -> None:
        self._semaphores: list[asyncio.Semaphore] = list(semaphores)

    def release(self) -> None:
        """Возвращает слот (повторный вызов ничего не делает)."""
        semaphores, self._semaphores = self._semaphores, []
        for semaphore in semaphores:
            semaphore.release()


class SlotStreamingResponse(StreamingResponse):
    """Потоковый ответ, который держит слот до конца отдачи (в том числе при обрыве)."""

    def __init__(self, *args: Any, slot: Slot, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._slot = slot

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Отдаёт ответ и освобождает слот, даже если клиент оборвал соединение."""
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._slot.release()


def max_body_bytes() -> int:
    """Читает предел тела из MAX_BODY_BYTES.

    Returns:
        Предел в байтах.

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


def upstream_client(
    transport: httpx.AsyncBaseTransport | None, base_url: str = ""
) -> httpx.AsyncClient:
    """Клиент к апстриму с таймаутом из UPSTREAM_TIMEOUT_SECONDS.

    Args:
        transport: Транспорт httpx (для тестов).
        base_url: Базовый адрес апстрима; пусто - адрес задаётся в каждом запросе.

    Returns:
        Клиент httpx.
    """
    timeout = httpx.Timeout(
        float(os.environ.get(UPSTREAM_TIMEOUT_ENV, DEFAULT_UPSTREAM_TIMEOUT)),
        connect=CONNECT_TIMEOUT,
    )
    return httpx.AsyncClient(base_url=base_url, timeout=timeout, transport=transport)


def has_identity_encoding(request: Request) -> bool:
    """Можно ли читать тело как есть (сжатое не прочитать, а непроверенным не пропустить)."""
    encoding = request.headers.get("content-encoding", "").strip().lower()
    return encoding in IDENTITY_ENCODINGS


async def read_body(request: Request, limit: int) -> bytes | None:
    """Читает тело целиком, не принимая больше предела.

    Заявленная длина больше предела отклоняется до чтения; поток обрывается, как только
    принятое превысило предел, поэтому тело сверх него в памяти не копится.

    Args:
        request: Входящий запрос.
        limit: Предел тела в байтах.

    Returns:
        Тело или None, если оно больше предела.
    """
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        return None
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def scan_request(
    pool: Executor,
    body: bytes,
    path: str,
    query: str,
    max_body: int,
    allow_account_email: bool = False,
) -> set[str]:
    """Проверяет тело (должно быть JSON) и адрес запроса в пуле потоков.

    Адрес проверяется после раскодирования %-последовательностей, в том числе Unicode:
    ПДн в пути или в строке запроса так же недопустимы, как в теле.

    Args:
        pool: Пул потоков проверки.
        body: Тело запроса.
        path: Путь запроса (без раскодирования).
        query: Строка запроса (без раскодирования).
        max_body: Предел сканирования тела.
        allow_account_email: Не считать находкой почту учётной записи (см. detector).

    Returns:
        Типы найденных ПДн.

    Raises:
        BodyTooLargeError: Тело больше предела.
        BodyNotJsonError: Тело не JSON.
    """
    loop = asyncio.get_running_loop()
    found: set[str] = set()
    if body:
        found |= await loop.run_in_executor(
            pool, scan_body, body, max_body, True, allow_account_email
        )
    address = unquote(path) + "\n" + unquote_plus(query)
    found |= await loop.run_in_executor(pool, find_pii_types, address)
    return found


def forward_headers(request: Request, drop: frozenset[str] = frozenset()) -> dict[str, str]:
    """Заголовки запроса для апстрима: без hop-by-hop и без перечисленных в drop."""
    return {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in SKIP_REQUEST_HEADERS and k.lower() not in drop
    }


async def send_unless_disconnected(
    request: Request,
    client: httpx.AsyncClient,
    upstream_req: httpx.Request,
) -> httpx.Response | None:
    """Отправляет запрос в апстрим и отменяет его, если клиент ушёл раньше ответа.

    Без этого брошенный клиентом запрос (таймаут ядра, рубильник хода, отмена
    пользователем) продолжал бы исполняться у провайдера и тратить бюджет впустую.

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


def stream_upstream(response: httpx.Response, slot: Slot) -> SlotStreamingResponse:
    """Отдаёт открытый ответ апстрима потоком, не накапливая (SSE идёт без задержки).

    Args:
        response: Ответ апстрима с открытым потоком.
        slot: Слот запроса: освобождается после отдачи последнего куска.

    Returns:
        Потоковый ответ клиенту.
    """

    async def body_iter() -> AsyncIterator[bytes]:
        try:
            async for part in response.aiter_raw():
                yield part
        finally:
            await response.aclose()

    headers = {
        k: v for k, v in response.headers.items() if k.lower() not in SKIP_RESPONSE_HEADERS
    }
    # aiter_raw отдаёт байты как есть, поэтому content-encoding оставляем
    if "content-encoding" in response.headers:
        headers["content-encoding"] = response.headers["content-encoding"]
    return SlotStreamingResponse(
        body_iter(), status_code=response.status_code, headers=headers, slot=slot
    )
