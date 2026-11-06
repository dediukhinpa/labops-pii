"""Прокси-фильтр ПДн между nginx и LiteLLM.

Тело запроса читается целиком (иначе его нельзя проверить), ответ апстрима отдаётся
потоком без буферизации. Режим fail closed: любая ошибка проверки или апстрима
приводит к отказу, запрос в LiteLLM без проверки не уходит. Тела запросов и ответов
не логируются: только путь, размер, типы находок и код. Журнал - JSON-строки (jsonlog.py).
"""

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response

from labops_pii.errors import ConfigError, reject_legacy_profile
from labops_pii.guard.address import ADDRESS_MODE_ENV, parse_address_mode
from labops_pii.guard.detector import BodyNotJsonError, BodyTooLargeError
from labops_pii.guard.litellm.jsonlog import (
    EVENT_PII_OBSERVED,
    EVENT_SERVICE_STARTED,
    EVENT_VISION_IMAGES,
    EVENT_WEBPAGE_REQUEST,
    JsonLogMiddleware,
    configure_logging,
    known_route,
    log_event,
    mark_denied,
    mark_failed,
    parse_request_id,
)
from labops_pii.guard.litellm.search_route import (
    REASON_NOT_JSON,
    REASON_SIZE,
    SEARCH_ALLOWED_MODELS_ENV,
    SEARCH_CONTINUATION_MAX_BODY_BYTES,
    SEARCH_ENABLED_ENV,
    SEARCH_FORM_CODE,
    SEARCH_ROUTE_PATH,
    SEARCH_UPSTREAM_PATH,
    check_search_form,
    is_search_namespace,
    parse_allowed_models,
)
from labops_pii.guard.litellm.vision_route import (
    REASON_PII,
    VISION_ALLOWED_MODELS_ENV,
    VISION_ENABLED_ENV,
    VISION_FORM_CODE,
    VISION_ROUTE_PATH,
    VISION_UPSTREAM_PATH,
    VisionLimits,
    check_vision_head,
    check_vision_request,
    is_vision_namespace,
    parse_vision_models,
)
from labops_pii.guard.litellm.webpage_route import (
    WEBPAGE_ALLOWED_MODELS_ENV,
    WEBPAGE_ENABLED_ENV,
    WEBPAGE_FORM_CODE,
    WEBPAGE_MAX_BODY_BYTES,
    WEBPAGE_ROUTE_PATH,
    WEBPAGE_UPSTREAM_PATH,
    check_webpage_head,
    check_webpage_request,
    is_webpage_namespace,
    parse_webpage_models,
)
from labops_pii.guard.metrics import METRICS
from labops_pii.guard.names import NAMES_MODE_ENV, parse_names_mode
from labops_pii.guard.policy import Findings, split_findings
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

UPSTREAM_URL_ENV = "UPSTREAM_URL"
DEFAULT_UPSTREAM = "http://litellm:4000"
HTTP_PII = 422
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_UNSUPPORTED_MEDIA = 415
HTTP_TOO_LARGE = 413
HTTP_GUARD_FAILURE = 503
HTTP_BAD_GATEWAY = 502
# Нестандартный код nginx «клиент закрыл соединение»: в журнале отличает отмену от сбоя.
HTTP_CLIENT_CLOSED = 499
# Коды причин отказа для журнала (категории ПДн берутся из detector, значения - никогда)
CODE_SEARCH_NAMESPACE = "search_namespace"
CODE_SEARCH_DISABLED = "search_disabled"
CODE_VISION_NAMESPACE = "vision_namespace"
CODE_VISION_DISABLED = "vision_disabled"
CODE_WEBPAGE_NAMESPACE = "webpage_namespace"
CODE_WEBPAGE_DISABLED = "webpage_disabled"
CODE_GUARD_BUSY = "guard_busy"
CODE_CONTENT_ENCODING = "content_encoding"
CODE_BODY_TOO_LARGE = "body_too_large"
CODE_BODY_NOT_JSON = "body_not_json"
CODE_SCAN_FAILURE = "scan_failure"
CODE_UPSTREAM_FAILURE = "upstream_failure"
CODE_CLIENT_DISCONNECTED = "client_disconnected"
# Предел запросов в полёте (R5-PY-8). Слот занят от чтения тела до конца отдачи ответа: всё
# это время тело (до 8 МиБ) живёт в памяти, а у запроса к апстриму оно же в `response.request`.
# Бюджет под mem_limit 1g: интерпретатор ~60 МБ + пул проверки 4 x ~105 МБ пика скана
# + 16 запросов x ~16 МБ (тело и копия при join) = ~740 МБ, запас на всплески.
MAX_INFLIGHT_REQUESTS = 16
# Сколько запрос ждёт свободный слот, прежде чем получить 503. Тело к этому моменту не
# читается, поэтому очередь памяти не копит.
SLOT_WAIT_SECONDS = 15.0
HTTP_BUSY = 503
RETRY_AFTER_SECONDS = 5
HTTP_TOO_MANY_REQUESTS = 429
CODE_VISION_BUSY = "vision_busy"
# Подсказка клиенту, когда повторить после отказа по очереди зрения
VISION_RETRY_AFTER_SECONDS = 10

# Заголовки, которые не пересылаются дальше (hop-by-hop и пересчитываемые)
# Заголовки, которые на маршруте поиска не пробрасываются (beta-функции апстрима там не нужны)
SEARCH_DROP_HEADERS = frozenset({"anthropic-beta"})
# На маршруте зрения beta-заголовки тоже не нужны и не пробрасываются
VISION_DROP_HEADERS = frozenset({"anthropic-beta"})
# И на маршруте страниц сайтов beta-заголовки не нужны
WEBPAGE_DROP_HEADERS = frozenset({"anthropic-beta"})
def create_app(
    upstream_url: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    max_inflight: int = MAX_INFLIGHT_REQUESTS,
    slot_wait_seconds: float = SLOT_WAIT_SECONDS,
    search_enabled: bool | None = None,
    vision_enabled: bool | None = None,
    vision_limits: VisionLimits | None = None,
    webpage_enabled: bool | None = None,
) -> FastAPI:
    """Создаёт приложение.

    Args:
        upstream_url: Адрес LiteLLM. По умолчанию из переменной UPSTREAM_URL.
        transport: Транспорт httpx (для тестов).
        max_inflight: Предел одновременно обрабатываемых запросов (память под тела).
        slot_wait_seconds: Сколько запрос ждёт слот до ответа 503.
        search_enabled: Включён ли маршрут поиска. По умолчанию из SEARCH_ROUTE_ENABLED
            (выключен, пока переменная не равна "1").
        vision_enabled: Включён ли маршрут зрения. По умолчанию из VISION_ROUTE_ENABLED
            (выключен, пока переменная не равна "1").
        vision_limits: Пределы маршрута зрения. По умолчанию из окружения (VISION_MAX_*).
        webpage_enabled: Включён ли маршрут страниц сайтов. По умолчанию из
            WEBPAGE_ROUTE_ENABLED (выключен, пока переменная не равна "1").

    Returns:
        Приложение FastAPI.

    Raises:
        ValueError: Недопустимое значение MAX_BODY_BYTES, VISION_MAX_* или
            PII_GUARD_NAMES_MODE или PII_GUARD_ADDRESS_MODE.
        ConfigError: Задана прежняя LABOPS_PII_PROFILE или маршрут поиска включён без
            SEARCH_ALLOWED_MODELS.
    """
    reject_legacy_profile()
    base = (upstream_url or os.environ.get(UPSTREAM_URL_ENV, DEFAULT_UPSTREAM)).rstrip("/")
    max_body = max_body_bytes()
    # Неизвестный режим ФИО - ошибка старта, а не тихое отключение защиты (см. parse_names_mode)
    parse_names_mode(os.environ.get(NAMES_MODE_ENV))
    # То же для режима адресов (parse_address_mode)
    parse_address_mode(os.environ.get(ADDRESS_MODE_ENV))
    client = upstream_client(transport, base)
    scan_pool = ThreadPoolExecutor(max_workers=SCAN_WORKERS, thread_name_prefix="pii-scan")
    inflight = asyncio.Semaphore(max_inflight)
    if search_enabled is None:
        search_enabled = os.environ.get(SEARCH_ENABLED_ENV, "0").strip() == "1"
    allowed_models = parse_allowed_models(os.environ.get(SEARCH_ALLOWED_MODELS_ENV))
    # Включённый маршрут поиска без списка моделей пропускал бы любую модель (fail open):
    # такой конфиг - ошибка старта, а не молчаливое снятие ограничения
    if search_enabled and allowed_models is None:
        raise ConfigError(
            f"{SEARCH_ENABLED_ENV}=1 требует {SEARCH_ALLOWED_MODELS_ENV} (список моделей через "
            "запятую): без него маршрут поиска не ограничивал бы модель"
        )
    if vision_enabled is None:
        vision_enabled = os.environ.get(VISION_ENABLED_ENV, "0").strip() == "1"
    limits = vision_limits or VisionLimits.from_env()
    vision_models = parse_vision_models(os.environ.get(VISION_ALLOWED_MODELS_ENV))
    if webpage_enabled is None:
        webpage_enabled = os.environ.get(WEBPAGE_ENABLED_ENV, "0").strip() == "1"
    webpage_models = parse_webpage_models(os.environ.get(WEBPAGE_ALLOWED_MODELS_ENV))
    # Отдельный семафор маршрута зрения: тела до 16 МиБ дороже обычных, mem_limit не растёт
    vision_slots = asyncio.Semaphore(limits.max_concurrent)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        """Закрывает пул соединений при остановке."""
        log_event(logger, EVENT_SERVICE_STARTED)
        yield
        scan_pool.shutdown(wait=False, cancel_futures=True)
        await client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    # Внешний слой: пишет одну JSON-строку на запрос (тело не читает)
    app.add_middleware(JsonLogMiddleware)

    def _record_findings(request: Request, findings: Findings) -> None:
        """Метрика находок и запись о наблюдаемых типах (log_only); значений ПДн здесь нет."""
        METRICS.record_findings(findings.blocking | findings.observed)
        if findings.observed:
            log_event(
                logger, EVENT_PII_OBSERVED, request_id=_request_id(request),
                route=known_route(request.url.path), pii_types=sorted(findings.observed),
            )

    def _pii_denied(request: Request, findings: Findings) -> Response:
        """Отказ по ПДн: код отказа и метрика - только имена типов."""
        types = sorted(findings.blocking)
        METRICS.record_denied(types)
        mark_denied(request.scope, "+".join(types))
        return _error(
            HTTP_PII,
            "invalid_request_error",
            "request contains personal data: " + ", ".join(types),
            pii_types=types,
        )

    @app.get("/_guard/metrics")
    async def metrics() -> Response:
        """Счётчики срабатываний по типам (внутренняя сеть; наружу nginx этот путь не отдаёт)."""
        return Response(METRICS.render(), media_type="text/plain; version=0.0.4")

    @app.get("/_guard/healthz")
    async def healthz() -> dict[str, str]:
        """Проверка живости самого фильтра (до апстрима не ходит)."""
        return {"status": "ok"}

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def proxy(path: str, request: Request) -> Response:
        """Берёт слот запроса в полёте и проксирует запрос; при перегрузке отвечает 503."""
        raw = request.scope.get("raw_path")
        raw_path = raw.decode("latin-1") if isinstance(raw, bytes) else request.url.path
        is_search = False
        is_vision = False
        is_webpage = False
        if is_search_namespace(request.url.path) or is_search_namespace(raw_path):
            # Всё под /search/, кроме точного маршрута, закрыто до чтения тела: обойти
            # фильтр ПДн основного маршрута через это пространство нельзя.
            exact = raw_path == SEARCH_ROUTE_PATH and request.url.path == SEARCH_ROUTE_PATH
            if not exact:
                mark_denied(request.scope, CODE_SEARCH_NAMESPACE)
                return _error(
                    HTTP_FORBIDDEN, "permission_error", "forbidden", code=SEARCH_FORM_CODE
                )
            if not search_enabled:
                mark_denied(request.scope, CODE_SEARCH_DISABLED)
                return _error(HTTP_NOT_FOUND, "not_found_error", "not found")
            is_search = True
        elif is_vision_namespace(request.url.path) or is_vision_namespace(raw_path):
            # То же для /vision/: обойти фильтр ПДн основного маршрута через пространство
            # нельзя, а картинки допустимы только на точном маршруте.
            exact = raw_path == VISION_ROUTE_PATH and request.url.path == VISION_ROUTE_PATH
            if not exact:
                mark_denied(request.scope, CODE_VISION_NAMESPACE)
                return _error(
                    HTTP_FORBIDDEN, "permission_error", "forbidden", code=VISION_FORM_CODE
                )
            if not vision_enabled:
                mark_denied(request.scope, CODE_VISION_DISABLED)
                return _error(HTTP_NOT_FOUND, "not_found_error", "not found")
            is_vision = True
            # Слот зрения берётся ДО общего слота и до чтения тела: ожидающие не занимают
            # общие слоты и не копят тела в памяти.
            try:
                await asyncio.wait_for(
                    vision_slots.acquire(), timeout=limits.queue_timeout_seconds
                )
            except TimeoutError:
                mark_denied(request.scope, CODE_VISION_BUSY)
                busy = _error(
                    HTTP_TOO_MANY_REQUESTS,
                    "rate_limit_error",
                    "vision route is busy, retry later",
                    code=CODE_VISION_BUSY,
                )
                busy.headers["retry-after"] = str(VISION_RETRY_AFTER_SECONDS)
                return busy
        elif is_webpage_namespace(request.url.path) or is_webpage_namespace(raw_path):
            # То же для /webpage/: обойти фильтр ПДн основного маршрута через пространство
            # нельзя, а ослабленная проверка действует только на точном маршруте.
            exact = raw_path == WEBPAGE_ROUTE_PATH and request.url.path == WEBPAGE_ROUTE_PATH
            if not exact:
                mark_denied(request.scope, CODE_WEBPAGE_NAMESPACE)
                return _error(
                    HTTP_FORBIDDEN, "permission_error", "forbidden", code=WEBPAGE_FORM_CODE
                )
            if not webpage_enabled:
                mark_denied(request.scope, CODE_WEBPAGE_DISABLED)
                return _error(HTTP_NOT_FOUND, "not_found_error", "not found")
            is_webpage = True
        try:
            await asyncio.wait_for(inflight.acquire(), timeout=slot_wait_seconds)
        except BaseException as exc:
            # Отмена или таймаут общего слота: слот зрения не должен утечь
            if is_vision:
                vision_slots.release()
            if not isinstance(exc, TimeoutError):
                raise
            mark_denied(request.scope, CODE_GUARD_BUSY)
            response = _error(
                HTTP_BUSY, "overloaded_error", "pii guard is busy, retry later", code="guard_busy"
            )
            response.headers["retry-after"] = str(RETRY_AFTER_SECONDS)
            return response
        slot = Slot(inflight, vision_slots) if is_vision else Slot(inflight)
        try:
            if is_search:
                response = await _handle_search(request, slot)
            elif is_vision:
                response = await _handle_vision(request, slot)
            elif is_webpage:
                response = await _handle_webpage(request, slot)
            else:
                response = await _handle(path, request, slot)
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

    async def _handle(path: str, request: Request, slot: Slot) -> Response:
        """Проверяет тело на ПДн и проксирует запрос в LiteLLM."""
        if not has_identity_encoding(request):
            # Сжатое тело не прочитать, а пропустить непроверенным нельзя
            mark_denied(request.scope, CODE_CONTENT_ENCODING)
            return _error(
                HTTP_UNSUPPORTED_MEDIA, "invalid_request_error", "content-encoding not supported"
            )
        # Куски тела живут только внутри read_body: вторая копия не держится всё время
        # ожидания апстрима (до 600 с)
        body = await read_body(request, max_body)
        if body is None:
            return _too_large(request)
        try:
            found = await scan_request(scan_pool, body, path, request.url.query, max_body)
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
            return _error(HTTP_GUARD_FAILURE, "api_error", "pii guard failure")

        # ФИО и адрес в log_only только наблюдаются (журнал и метрика), в enforce блокирует как
        # телефон
        findings = split_findings(found)
        _record_findings(request, findings)
        if findings.blocking:
            return _pii_denied(request, findings)

        return await _forward(request, "/" + path, request.url.query, body, slot)

    async def _handle_search(request: Request, slot: Slot) -> Response:
        """Проверяет форму запроса поиска (не ПДн) и пересылает его в /v1/messages."""
        encoding = request.headers.get("content-encoding", "")
        limit = SEARCH_CONTINUATION_MAX_BODY_BYTES
        reason = check_search_form(request.method, request.url.query, encoding, b"")
        # Пустое тело даёт REASON_NOT_JSON; отказ по методу, query и кодированию - сразу.
        if reason not in (None, REASON_NOT_JSON):
            return _search_reject(request, reason)
        body = await read_body(request, limit)
        if body is None:
            return _search_reject(request, REASON_SIZE)
        reason = check_search_form(
            request.method, request.url.query, encoding, body, allowed_models
        )
        if reason is not None:
            return _search_reject(request, reason)
        return await _forward(
            request, SEARCH_UPSTREAM_PATH, "", body, slot, SEARCH_DROP_HEADERS,
        )

    async def _handle_vision(request: Request, slot: Slot) -> Response:
        """Проверяет запрос с картинками (форма, base64, размеры, ПДн в тексте), шлёт в LiteLLM."""
        encoding = request.headers.get("content-encoding", "")
        reason = check_vision_head(request.method, request.url.query, encoding)
        if reason is not None:
            return _vision_reject(request, reason)
        body = await read_body(request, limits.max_body_bytes)
        if body is None:
            return _vision_reject(request, REASON_SIZE)
        loop = asyncio.get_running_loop()
        try:
            # Разбор JSON и декодирование base64 - в пуле потоков, чтобы не держать цикл событий
            verdict = await loop.run_in_executor(
                scan_pool, check_vision_request, request.method, request.url.query,
                encoding, body, limits, vision_models,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed на любой сбой проверки
            mark_failed(request.scope, CODE_SCAN_FAILURE, exc)
            return _error(HTTP_GUARD_FAILURE, "api_error", "pii guard failure")
        # Находки уже разделены проверкой (pii_types - блокирующие, observed_types - наблюдаемые)
        _record_findings(request, Findings(verdict.pii_types, verdict.observed_types))
        if verdict.reason == REASON_PII:
            return _pii_denied(request, Findings(verdict.pii_types, verdict.observed_types))
        if verdict.reason is not None:
            return _vision_reject(request, verdict.reason)
        # Только mime, размер, размеры и префикс sha256: содержимое картинок в журнал не идёт
        log_event(
            logger, EVENT_VISION_IMAGES, request_id=_request_id(request),
            route=VISION_ROUTE_PATH, images=[m.log_text() for m in verdict.images],
        )
        return await _forward(
            request, VISION_UPSTREAM_PATH, "", body, slot, VISION_DROP_HEADERS,
        )

    async def _handle_webpage(request: Request, slot: Slot) -> Response:
        """Проверяет запрос со страницей сайта (форма, ПДн кроме phone/email), шлёт в LiteLLM."""
        encoding = request.headers.get("content-encoding", "")
        reason = check_webpage_head(request.method, request.url.query, encoding)
        if reason is not None:
            return _webpage_reject(request, reason)
        body = await read_body(request, WEBPAGE_MAX_BODY_BYTES)
        if body is None:
            return _webpage_reject(request, REASON_SIZE)
        loop = asyncio.get_running_loop()
        try:
            verdict = await loop.run_in_executor(
                scan_pool, check_webpage_request, request.method, request.url.query,
                encoding, body, webpage_models,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed на любой сбой проверки
            mark_failed(request.scope, CODE_SCAN_FAILURE, exc)
            return _error(HTTP_GUARD_FAILURE, "api_error", "pii guard failure")
        if verdict.reason is not None:
            return _webpage_reject(request, verdict.reason)
        # Маршрут страниц никогда не блокирует по ПДн (решение 28.10), в том числе по ФИО даже в
        # enforce: директор на странице поставщика - общедоступные данные. В метрику срабатываний
        # эти находки не идут: иначе страницы поставщиков забили бы сигнал о ПДн от пользователей.
        # В журнал - отметка маршрута и имена видов найденных ПДн, без содержимого
        log_event(
            logger, EVENT_WEBPAGE_REQUEST, request_id=_request_id(request),
            route=WEBPAGE_ROUTE_PATH, pii_types=sorted(verdict.pii_types),
        )
        return await _forward(
            request, WEBPAGE_UPSTREAM_PATH, "", body, slot, WEBPAGE_DROP_HEADERS,
        )

    def _webpage_reject(request: Request, reason: str) -> Response:
        """Отказ маршруту страниц: в журнал только код причины из закрытого списка."""
        mark_denied(request.scope, f"{WEBPAGE_FORM_CODE}.{reason}")
        return _error(
            HTTP_FORBIDDEN,
            "permission_error",
            "webpage request not allowed: " + reason,
            code=WEBPAGE_FORM_CODE,
        )

    def _request_id(request: Request) -> str | None:
        """Проверенный идентификатор запроса из заголовка (тот же разбор, что в журнале)."""
        return parse_request_id(request.headers.get("x-request-id"))

    def _vision_reject(request: Request, reason: str) -> Response:
        """Отказ маршруту зрения: в журнал только код причины из закрытого списка."""
        mark_denied(request.scope, f"{VISION_FORM_CODE}.{reason}")
        return _error(
            HTTP_FORBIDDEN,
            "permission_error",
            "vision request not allowed: " + reason,
            code=VISION_FORM_CODE,
        )

    def _search_reject(request: Request, reason: str) -> Response:
        """Отказ маршруту поиска: в журнал только код причины из закрытого списка."""
        mark_denied(request.scope, f"{SEARCH_FORM_CODE}.{reason}")
        return _error(
            HTTP_FORBIDDEN,
            "permission_error",
            "search request form not allowed: " + reason,
            code=SEARCH_FORM_CODE,
        )

    async def _forward(
        request: Request,
        upstream_path: str,
        query: str,
        body: bytes,
        slot: Slot,
        drop_headers: frozenset[str] = frozenset(),
    ) -> Response:
        """Пересылает проверенное тело в LiteLLM и отдаёт ответ потоком."""
        url = httpx.URL(path=upstream_path, query=query.encode())
        try:
            upstream_req = client.build_request(
                request.method, url, headers=forward_headers(request, drop_headers), content=body
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


_configure_logging()
app = create_app()
