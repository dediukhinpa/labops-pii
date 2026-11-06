"""HTTP API сервиса псевдонимизации (FastAPI)."""

from __future__ import annotations

import hmac
import logging
import threading
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from labops_pii.body_guard import BodyGuardMiddleware
from labops_pii.config import (
    BATCH_ITEM_COST_CHARS,
    STORE_SQLITE,
    ConfigError,
    Settings,
    load_settings,
    max_body_bytes,
)
from labops_pii.detector import PiiDetector
from labops_pii.errors import reject_legacy_profile
from labops_pii.inflect import signatory_genitive
from labops_pii.jsonlog import (
    EVENT_RESTORE_FAILED,
    EVENT_SERVICE_STARTED,
    EVENT_SERVICE_STOPPED,
    JsonLogMiddleware,
    log_event,
)
from labops_pii.service import Pseudonymizer, TooManyTokensError
from labops_pii.store import (
    SECONDS_PER_HOUR,
    MemoryReplacementStore,
    ReplacementStore,
    SqliteReplacementStore,
    resolve_key_scheme,
)

logger = logging.getLogger(__name__)

HTTP_UNAUTHORIZED = 401
HTTP_NO_CONTENT = 204
# Пачка /pseudonymize_batch сверх пределов (число текстов или их суммарная длина): клиент
# может разрезать её мельче или перейти на одиночные вызовы. Отдельно от 422, который
# значит «этот текст слишком длинный» и одиночным вызовом тоже не пройдёт.
HTTP_TOO_LARGE = 413
HTTP_UNPROCESSABLE = 422
HTTP_BUSY = 503
BEARER_SCHEME = "bearer"
# Пути с телом JSON: токен и размер тела проверяются в BodyGuardMiddleware до его чтения
GUARDED_PATHS = ("/pseudonymize", "/pseudonymize_batch", "/restore", "/check")
# Подписант (ENABLE_INFLECT_SIGNATORY): должность и ФИО в родительном падеже без участия модели
SIGNATORY_ROUTE = "/inflect_signatory"
# Должность и ФИО - короткие строки; длиннее - явно не подписант
MAX_SIGNATORY_FIELD_CHARS = 200
# DELETE-маршруты с токеном (тела нет): очистка треда по концу сессии клиента
GUARDED_DELETE_PREFIXES = ("/threads/",)
# Номер запуска процесса: клиент по его смене узнаёт, что таблица замен в памяти потеряна.
# Не секрет, но и не предсказуем; новый на каждый запуск.
BOOT_ID = str(uuid.uuid4())
# Как часто проверять ретенцию таблицы замен во время работы (при старте проверяется всегда).
# SQLite: срок задан в часах, проверка не реже раза в час. Память: тред дешёвый для обхода,
# поэтому проверяем чаще, чтобы оригиналы не жили сверх срока.
SECONDS_PER_MINUTE = 60.0
SQLITE_RETENTION_CHECK_INTERVAL_SECONDS = 60 * SECONDS_PER_MINUTE
MEMORY_RETENTION_CHECK_INTERVAL_SECONDS = 10 * SECONDS_PER_MINUTE


def batch_cost_chars(texts: list[str]) -> int:
    """Длина пачки в «символах худшего текста»: сумма длин плюс цена каждого текста после первого.

    Ту же формулу применяет TS-клиент (`@labops/pii`), когда режет листья на пачки.
    """
    return sum(len(text) for text in texts) + BATCH_ITEM_COST_CHARS * max(len(texts) - 1, 0)


class PseudonymizeRequest(BaseModel):
    """Запрос на маскирование."""

    thread_id: str = Field(min_length=1)
    text: str


class SignatoryRequest(BaseModel):
    """Подписант в именительном падеже: должность и ФИО (настоящее, не токен)."""

    position: str = Field(min_length=1, max_length=MAX_SIGNATORY_FIELD_CHARS)
    full_name: str = Field(min_length=1, max_length=MAX_SIGNATORY_FIELD_CHARS)


class SignatoryResponse(BaseModel):
    """Должность и ФИО в родительном падеже; null - словарь не разобрал, спросить человека."""

    text: str | None


class MaskRequest(PseudonymizeRequest):
    """Запрос /pseudonymize: необязательные падежные метки у ФИО в косвенном падеже."""

    case_labels: bool = False


class EntityOut(BaseModel):
    """Сущность в ответе (без оригинала)."""

    type: str
    token: str


class PseudonymizeResponse(BaseModel):
    """Ответ маскирования."""

    text: str
    entities: list[EntityOut]


class PseudonymizeBatchRequest(BaseModel):
    """Запрос на маскирование пачки текстов одного треда (R9-A2-04)."""

    thread_id: str = Field(min_length=1)
    texts: list[str]
    case_labels: bool = False


class PseudonymizeBatchResponse(BaseModel):
    """Ответ пачки: по элементу на каждый текст запроса, в том же порядке."""

    items: list[PseudonymizeResponse]


class RestoreResponse(BaseModel):
    """Ответ восстановления."""

    text: str


class CheckRequest(BaseModel):
    """Запрос страховочной проверки.

    `thread_id` необязателен: с ним проверка учитывает леммы ФИО этого треда (R7-03).
    """

    text: str
    thread_id: str | None = Field(default=None, min_length=1)


class CheckResponse(BaseModel):
    """Ответ страховочной проверки."""

    has_pii: bool
    types: list[str]


class _RetentionGate:
    """Запускает удаление устаревших замен: при старте и не чаще раза в интервал далее.

    Отдельного потока нет: проверка вызывается из запроса /pseudonymize, дешёвое сравнение
    времени; сам запрос DELETE короткий (по индексированному thread_activity).
    """

    def __init__(self, store: ReplacementStore, retention_hours: int) -> None:
        self._store = store
        self._hours = retention_hours
        self._interval = (
            MEMORY_RETENTION_CHECK_INTERVAL_SECONDS
            if isinstance(store, MemoryReplacementStore)
            else SQLITE_RETENTION_CHECK_INTERVAL_SECONDS
        )
        self._last = 0.0
        self._lock = threading.Lock()

    def run_if_due(self, force: bool = False) -> None:
        """Удаляет просроченные треды, если пора; ошибка удаления запрос не ломает."""
        if self._hours <= 0:
            return
        now = time.monotonic()
        with self._lock:
            if not force and now - self._last < self._interval:
                return
            self._last = now
        try:
            removed = self._store.purge_idle(self._hours * SECONDS_PER_HOUR)
        except Exception:  # noqa: BLE001 - ретенция не должна валить обработку запроса
            logger.exception("retention purge failed")
            return
        if removed:
            logger.info("retention: removed %d expired thread(s)", removed)


# Маршрут восстановления: его сбой (5xx/исключение) - отдельное критичное событие
RESTORE_ROUTE = "/restore"


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Пишет события запуска и остановки сервиса."""
    log_event(logger, EVENT_SERVICE_STARTED)
    try:
        yield
    finally:
        log_event(logger, EVENT_SERVICE_STOPPED)


def create_app(
    settings: Settings | None = None,
    store: ReplacementStore | None = None,
) -> FastAPI:
    """Собирает приложение.

    Args:
        settings: Настройки; по умолчанию из окружения (нет ключа -> ConfigError).
        store: Хранилище; по умолчанию SQLite по пути из настроек.

    Raises:
        ConfigError: Не задан или невалиден PSEUDONYMIZER_KEY; не задан токен API.
    """
    reject_legacy_profile()
    settings = settings or load_settings()
    api_token = settings.api_token.strip()
    if not api_token:
        # Fail closed (R4-SEC-3): без секрета API не поднимается, тихого отката нет
        raise ConfigError("Не задан токен API (PSEUDONYMIZER_API_TOKEN): сервис не стартует")
    expected_token = api_token.encode()
    if store is None:
        store = (
            SqliteReplacementStore(
                settings.db_path, settings.key, key_scheme=resolve_key_scheme(settings.key_scheme)
            )
            if settings.store_backend == STORE_SQLITE
            else MemoryReplacementStore()
        )
    detector = PiiDetector(
        settings.mask_legal_entity_requisites,
        settings.contacts,
        mask_addresses=settings.mask_addresses,
    )
    service = Pseudonymizer(detector, store, settings.max_restore_tokens)
    slots = threading.BoundedSemaphore(settings.max_concurrency)
    retention = _RetentionGate(store, settings.retention_hours)
    retention.run_if_due(force=True)

    def token_valid(authorization: str) -> bool:
        """Значение заголовка Authorization - «Bearer <секрет>» с верным секретом."""
        scheme, _, supplied = authorization.partition(" ")
        # compare_digest по байтам: строка не-ASCII иначе вызвала бы TypeError (500)
        return scheme.lower() == BEARER_SCHEME and hmac.compare_digest(
            supplied.strip().encode("utf-8", "surrogateescape"), expected_token
        )

    def require_token(request: Request) -> None:
        """Повторная проверка токена на самом маршруте; 401 без верного Bearer.

        Основной отказ даёт BodyGuardMiddleware до чтения тела: сама зависимость FastAPI
        выполняется уже после `await request.json()`, то есть после разбора тела.
        """
        if not token_valid(request.headers.get("authorization", "")):
            logger.warning("request unauthorized: path=%s", request.url.path)
            raise HTTPException(
                status_code=HTTP_UNAUTHORIZED,
                detail="unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def limit_concurrency() -> Iterator[None]:
        """Пускает не больше max_concurrency запросов; остальным 503 после ожидания."""
        if not slots.acquire(timeout=settings.busy_timeout_seconds):
            logger.warning("request rejected: concurrency limit=%d", settings.max_concurrency)
            raise HTTPException(status_code=HTTP_BUSY, detail="service is busy, retry later")
        try:
            yield
        finally:
            slots.release()

    # Форма API задаётся флагами PSEUDONYMIZER_ENABLE_*; не включённые явно маршруты выключены
    guarded_paths = (*GUARDED_PATHS, SIGNATORY_ROUTE) if settings.enable_inflect_signatory else (
        GUARDED_PATHS
    )
    delete_prefixes = GUARDED_DELETE_PREFIXES if settings.enable_delete_threads else ()
    app = FastAPI(title="pseudonymizer", lifespan=_lifespan)
    # Токен и предел тела - до чтения тела (иначе тело на сотни МБ попадает в память).
    app.add_middleware(
        BodyGuardMiddleware,
        max_body_bytes=max_body_bytes(settings.max_text_chars, settings.max_batch_items),
        authorize=token_valid,
        guarded_paths=guarded_paths,
        guarded_delete_prefixes=delete_prefixes,
    )
    # Добавлен последним, значит внешний: логирует и отказы BodyGuard (401/413)
    app.add_middleware(JsonLogMiddleware, failure_events={RESTORE_ROUTE: EVENT_RESTORE_FAILED})

    def ensure_size(text: str) -> None:
        """Отказывает (422) на слишком длинном тексте; значение и фрагменты не возвращает."""
        if len(text) > settings.max_text_chars:
            logger.warning("text rejected: length=%d limit=%d", len(text), settings.max_text_chars)
            raise HTTPException(
                status_code=HTTP_UNPROCESSABLE,
                detail=f"text is too long: limit is {settings.max_text_chars} characters",
            )

    def ensure_batch_size(texts: list[str]) -> None:
        """Отказывает (413) на пачке сверх пределов, (422) на слишком длинном тексте.

        Проверка до обработки: отказ не оставляет в таблице ни одного токена пачки. Длина
        пачки с поправкой на постоянную цену текста (BATCH_ITEM_COST_CHARS за каждый текст,
        кроме первого) ограничена тем же пределом, что и один текст: пачка занимает один слот
        конкуренции, и худшее время её обработки то же, что у одного предельного текста.
        """
        cost = batch_cost_chars(texts)
        # Число текстов - до проверки каждого: пачку на миллион строк незачем перебирать.
        too_many = len(texts) > settings.max_batch_items
        if not too_many:
            for text in texts:
                ensure_size(text)
        if too_many or cost > settings.max_text_chars:
            logger.warning(
                "batch rejected: items=%d cost=%d limits=%d/%d",
                len(texts), cost, settings.max_batch_items, settings.max_text_chars,
            )
            raise HTTPException(
                status_code=HTTP_TOO_LARGE,
                detail=(
                    f"batch is too large: limits are {settings.max_batch_items} texts and "
                    f"{settings.max_text_chars} characters in total, each text after the "
                    f"first counts as {BATCH_ITEM_COST_CHARS} more"
                ),
            )

    guarded = [Depends(require_token), Depends(limit_concurrency)]

    @app.post(
        "/pseudonymize",
        dependencies=guarded,
        response_model=PseudonymizeResponse,
    )
    def pseudonymize(req: MaskRequest) -> PseudonymizeResponse:
        ensure_size(req.text)
        retention.run_if_due()
        text, entities = service.pseudonymize(
            req.thread_id, req.text, req.case_labels and settings.enable_case_labels
        )
        return PseudonymizeResponse(
            text=text, entities=[EntityOut(type=e.type, token=e.token) for e in entities]
        )

    @app.post(
        "/pseudonymize_batch",
        dependencies=guarded,
        response_model=PseudonymizeBatchResponse,
    )
    def pseudonymize_batch(req: PseudonymizeBatchRequest) -> PseudonymizeBatchResponse:
        # Пачка вместо сотен одиночных вызовов по листьям JSON результата инструмента: тот же
        # результат (порядок и номера токенов, см. Pseudonymizer.pseudonymize_batch), но один
        # HTTP-запрос и один слот конкуренции (R9-A2-04).
        ensure_batch_size(req.texts)
        retention.run_if_due()
        results = service.pseudonymize_batch(
            req.thread_id, req.texts, req.case_labels and settings.enable_case_labels
        )
        return PseudonymizeBatchResponse(
            items=[
                PseudonymizeResponse(
                    text=text, entities=[EntityOut(type=e.type, token=e.token) for e in entities]
                )
                for text, entities in results
            ]
        )

    @app.post(RESTORE_ROUTE, dependencies=guarded, response_model=RestoreResponse)
    def restore(req: PseudonymizeRequest) -> RestoreResponse:
        ensure_size(req.text)
        try:
            return RestoreResponse(text=service.restore(req.thread_id, req.text))
        except TooManyTokensError as exc:
            logger.warning("restore rejected: tokens limit=%d", exc.limit)
            raise HTTPException(
                status_code=HTTP_UNPROCESSABLE,
                detail=f"text has too many tokens: limit is {exc.limit}",
            ) from exc

    @app.post("/check", dependencies=guarded, response_model=CheckResponse)
    def check(req: CheckRequest) -> CheckResponse:
        ensure_size(req.text)
        types = service.check(req.text, req.thread_id)
        return CheckResponse(has_pii=bool(types), types=types)

    if settings.enable_delete_threads:

        @app.delete(
            # :path - идентификатор треда может содержать «/» (например, «agent/sess»), без
            # него такой DELETE давал 404 и замены треда не удалялись
            "/threads/{thread_id:path}",
            dependencies=[Depends(require_token)],
            status_code=HTTP_NO_CONTENT,
            response_class=Response,
        )
        def delete_thread(thread_id: str) -> Response:
            """Удаляет все замены треда; 204 и когда треда не было (идемпотентно)."""
            service.delete_thread(thread_id)
            return Response(status_code=HTTP_NO_CONTENT)

    if settings.enable_inflect_signatory:

        @app.post(SIGNATORY_ROUTE, dependencies=guarded, response_model=SignatoryResponse)
        def inflect_signatory(req: SignatoryRequest) -> SignatoryResponse:
            # Склонение здесь, а не в модели: модель видит ФИО токеном (см. inflect.py)
            return SignatoryResponse(text=signatory_genitive(req.position, req.full_name))

    @app.get("/health")
    def health() -> dict[str, str]:
        if settings.enable_expose_boot_id:
            return {"status": "ok", "boot_id": BOOT_ID}
        return {"status": "ok"}

    return app
