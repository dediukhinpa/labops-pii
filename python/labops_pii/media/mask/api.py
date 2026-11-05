"""HTTP API сервиса маскирования (FastAPI)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from labops_pii.body_guard import BodyGuardMiddleware
from labops_pii.detector import PiiDetector
from labops_pii.media.mask.config import MAX_BODY_BYTES, MAX_FILE_BYTES, Settings
from labops_pii.media.mask.faces import FaceBlurrer
from labops_pii.media.mask.codes import CodeFinder
from labops_pii.media.mask.imaging import ImageMasker, MaskStats, MediaRefusedError, Recognized
from labops_pii.media.mask.jsonlog import (
    EVENT_MASK_DONE,
    EVENT_MASK_REFUSED,
    EVENT_SERVICE_STARTED,
    JsonLogMiddleware,
    log_event,
)
from labops_pii.media.mask.ocr import TesseractOcr
from labops_pii.media.mask.pdfdoc import DocumentResult, PdfProcessor

logger = logging.getLogger(__name__)

BEARER_SCHEME = "bearer"
GUARDED_PATHS = ("/mask_image", "/extract_document")
HTTP_TOO_LARGE = 413
HTTP_UNPROCESSABLE = 422
HTTP_INTERNAL = 500


class MediaRequest(BaseModel):
    """Файл в base64 (как source.data блока image/document в API модели)."""

    media_type: str
    data: str


class ImageOut(BaseModel):
    """Картинка в base64."""

    media_type: str
    data: str


class StatsOut(BaseModel):
    """Счётчики без значений."""

    words: int
    masked_boxes: int
    faces: int
    low_conf_boxes: int
    codes: int = 0
    unreadable_boxes: int = 0


class CodeOut(BaseModel):
    """Содержимое QR-кода или штрихкода (расшифровано локально)."""

    kind: Literal["qr", "barcode"]
    text: str


class RecognizedOut(BaseModel):
    """Распознанное на картинке: текст, коды, признак скрытого нераспознанного текста.

    Тексты отдаются как есть, со всеми ПДн: сервис локальный, ПДн в них заменяет прокси.
    """

    text: str = ""
    codes: list[CodeOut] = []
    hidden_text: bool = False


class MaskImageResponse(BaseModel):
    """Ответ /mask_image."""

    media_type: str
    data: str
    stats: StatsOut
    recognized: RecognizedOut = RecognizedOut()


class PageOut(BaseModel):
    """Страница PDF: либо text, либо image."""

    index: int
    text: str | None
    image: ImageOut | None
    recognized: RecognizedOut | None = None


class ExtractResponse(BaseModel):
    """Ответ /extract_document."""

    kind: Literal["text", "images", "mixed"]
    pages: list[PageOut]
    stats: StatsOut


def _stats_out(stats: MaskStats) -> StatsOut:
    return StatsOut(
        words=stats.words,
        masked_boxes=stats.masked_boxes,
        faces=stats.faces,
        low_conf_boxes=stats.low_conf_boxes,
        codes=stats.codes,
        unreadable_boxes=stats.unreadable_boxes,
    )


def _recognized_out(rec: Recognized) -> RecognizedOut:
    return RecognizedOut(
        text=rec.text,
        codes=[CodeOut(kind=c.kind, text=c.text) for c in rec.codes],  # type: ignore[arg-type]
        hidden_text=rec.hidden_text,
    )


def _decode_base64(data: str) -> bytes:
    """Строгий base64 с пределом размера."""
    # Грубая оценка до декодирования: не выделять память под заведомо большое
    if len(data) > MAX_BODY_BYTES:
        raise MediaRefusedError(HTTP_TOO_LARGE, "file_too_large")
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MediaRefusedError(HTTP_UNPROCESSABLE, "bad_base64") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise MediaRefusedError(HTTP_TOO_LARGE, "file_too_large")
    if not raw:
        raise MediaRefusedError(HTTP_UNPROCESSABLE, "empty_file")
    return raw


def _document_out(result: DocumentResult) -> ExtractResponse:
    pages = [
        PageOut(
            index=p.index,
            text=p.text,
            image=None if p.image is None else ImageOut(
                media_type=p.image.media_type,
                data=base64.b64encode(p.image.data).decode("ascii"),
            ),
            recognized=None if p.image is None else _recognized_out(p.recognized),
        )
        for p in result.pages
    ]
    return ExtractResponse(kind=result.kind, pages=pages, stats=_stats_out(result.stats))


def create_app(settings: Settings) -> FastAPI:
    """Собирает приложение: грузит детектор, проверяет Tesseract и каскады лиц.

    Raises:
        OcrError: Tesseract недоступен или нет языка (сервис не стартует).
        FaceError: Каскады лиц не загрузились.
    """
    ocr = TesseractOcr(
        settings.tesseract_cmd, settings.langs, settings.ocr_timeout_s, settings.tessdata
    )
    ocr.check_ready()
    detector = PiiDetector(
        settings.mask_legal_entity, settings.contacts, mask_addresses=settings.mask_addresses
    )
    masker = ImageMasker(
        ocr, detector, FaceBlurrer(), settings.hide_unreadable, CodeFinder()
    )
    pdf = PdfProcessor(masker, settings.max_pdf_pages)
    slots = asyncio.Semaphore(settings.max_concurrency)
    expected = settings.api_token.encode()

    def token_valid(authorization: str) -> bool:
        scheme, _, supplied = authorization.partition(" ")
        return scheme.lower() == BEARER_SCHEME and hmac.compare_digest(
            supplied.strip().encode("utf-8", "surrogateescape"), expected
        )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        log_event(logger, EVENT_SERVICE_STARTED)
        yield

    app = FastAPI(
        title="media-masker", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.add_middleware(
        BodyGuardMiddleware,
        max_body_bytes=MAX_BODY_BYTES,
        authorize=token_valid,
        guarded_paths=GUARDED_PATHS,
    )
    app.add_middleware(JsonLogMiddleware)

    def refused(route: str, exc: MediaRefusedError) -> JSONResponse:
        # В журнал только код причины, без содержимого
        log_event(logger, EVENT_MASK_REFUSED, logging.WARNING, route=route, code=exc.code)
        return JSONResponse({"error": exc.code}, status_code=exc.status)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mask_image", response_model=None)
    async def mask_image(req: MediaRequest) -> MaskImageResponse | JSONResponse:
        try:
            if not req.media_type.startswith("image/"):
                raise MediaRefusedError(HTTP_UNPROCESSABLE, "unsupported_media_type")
            raw = _decode_base64(req.data)
            async with slots:
                result = await run_in_threadpool(masker.mask_bytes, raw)
        except MediaRefusedError as exc:
            return refused("/mask_image", exc)
        s = result.stats
        log_event(
            logger, EVENT_MASK_DONE, route="/mask_image",
            words=s.words, masked_boxes=s.masked_boxes, faces=s.faces,
            codes=s.codes, unreadable_boxes=s.unreadable_boxes,
        )
        return MaskImageResponse(
            media_type=result.media_type,
            data=base64.b64encode(result.data).decode("ascii"),
            stats=_stats_out(s),
            recognized=_recognized_out(result.recognized),
        )

    @app.post("/extract_document", response_model=None)
    async def extract_document(req: MediaRequest) -> ExtractResponse | JSONResponse:
        try:
            if req.media_type != "application/pdf":
                raise MediaRefusedError(HTTP_UNPROCESSABLE, "unsupported_media_type")
            raw = _decode_base64(req.data)
            async with slots:
                result = await run_in_threadpool(pdf.process, raw)
        except MediaRefusedError as exc:
            return refused("/extract_document", exc)
        s = result.stats
        log_event(
            logger, EVENT_MASK_DONE, route="/extract_document", pages=len(result.pages),
            words=s.words, masked_boxes=s.masked_boxes, faces=s.faces,
        )
        return _document_out(result)

    @app.exception_handler(Exception)
    async def unexpected(_request: object, exc: Exception) -> JSONResponse:
        # Любой непредвиденный сбой = отказ; текст исключения может содержать данные
        log_event(logger, EVENT_MASK_REFUSED, logging.ERROR, code="internal",
                  exc_type=type(exc).__name__)
        return JSONResponse({"error": "internal"}, status_code=HTTP_INTERNAL)

    return app
