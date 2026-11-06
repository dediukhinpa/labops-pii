"""HTTP-обёртка gate: POST /images/detect-text (контракт сервиса documents потребителя).

Ответы: 200 `{"result": "no_text"|"text"|"not_recognized"}`; 415 формат не поддержан;
413 файл больше лимита; 422 заголовок повреждён; 503 с Retry-After — очередь переполнена.
Содержимое, имя файла и распознанный текст не логируются и не возвращаются.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from labops_pii.media.gate.detect import (
    RETRY_AFTER_SECONDS,
    OcrBusyError,
    OcrGate,
    OcrSettings,
    check_input,
    detect_text,
    load_ocr_settings,
)
from labops_pii.media.gate.normalize import (
    ImageCorruptError,
    ImageLimits,
    ImageTooLargeError,
    ImageUnsupportedError,
)

logger = logging.getLogger(__name__)

HTTP_TOO_LARGE = 413
HTTP_UNSUPPORTED = 415
HTTP_UNPROCESSABLE = 422
HTTP_UNAVAILABLE = 503
DETAIL_OCR_BUSY = "очередь распознавания переполнена, повторите позже"


@dataclass(frozen=True)
class GateSettings:
    """Настройки HTTP-обёртки gate.

    Attributes:
        image_limits: Лимиты картинок.
        ocr: Настройки детектора текста.
    """

    image_limits: ImageLimits = field(default_factory=ImageLimits)
    ocr: OcrSettings = field(default_factory=load_ocr_settings)


def create_app(settings: GateSettings | None = None) -> FastAPI:
    """Создаёт приложение gate."""
    cfg = settings or GateSettings()
    ocr_gate = OcrGate(cfg.ocr)
    app = FastAPI(title="labops-pii-media-gate")

    @app.post("/images/detect-text")
    async def detect_text_endpoint(file: UploadFile = File(...)) -> Response:
        """Есть ли на картинке текст (jpeg/png/webp)."""
        limits = cfg.image_limits
        try:
            data = await file.read(limits.max_input_bytes + 1)
        finally:
            await file.close()
        if len(data) > limits.max_input_bytes:
            raise HTTPException(HTTP_TOO_LARGE, "файл слишком большой")
        try:
            await run_in_threadpool(check_input, data, limits)
            async with ocr_gate.slot():
                result = await run_in_threadpool(detect_text, data, limits, cfg.ocr)
        except ImageUnsupportedError as exc:
            raise HTTPException(HTTP_UNSUPPORTED, str(exc)) from exc
        except ImageTooLargeError as exc:
            raise HTTPException(HTTP_TOO_LARGE, str(exc)) from exc
        except ImageCorruptError as exc:
            raise HTTPException(HTTP_UNPROCESSABLE, str(exc)) from exc
        except OcrBusyError as exc:
            raise HTTPException(
                HTTP_UNAVAILABLE, DETAIL_OCR_BUSY,
                headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
            ) from exc
        return JSONResponse({"result": result})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
