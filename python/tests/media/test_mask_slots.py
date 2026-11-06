"""media-masker: ожидание слота ограничено (503), пустой токен - ошибка старта.

Tesseract не нужен: проверка готовности OCR и сама маска подменены.
"""

from __future__ import annotations

import asyncio
import base64
import time

import httpx
import pytest

pytest.importorskip("cv2")

from labops_pii.media.mask import api  # noqa: E402
from labops_pii.media.mask.config import ConfigError, Settings  # noqa: E402
from labops_pii.media.mask.imaging import ImageMasker  # noqa: E402
from labops_pii.media.mask.ocr import TesseractOcr  # noqa: E402

TOKEN = "slot-test-token"
HOLD_SECONDS = 0.5
WAIT_SECONDS = 0.1


def _app(monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.setattr(TesseractOcr, "check_ready", lambda self: None)

    def slow_mask(self: ImageMasker, data: bytes) -> object:
        time.sleep(HOLD_SECONDS)
        raise api.MediaRefusedError(api.HTTP_UNPROCESSABLE, "test_done")

    monkeypatch.setattr(ImageMasker, "mask_bytes", slow_mask)
    monkeypatch.setattr(api, "SLOT_WAIT_SECONDS", WAIT_SECONDS)
    return api.create_app(Settings(api_token=TOKEN, max_concurrency=1))


async def test_waiting_for_slot_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(monkeypatch)
    body = {"media_type": "image/png", "data": base64.b64encode(b"x").decode()}
    headers = {"Authorization": f"Bearer {TOKEN}"}
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://m") as client:
        replies = await asyncio.gather(
            *(client.post("/mask_image", json=body, headers=headers) for _ in range(4))
        )
    codes = sorted(r.status_code for r in replies)
    # Один занял слот, остальные не ждут дольше предела: ответ 503, а не бесконечная очередь
    assert codes.count(api.HTTP_BUSY) >= 1
    assert api.HTTP_UNPROCESSABLE in codes


@pytest.mark.parametrize("token", ["", "   "])
def test_empty_token_refuses_to_start(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    monkeypatch.setattr(TesseractOcr, "check_ready", lambda self: None)
    with pytest.raises(ConfigError):
        api.create_app(Settings(api_token=token))
