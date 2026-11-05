"""Общие фикстуры: синтетические изображения, PDF и приложение с настоящим Tesseract."""

from __future__ import annotations

import base64
import io
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont

from labops_pii.media.mask.api import create_app
from labops_pii.media.mask.config import DEFAULT_TESSERACT_CMD, Settings
from labops_pii.media.mask.faces import FaceBlurrer
from labops_pii.media.mask.imaging import ImageMasker
from labops_pii.media.mask.ocr import TesseractOcr

TOKEN = "test-token"
FONT_PATH = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
FONT_SIZE = 32
LINE_STEP = 70
TEXT_ORIGIN = (40, 40)
PAGE_SIZE = (1200, 500)

# Все значения вымышлены; ИНН с верной контрольной суммой, иначе детектор его не примет
PERSON_LINE = "ФИО: Иванов Пётр Сергеевич"
PHONE_LINE = "Телефон: +7 912 345-67-89"
INN_LINE = "ИНН 500100732259"
PII_LINES = (PERSON_LINE, PHONE_LINE, INN_LINE)
SAFE_LINES = ("Заявление на отпуск", "Отдел закупок, офис 12")
PII_FRAGMENTS = ("Иванов", "Сергеевич", "912", "345-67-89", "500100732259")


def tesseract_cmd() -> str:
    """Бинарь из MEDIA_MASKER_TESSERACT_CMD или из PATH."""
    return os.environ.get("MEDIA_MASKER_TESSERACT_CMD", DEFAULT_TESSERACT_CMD)


def make_text_image(lines: tuple[str, ...], size: tuple[int, int] = PAGE_SIZE) -> Image.Image:
    """Рисует строки чёрным по белому шрифтом DejaVu."""
    font = ImageFont.truetype(str(FONT_PATH), FONT_SIZE)
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((TEXT_ORIGIN[0], TEXT_ORIGIN[1] + i * LINE_STEP), line, font=font, fill="black")
    return img


def to_bytes(img: Image.Image, fmt: str = "PNG") -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.fixture(scope="session")
def ocr() -> TesseractOcr:
    if shutil.which(tesseract_cmd()) is None and not Path(tesseract_cmd()).exists():
        pytest.skip("tesseract не установлен (см. README, MEDIA_MASKER_TESSERACT_CMD)")
    engine = TesseractOcr(tesseract_cmd(), "rus+eng", 60.0, os.environ.get("TESSDATA_PREFIX"))
    engine.check_ready()
    return engine


@pytest.fixture(scope="session")
def masker(ocr: TesseractOcr) -> ImageMasker:
    from labops_pii.detector import PiiDetector

    return ImageMasker(ocr, PiiDetector(True), FaceBlurrer())


@pytest.fixture(scope="session")
def client(ocr: TesseractOcr) -> Iterator[TestClient]:
    settings = Settings(
        api_token=TOKEN,
        tesseract_cmd=tesseract_cmd(),
        tessdata=os.environ.get("TESSDATA_PREFIX"),
        max_pdf_pages=4,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture()
def auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}
