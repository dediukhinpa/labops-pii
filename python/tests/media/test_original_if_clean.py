"""Проверочный проход и режим «оригинал, если чисто»: детерминированные тесты на подставном OCR.

OCR и детектор подменены сценарием: на каждом вызове распознавания отдаётся заранее заданный
список слов. Так видно, сколько проходов сделано и какие прямоугольники закрашены, без
Tesseract. Настоящий Tesseract проверяется в конце файла (пропускается, если его нет).
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass

import numpy as np
import pytest
from PIL import Image

from labops_pii.media.mask.imaging import (
    FILL_COLOR, MAX_PASSES, ImageMasker, MediaRefusedError,
)
from labops_pii.media.mask.ocr import OcrWord
from tests.media.conftest import (
    PHONE_LINE, SAFE_LINES, b64, make_text_image, to_bytes,
)

SIZE = (2000, 400)  # длинная сторона = OCR_TARGET_SIDE: масштаб 1, координаты не пересчитываются
SECRET = "SECRETWORD"
LOW_CONF_VALUE = 10.0
HIGH_CONF_VALUE = 90.0
WORD_H = 30
PAD_LIMIT = 12  # поле закраски вокруг слова меньше этого


def word(text: str, left: int, top: int = 50, conf: float = HIGH_CONF_VALUE) -> OcrWord:
    """Слово 100x30 px в строке с ключом по top."""
    return OcrWord(text, left, top, 100, WORD_H, conf, (1, 1, top))


PII_A = word(f"{SECRET}A", 100)
PII_B = word(f"{SECRET}B", 400)
PII_C = word(f"{SECRET}C", 700)
SAFE = word("hello", 1000)
LOW = word("junk123", 1300, conf=LOW_CONF_VALUE)


@dataclass(frozen=True, slots=True)
class Hit:
    """Находка детектора (нужны только границы)."""

    start: int
    end: int


class ScriptedOcr:
    """OCR по сценарию: n-й вызов recognize отдаёт n-й список слов (последний повторяется)."""

    def __init__(self, passes: list[list[OcrWord]]) -> None:
        self._passes = passes
        self.calls = 0

    def detect_rotation(self, _gray: Image.Image) -> int:
        return 0

    def recognize(self, _gray: Image.Image, _scale: float = 1.0) -> list[OcrWord]:
        words = self._passes[min(self.calls, len(self._passes) - 1)]
        self.calls += 1
        return words


class SecretDetector:
    """Детектор: ПДн - любое слово, начинающееся с SECRETWORD."""

    def detect(self, text: str) -> list[Hit]:
        return [Hit(m.start(), m.end()) for m in re.finditer(rf"{SECRET}\w*", text)]


class NoFaces:
    """Лиц нет."""

    def find(self, _image: Image.Image) -> list[tuple[int, int, int, int]]:
        return []

    def pixelate(self, _image: Image.Image, _box: tuple[int, int, int, int]) -> None:
        raise AssertionError("pixelate не должен вызываться")


class ForbiddenFaces:
    """Лица в режиме «оригинал» проверяться не должны."""

    def find(self, _image: Image.Image) -> list[tuple[int, int, int, int]]:
        raise AssertionError("лица в этом режиме не проверяются")


class NoCodes:
    """Кодов нет."""

    def find(self, _image: Image.Image) -> list[object]:
        return []


class ForbiddenCodes:
    """QR-коды в режиме «оригинал» проверяться не должны."""

    def find(self, _image: Image.Image) -> list[object]:
        raise AssertionError("коды в этом режиме не проверяются")


def make_masker(
    passes: list[list[OcrWord]], strict_stubs: bool = False, paint_low_conf: bool = False
) -> tuple[ImageMasker, ScriptedOcr]:
    ocr = ScriptedOcr(passes)
    masker = ImageMasker(
        ocr,  # type: ignore[arg-type]
        SecretDetector(),  # type: ignore[arg-type]
        ForbiddenFaces() if strict_stubs else NoFaces(),  # type: ignore[arg-type]
        hide_unreadable=False,
        codes=ForbiddenCodes() if strict_stubs else NoCodes(),  # type: ignore[arg-type]
        paint_low_conf=paint_low_conf,
    )
    return masker, ocr


def blank() -> Image.Image:
    return Image.new("RGB", SIZE, "white")


def is_black(image: Image.Image, w: OcrWord) -> bool:
    """Центр слова закрашен."""
    return image.getpixel((w.left + w.width // 2, w.top + w.height // 2)) == FILL_COLOR


# --- Проверочный проход в обычном режиме -------------------------------------------------


def test_verification_pass_without_pii_returns_without_painting_low_conf() -> None:
    """После MAX_PASSES закрасок проверочный OCR без находок: слабое слово не закрашивается."""
    masker, ocr = make_masker([[PII_A], [PII_B], [PII_C], [SAFE, LOW]])
    out, stats, _rec = masker.mask_image_ex(blank())
    assert ocr.calls == MAX_PASSES + 1
    assert not is_black(out, LOW) and not is_black(out, SAFE)
    assert stats.masked_boxes == MAX_PASSES and stats.low_conf_boxes == 0


def test_verification_pass_paints_leftover_low_conf_when_enabled() -> None:
    """С paint_low_conf остаток слабых слов после проверочного прохода закрашивается."""
    masker, ocr = make_masker([[PII_A], [PII_B], [PII_C], [SAFE, LOW]], paint_low_conf=True)
    out, stats, _rec = masker.mask_image_ex(blank())
    assert ocr.calls == MAX_PASSES + 1
    assert is_black(out, LOW) and not is_black(out, SAFE)
    assert all(is_black(out, w) for w in (PII_A, PII_B, PII_C))
    assert stats.masked_boxes == MAX_PASSES + 1 and stats.low_conf_boxes == 1


def test_verification_pass_with_pii_still_refuses() -> None:
    masker, ocr = make_masker([[PII_A], [PII_B], [PII_C], [PII_A]])
    with pytest.raises(MediaRefusedError) as exc:
        masker.mask_image_ex(blank())
    assert exc.value.status == 422 and exc.value.code == "pii_remains_after_masking"
    assert ocr.calls == MAX_PASSES + 1


def test_clean_pass_inside_limit_does_not_need_verification() -> None:
    masker, ocr = make_masker([[PII_A], [SAFE]])
    _out, stats, _rec = masker.mask_image_ex(blank())
    assert ocr.calls == 2 and stats.masked_boxes == 1


# --- Режим «оригинал, если чисто» ---------------------------------------------------------


def test_original_returned_untouched_when_detector_finds_nothing() -> None:
    """Чисто: один OCR, пиксели те же, слабое слово не закрашено, лица и коды не трогались."""
    masker, ocr = make_masker([[SAFE, LOW]], strict_stubs=True)
    src = make_text_image(SAFE_LINES)
    result = masker.mask_bytes(to_bytes(src), original_if_clean=True)
    out = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert np.array_equal(np.asarray(out), np.asarray(src))
    assert ocr.calls == 1
    assert result.stats.original_kept and result.stats.masked_boxes == 0
    assert result.recognized.hidden_text is False
    assert "hello" in result.recognized.text and "junk123" not in result.recognized.text


def test_original_mode_paints_only_pii_words() -> None:
    """Найдены ПДн: закрашено только слово с находкой; слабое слово и остальное целы."""
    masker, ocr = make_masker([[PII_A, SAFE, LOW], [SAFE, LOW]], strict_stubs=True)
    out, stats, rec = masker.mask_original_if_clean(blank())
    assert is_black(out, PII_A)
    assert not is_black(out, SAFE) and not is_black(out, LOW)
    assert ocr.calls == 2  # закраска + проверочный OCR
    assert stats.masked_boxes == 1 and stats.original_kept is False
    assert stats.low_conf_boxes == 0 and stats.unreadable_boxes == 0
    # распознанный текст - с первого прохода, до закраски: метки в нём ставит прокси
    assert SECRET in rec.text and rec.hidden_text is False


def test_original_mode_paints_new_findings_of_verification_pass() -> None:
    masker, ocr = make_masker([[PII_A], [PII_B], [SAFE]], strict_stubs=True)
    out, stats, _rec = masker.mask_original_if_clean(blank())
    assert is_black(out, PII_A) and is_black(out, PII_B) and not is_black(out, SAFE)
    assert ocr.calls == 3 and stats.masked_boxes == 2


def test_original_mode_refuses_only_when_pii_persists() -> None:
    masker, ocr = make_masker([[PII_A]], strict_stubs=True)
    with pytest.raises(MediaRefusedError) as exc:
        masker.mask_original_if_clean(blank())
    assert exc.value.code == "pii_remains_after_masking"
    assert ocr.calls == MAX_PASSES + 1


def test_default_mode_does_not_paint_low_conf_without_pii() -> None:
    """Слабое слово без находки детектора по умолчанию не закрашивается (с 1.1.3)."""
    masker, ocr = make_masker([[SAFE, LOW]])
    result = masker.mask_bytes(to_bytes(blank()))
    out = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert not is_black(out, LOW) and result.stats.original_kept is False
    assert ocr.calls == 1 and result.stats.masked_boxes == 0


def test_low_conf_painted_when_enabled() -> None:
    masker, _ocr = make_masker([[SAFE, LOW], [SAFE]], paint_low_conf=True)
    out, stats, rec = masker.mask_image_ex(blank())
    assert is_black(out, LOW) and not is_black(out, SAFE)
    assert stats.low_conf_boxes == 1 and rec.hidden_text is True


# --- Настоящий Tesseract (на узле без Tesseract пропускаются) -------------------------------


def test_real_ocr_only_phone_is_painted(masker: ImageMasker, ocr: object) -> None:
    """Текст с телефоном: закрашен телефон, остальной текст читается."""
    src = make_text_image((SAFE_LINES[0], PHONE_LINE, SAFE_LINES[1]))
    result = masker.mask_bytes(to_bytes(src), original_if_clean=True)
    out = Image.open(io.BytesIO(result.data))
    text = " ".join(w.text for w in ocr.recognize(out))  # type: ignore[attr-defined]
    assert "345-67-89" not in text and "912" not in text
    assert "Заявление" in text and "закупок" in text
    assert result.stats.masked_boxes >= 1 and result.stats.original_kept is False


def test_real_ocr_clean_image_is_original(masker: ImageMasker) -> None:
    src = make_text_image(SAFE_LINES)
    result = masker.mask_bytes(to_bytes(src), original_if_clean=True)
    out = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert np.array_equal(np.asarray(out), np.asarray(src))
    assert result.stats.original_kept is True


def test_api_flag_reaches_masker(client: object, auth: dict[str, str]) -> None:
    """Поле original_if_clean запроса включает режим; без поля - прежняя маскировка."""
    data = b64(to_bytes(make_text_image(SAFE_LINES)))
    body = {"media_type": "image/png", "data": data}
    base = client.post("/mask_image", json=body, headers=auth)  # type: ignore[attr-defined]
    assert base.status_code == 200 and base.json()["stats"]["original_kept"] is False
    on = client.post(  # type: ignore[attr-defined]
        "/mask_image", json={**body, "original_if_clean": True}, headers=auth
    )
    assert on.status_code == 200 and on.json()["stats"]["original_kept"] is True
