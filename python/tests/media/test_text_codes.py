"""Текст с картинки, QR/штрихкоды, нераспознанный текст: что отдаётся прокси и что закрашено."""

from __future__ import annotations

import base64

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image
from labops_pii.detector import PiiDetector

from labops_pii.media.mask.codes import CodeFinder, describe_payload
from labops_pii.media.mask.config import load_settings
from labops_pii.media.mask.faces import FaceBlurrer
from labops_pii.media.mask.imaging import ImageMasker
from labops_pii.media.mask.ocr import TesseractOcr
from labops_pii.media.mask import unreadable
from labops_pii.media.mask.unreadable import find_unreadable
from tests.media.conftest import make_text_image, to_bytes
from tests.media.synthetic import (
    CARD_FRAGMENTS, QR_ORIGIN, SIGNATURE_BOX, VCARD, barcode_image, card_image,
    dark_share, draw_signature, photo_image, qr_image,
)
from tests.media.test_mask_api import post, scan_pdf

# Доля закрашенной площади фото без текста не выше этого (на деле 0)
PHOTO_MAX_MASKED_SHARE = 0.05
EAN_DIGITS = "460123456789"


@pytest.fixture(scope="module")
def finder() -> CodeFinder:
    return CodeFinder()


def test_card_text_is_returned_in_reading_order(masker: ImageMasker) -> None:
    _img, stats, rec = masker.mask_image_ex(card_image())
    lines = [ln for ln in rec.text.split("\n") if ln]
    assert lines[0].startswith("Иванов")
    assert any("912 345-67-89" in ln for ln in lines)
    assert lines.index(next(ln for ln in lines if "Абакан" in ln)) > 2
    assert stats.masked_boxes >= 3
    assert not rec.codes and not rec.hidden_text


def test_card_pii_painted_but_text_returned(masker: ImageMasker, ocr: TesseractOcr) -> None:
    out, _stats, rec = masker.mask_image_ex(card_image())
    after = " ".join(w.text for w in ocr.recognize(out))
    for fragment in CARD_FRAGMENTS:
        assert fragment in rec.text
    # Адрес детектор ПДн не ловит (в нём нет такого типа): его закраска не проверяется
    for fragment in CARD_FRAGMENTS[:3]:
        assert fragment not in after


def test_vcard_qr_decoded_painted_and_parsed(
    masker: ImageMasker, finder: CodeFinder
) -> None:
    src = qr_image(VCARD)
    assert finder.find(src), "sanity: QR находится до закраски"
    out, stats, rec = masker.mask_image_ex(src)
    assert stats.codes == 1
    assert len(rec.codes) == 1 and rec.codes[0].kind == "qr"
    text = rec.codes[0].text
    for part in ("Иванов Пётр Сергеевич", "+7 912 345-67-89", "petr.ivanov@example.com",
                 "Абакан", "Ленина 15"):
        assert part in text
    assert "VCARD" not in text
    # Область кода закрашена целиком и код больше не читается
    assert finder.find(out) == []
    left, top = QR_ORIGIN
    assert dark_share(out, (left + 60, top + 60, left + 200, top + 200)) == 1.0


def test_parsed_vcard_is_found_by_detector() -> None:
    detector = PiiDetector(True)
    types = {d.pii_type.name for d in detector.detect(describe_payload(VCARD))}
    assert {"PERSON", "PHONE", "EMAIL"} <= types


def test_undecodable_qr_is_still_painted(masker: ImageMasker, finder: CodeFinder) -> None:
    src = qr_image(VCARD)
    left, top = QR_ORIGIN
    # Портим данные кода (не угловые метки): расшифровать нельзя, найти по меткам можно
    arr = np.asarray(src).copy()
    rng = np.random.RandomState(0)
    patch = arr[top + 90:top + 180, left + 90:left + 180]
    patch[:] = rng.randint(0, 2, patch.shape[:2])[..., None] * 255
    broken = Image.fromarray(arr)
    out, stats, rec = masker.mask_image_ex(broken)
    assert stats.codes >= 1
    assert all(c.text == "" for c in rec.codes)
    assert dark_share(out, (left + 60, top + 60, left + 200, top + 200)) == 1.0


def test_barcode_decoded_and_painted(masker: ImageMasker, finder: CodeFinder) -> None:
    src = barcode_image(EAN_DIGITS)
    out, stats, rec = masker.mask_image_ex(src)
    assert stats.codes == 1
    assert rec.codes[0].kind == "barcode"
    assert rec.codes[0].text.startswith(EAN_DIGITS)
    assert finder.find(out) == []


def test_signature_hidden_and_flagged(masker: ImageMasker) -> None:
    card = card_image()
    draw_signature(card)
    out, stats, rec = masker.mask_image_ex(card)
    assert stats.unreadable_boxes >= 1
    assert rec.hidden_text
    # Штрихи подписи (синеватые) в итоге не остались
    region = np.asarray(out.crop(SIGNATURE_BOX)).astype(int)
    ink_left = np.sum((region[..., 2] - region[..., 0] > 20))
    assert ink_left == 0
    # Распознанный текст при этом не содержит подписи: мусора от неё нет
    assert "Иванов" in rec.text


def test_signature_ocr_does_not_read_it(ocr: TesseractOcr) -> None:
    """Sanity: без эвристики подпись остаётся нераспознанной (иначе тест выше ничего не значит)."""
    img = Image.new("RGB", (1200, 600), "white")
    draw_signature(img)
    words = [w for w in ocr.recognize(img) if w.conf >= 40.0 and len(w.text) >= 3]
    assert words == []


def test_unreadable_hiding_can_be_disabled(ocr: TesseractOcr) -> None:
    masker = ImageMasker(ocr, PiiDetector(True), FaceBlurrer(), hide_unreadable=False)
    img = Image.new("RGB", (1200, 600), "white")
    draw_signature(img)
    out, stats, rec = masker.mask_image_ex(img)
    assert stats.unreadable_boxes == 0 and not rec.hidden_text
    assert np.array_equal(np.asarray(out), np.asarray(img))


def test_photo_without_text_is_untouched(masker: ImageMasker) -> None:
    src = photo_image()
    out, stats, rec = masker.mask_image_ex(src)
    masked_share = float(np.mean(np.all(np.asarray(out) == 0, axis=2)))
    assert masked_share <= PHOTO_MAX_MASKED_SHARE
    assert stats.masked_boxes == 0 and stats.unreadable_boxes == 0
    assert rec.text == "" and not rec.codes and not rec.hidden_text
    assert np.array_equal(np.asarray(out), np.asarray(src))


def test_clean_printed_text_is_not_treated_as_unreadable(masker: ImageMasker) -> None:
    src = make_text_image(("Заявление на отпуск", "Отдел закупок, офис 12"))
    out, stats, rec = masker.mask_image_ex(src)
    assert stats.unreadable_boxes == 0 and not rec.hidden_text
    assert np.array_equal(np.asarray(out), np.asarray(src))


def test_too_much_candidate_area_is_treated_as_photo(monkeypatch: pytest.MonkeyPatch) -> None:
    """Если «письмом» покрыта слишком большая часть кадра, это фото: ничего не закрашиваем."""
    img = Image.new("RGB", (1200, 600), "white")
    draw_signature(img)
    assert find_unreadable(img, []).rects, "sanity: подпись находится"
    monkeypatch.setattr(unreadable, "MAX_TOTAL_SHARE", 0.001)
    result = find_unreadable(img, [])
    assert result.dropped_as_photo and result.rects == []


@pytest.mark.parametrize(
    ("payload", "expected", "forbidden"),
    [
        ("MECARD:N:Иванов,Пётр;TEL:+79123456789;EMAIL:p@example.com;ADR:Абакан,Ленина 15;;",
         ["ФИО: Пётр Иванов", "Телефон: +79123456789", "Эл. почта: p@example.com",
          "Адрес: Абакан, Ленина 15"], ["MECARD"]),
        ("WIFI:T:WPA;S:office;P:s3cret-pass;;", ["Wi-Fi"], ["s3cret-pass", "office"]),
        ("https://example.com/a?b=1", ["https://example.com/a?b=1"], []),
        ("BEGIN:VCARD\nN:Иванов;Пётр;;;\nTEL:+79123456789\nEND:VCARD",
         ["ФИО: Пётр Иванов", "Телефон: +79123456789"], ["VCARD"]),
    ],
)
def test_describe_payload(payload: str, expected: list[str], forbidden: list[str]) -> None:
    text = describe_payload(payload)
    for part in expected:
        assert part in text
    for part in forbidden:
        assert part not in text


def test_mask_image_endpoint_returns_recognized(client: TestClient, auth: dict[str, str]) -> None:
    card = card_image()
    draw_signature(card)
    body = post(client, "/mask_image", auth, "image/png", to_bytes(card)).json()
    rec = body["recognized"]
    assert "912 345-67-89" in rec["text"] and rec["hidden_text"] is True
    assert body["stats"]["unreadable_boxes"] >= 1
    qr = post(client, "/mask_image", auth, "image/png", to_bytes(qr_image(VCARD))).json()
    assert qr["recognized"]["codes"][0]["kind"] == "qr"
    assert "petr.ivanov@example.com" in qr["recognized"]["codes"][0]["text"]
    assert base64.b64decode(qr["data"])


def test_scanned_pdf_pages_carry_recognized_text(
    client: TestClient, auth: dict[str, str]
) -> None:
    body = post(client, "/extract_document", auth, "application/pdf", scan_pdf(1)).json()
    page = body["pages"][0]
    assert page["text"] is None and page["image"] is not None
    assert "912" in page["recognized"]["text"]


@pytest.mark.parametrize(("raw", "expected"), [("", True), ("true", True), ("false", False),
                                               ("0", False), ("no", False)])
def test_hide_unreadable_setting(raw: str, expected: bool) -> None:
    env = {"MEDIA_MASKER_API_TOKEN": "t"}
    if raw:
        env["MEDIA_MASKER_HIDE_UNREADABLE"] = raw
    assert load_settings(env).hide_unreadable is expected
