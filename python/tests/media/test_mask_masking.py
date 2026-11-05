"""Маскирование изображений: ПДн закрашиваются, чистая картинка проходит, лица пикселизируются."""

from __future__ import annotations

import io

import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFilter

from labops_pii.media.mask.imaging import ImageMasker, MediaRefusedError, build_text
from labops_pii.media.mask.ocr import OcrWord, TesseractOcr
from tests.media.conftest import (
    INN_LINE, PERSON_LINE, PHONE_LINE, PII_FRAGMENTS, PII_LINES, SAFE_LINES, make_text_image,
    to_bytes,
)


def ocr_text(ocr: TesseractOcr, img: Image.Image) -> str:
    return " ".join(w.text for w in ocr.recognize(img))


def test_pii_is_painted_and_ocr_cannot_read_it(masker: ImageMasker, ocr: TesseractOcr) -> None:
    src = make_text_image((SAFE_LINES[0], *PII_LINES, SAFE_LINES[1]))
    before = ocr_text(ocr, src)
    assert all(f in before for f in PII_FRAGMENTS)  # sanity: без маски ПДн читаются
    result = masker.mask_bytes(to_bytes(src))
    out = Image.open(io.BytesIO(result.data))
    after = ocr_text(ocr, out)
    for fragment in PII_FRAGMENTS:
        assert fragment not in after
    # Непротиворечивый текст остаётся читаемым
    assert "Заявление" in after and "закупок" in after
    assert result.stats.masked_boxes >= 3
    assert result.stats.faces == 0


def test_clean_image_changes_only_by_reencoding(masker: ImageMasker) -> None:
    src = make_text_image(SAFE_LINES)
    result = masker.mask_bytes(to_bytes(src))
    out = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert out.size == src.size
    assert np.array_equal(np.asarray(out), np.asarray(src))
    assert result.stats.masked_boxes == 0


def test_result_is_deterministic(masker: ImageMasker) -> None:
    data = to_bytes(make_text_image(PII_LINES))
    assert masker.mask_bytes(data).data == masker.mask_bytes(data).data


def test_metadata_is_stripped(masker: ImageMasker) -> None:
    src = make_text_image(SAFE_LINES)
    exif = Image.Exif()
    exif[0x010E] = "SECRET-DESCRIPTION"  # ImageDescription
    buf = io.BytesIO()
    src.save(buf, format="JPEG", exif=exif.tobytes())
    assert b"SECRET-DESCRIPTION" in buf.getvalue()
    result = masker.mask_bytes(buf.getvalue())
    assert result.media_type == "image/jpeg"
    assert b"SECRET-DESCRIPTION" not in result.data
    assert not Image.open(io.BytesIO(result.data)).getexif()


def test_png_text_chunks_dropped(masker: ImageMasker) -> None:
    from PIL.PngImagePlugin import PngInfo

    info = PngInfo()
    info.add_text("Author", "Иван Иванов")
    buf = io.BytesIO()
    make_text_image(SAFE_LINES).save(buf, format="PNG", pnginfo=info)
    out = masker.mask_bytes(buf.getvalue())
    assert "Author".encode() not in out.data


def test_small_image_is_upscaled_for_ocr(masker: ImageMasker, ocr: TesseractOcr) -> None:
    src = make_text_image((PHONE_LINE, PERSON_LINE), size=(700, 200))
    out = Image.open(io.BytesIO(masker.mask_bytes(to_bytes(src)).data))
    assert "345-67-89" not in ocr_text(ocr, out)


@pytest.mark.parametrize("angle", [90, 180, 270])
def test_rotated_text_is_still_masked(
    masker: ImageMasker, ocr: TesseractOcr, angle: int
) -> None:
    # Повёрнутый текст Tesseract без OSD не читает: он остался бы незакрашенным
    src = make_text_image(PII_LINES).rotate(angle, expand=True, fillcolor="white")
    out = Image.open(io.BytesIO(masker.mask_bytes(to_bytes(src)).data))
    assert out.size == src.size
    upright = out.rotate(-angle, expand=True, fillcolor="white")
    text = ocr_text(ocr, upright)
    for fragment in PII_FRAGMENTS:
        assert fragment not in text


def test_low_confidence_words_are_painted(masker: ImageMasker, ocr: TesseractOcr) -> None:
    # Сильно размытый текст читается плохо: его нельзя проверить, значит закрашиваем
    blurred = make_text_image((INN_LINE, PHONE_LINE)).filter(ImageFilter.GaussianBlur(3))
    result = masker.mask_bytes(to_bytes(blurred))
    out = Image.open(io.BytesIO(result.data))
    assert "500100732259" not in ocr_text(ocr, out)


def test_face_is_pixelated(masker: ImageMasker) -> None:
    canvas = Image.new("RGB", (640, 480), (150, 150, 150))
    canvas.paste(_synthetic_face(), (200, 100))
    result = masker.mask_bytes(to_bytes(canvas))
    assert result.stats.faces >= 1
    out = np.asarray(Image.open(io.BytesIO(result.data)).convert("RGB")).astype(int)
    region = out[130:360, 230:470]
    # Мозаика PIXEL_GRID x PIXEL_GRID: внутри области мало различных значений
    assert len({tuple(px) for row in region[::8] for px in row[::8]}) <= 60


def _synthetic_face() -> Image.Image:
    """Схематичное лицо (овал, глазницы, брови, нос, рот), на котором срабатывает alt2."""
    img = Image.new("L", (300, 300), 150)
    d = ImageDraw.Draw(img)
    d.ellipse((40, 20, 260, 280), fill=170)
    d.ellipse((70, 100, 120, 135), fill=60)
    d.ellipse((180, 100, 230, 135), fill=60)
    d.ellipse((85, 108, 105, 128), fill=20)
    d.ellipse((195, 108, 215, 128), fill=20)
    d.rectangle((60, 85, 125, 98), fill=50)
    d.rectangle((175, 85, 240, 98), fill=50)
    d.polygon([(150, 120), (125, 200), (175, 200)], fill=130)
    d.ellipse((115, 225, 185, 250), fill=80)
    return img.filter(ImageFilter.GaussianBlur(3)).convert("RGB")


@pytest.mark.parametrize("payload", [b"", b"not an image", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20])
def test_broken_data_is_refused(masker: ImageMasker, payload: bytes) -> None:
    with pytest.raises(MediaRefusedError) as info:
        masker.mask_bytes(payload)
    assert info.value.status == 422


def test_pixel_limit(masker: ImageMasker, monkeypatch: pytest.MonkeyPatch) -> None:
    # _decode сам выставляет глобальный предел Pillow: monkeypatch вернёт его после теста
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", None)
    monkeypatch.setattr("labops_pii.media.mask.imaging.MAX_IMAGE_PIXELS", 100)
    with pytest.raises(MediaRefusedError) as info:
        masker.mask_bytes(to_bytes(Image.new("RGB", (50, 50), "white")))
    assert info.value.status == 413


def test_ocr_failure_refuses(masker: ImageMasker, monkeypatch: pytest.MonkeyPatch) -> None:
    from labops_pii.media.mask.ocr import OcrError

    def boom(*_a: object, **_k: object) -> list[OcrWord]:
        raise OcrError("x")

    monkeypatch.setattr(masker._ocr, "recognize", boom)
    with pytest.raises(MediaRefusedError) as info:
        masker.mask_bytes(to_bytes(make_text_image(SAFE_LINES)))
    assert info.value.status == 500


def test_build_text_layout() -> None:
    def w(text: str, key: tuple[int, int, int]) -> OcrWord:
        return OcrWord(text, 0, 0, 1, 1, 90.0, key)

    text, offsets = build_text([w("a", (1, 1, 1)), w("b", (1, 1, 1)), w("c", (1, 1, 2)),
                                w("d", (2, 1, 1))])
    assert text == "a b\nc\n\nd"
    assert [text[s:e] for s, e in offsets] == ["a", "b", "c", "d"]
