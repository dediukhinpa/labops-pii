"""PDF: текстовый слой отдаётся текстом, страницы без текста растрируются и маскируются."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

import pypdfium2 as pdfium

from labops_pii.media.mask.config import MAX_IMAGE_PIXELS
from labops_pii.media.mask.imaging import (
    ImageMasker, MaskedImage, MaskStats, MediaRefusedError, Recognized,
)

logger = logging.getLogger(__name__)

# Меньше значимых символов - у страницы нет настоящего текстового слоя (штамп, номер страницы):
# её содержимое в картинке, поэтому она растрируется
MIN_TEXT_CHARS = 20
# 180 dpi: Tesseract читает текст страницы A4 и размер картинки для модели умеренный
PDF_POINTS_PER_INCH = 72.0
RENDER_DPI = 180.0
RENDER_SCALE = RENDER_DPI / PDF_POINTS_PER_INCH
SOURCE_FORMAT_RASTER = "JPEG"
# pdfium не потокобезопасен: все обращения к документу идут под одним замком
_PDFIUM_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class PageResult:
    """Результат по странице: либо текст, либо замаскированная картинка."""

    index: int
    text: str | None
    image: MaskedImage | None
    recognized: Recognized = Recognized()


@dataclass(frozen=True, slots=True)
class DocumentResult:
    """Результат по документу.

    Attributes:
        kind: text (все страницы с текстовым слоем), images (ни одной) или mixed.
        pages: Страницы по порядку.
        stats: Суммарные счётчики по растрированным страницам.
    """

    kind: str
    pages: list[PageResult]
    stats: MaskStats


def _render_scale(width_pt: float, height_pt: float) -> float:
    """Масштаб растеризации с потолком по числу пикселей."""
    scale = RENDER_SCALE
    pixels = width_pt * height_pt * scale * scale
    if pixels > MAX_IMAGE_PIXELS:
        scale *= (MAX_IMAGE_PIXELS / pixels) ** 0.5
    return scale


class PdfProcessor:
    """Обрабатывает PDF.

    Args:
        masker: Маскировщик изображений для растрированных страниц.
        max_pages: Предел страниц; сверх него 413.
    """

    def __init__(self, masker: ImageMasker, max_pages: int) -> None:
        self._masker = masker
        self._max_pages = max_pages

    def process(self, data: bytes) -> DocumentResult:
        """Извлекает текст или маскирует растр страниц.

        Raises:
            MediaRefusedError: Не PDF, зашифрован, слишком много страниц, сбой маскирования.
        """
        try:
            with _PDFIUM_LOCK:
                doc = pdfium.PdfDocument(data)
                count = len(doc)
        except pdfium.PdfiumError as exc:
            raise MediaRefusedError(422, "pdf_unreadable") from exc
        try:
            if count == 0:
                raise MediaRefusedError(422, "pdf_empty")
            if count > self._max_pages:
                raise MediaRefusedError(413, "pdf_too_many_pages")
            pages: list[PageResult] = []
            total = MaskStats()
            for index in range(count):
                result, stats = self._page(doc, index)
                pages.append(result)
                total = MaskStats(
                    total.words + stats.words,
                    total.masked_boxes + stats.masked_boxes,
                    total.faces + stats.faces,
                    total.low_conf_boxes + stats.low_conf_boxes,
                    total.codes + stats.codes,
                    total.unreadable_boxes + stats.unreadable_boxes,
                )
            texts = sum(1 for p in pages if p.text is not None)
            kind = "text" if texts == count else "images" if texts == 0 else "mixed"
            return DocumentResult(kind, pages, total)
        finally:
            with _PDFIUM_LOCK:
                doc.close()

    def _page(self, doc: pdfium.PdfDocument, index: int) -> tuple[PageResult, MaskStats]:
        """Страница: текстовый слой, если он есть, иначе растр через маскировщик."""
        try:
            with _PDFIUM_LOCK:
                page = doc[index]
                textpage = page.get_textpage()
                text = textpage.get_text_range()
                width, height = page.get_size()
                if len("".join(text.split())) >= MIN_TEXT_CHARS:
                    return PageResult(index, text, None), MaskStats()
                scale = _render_scale(width, height)
                image = page.render(scale=scale, may_draw_forms=False).to_pil().convert("RGB")
        except (pdfium.PdfiumError, ValueError, OverflowError) as exc:
            raise MediaRefusedError(422, "pdf_page_failed") from exc
        masked, stats, recognized = self._masker.mask_image_ex(image)
        media_type, payload = self._masker.encode(masked, SOURCE_FORMAT_RASTER)
        image_out = MaskedImage(media_type, payload, stats, recognized)
        return PageResult(index, None, image_out, recognized), stats
