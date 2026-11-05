"""Маскирование одного изображения: лица, OCR, детектор ПДн, заливка, перекодирование."""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageOps, UnidentifiedImageError

from labops_pii.detector import PiiDetector
from labops_pii.media.mask.config import MAX_IMAGE_PIXELS
from labops_pii.media.mask.faces import FaceBlurrer
from labops_pii.media.mask.ocr import OcrError, OcrWord, TesseractOcr

logger = logging.getLogger(__name__)

# Слово с уверенностью ниже порога читается ненадёжно: его нельзя проверить детектором,
# поэтому оно закрашивается целиком (консервативно). Короткий мусор без цифр не трогаем.
LOW_CONF = 40.0
LOW_CONF_MIN_ALNUM = 3
# Сколько раз OCR-проверять результат: после заливки картинку читают заново; если и
# в последний проход находится ПДн - отказ. Чистая картинка стоит одного OCR.
MAX_PASSES = 3
# Для OCR мелкая картинка увеличивается до этой длинной стороны (но не более MAX_UPSCALE раз),
# крупная уменьшается до OCR_MAX_SIDE: Tesseract лучше всего читает текст ~30 px высотой.
OCR_TARGET_SIDE = 2000
OCR_MAX_UPSCALE = 3.0
OCR_MAX_SIDE = 4000
# Поле заливки вокруг слова: доля высоты, не меньше PAD_MIN_PX
PAD_SHARE = 0.25
PAD_MIN_PX = 2
# Целиком по тексту детектор запускается до этого размера; построчно - всегда
MAX_WHOLE_TEXT_CHARS = 60_000
FILL_COLOR = (0, 0, 0)
JPEG_QUALITY = 90
MEDIA_JPEG = "image/jpeg"
MEDIA_PNG = "image/png"
ALPHA_BACKGROUND = (255, 255, 255)


class MediaRefusedError(Exception):
    """Файл нельзя обработать или проверить: наружу его отправлять нельзя.

    Attributes:
        status: HTTP-код ответа сервиса.
        code: Короткий код причины (без содержимого).
    """

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


@dataclass(frozen=True, slots=True)
class MaskStats:
    """Счётчики маскирования без значений.

    Attributes:
        words: Распознано слов (последний проход).
        masked_boxes: Закрашено прямоугольников (все проходы).
        faces: Размыто лиц.
        low_conf_boxes: Из закрашенных слов - по низкой уверенности OCR.
    """

    words: int = 0
    masked_boxes: int = 0
    faces: int = 0
    low_conf_boxes: int = 0


@dataclass(frozen=True, slots=True)
class MaskedImage:
    """Результат: перекодированная картинка и счётчики."""

    media_type: str
    data: bytes
    stats: MaskStats


def build_text(words: list[OcrWord]) -> tuple[str, list[tuple[int, int]]]:
    """Склеивает слова в текст: строки через \\n, блоки через пустую строку.

    Returns:
        Текст и пары (start, end) положения каждого слова в нём.
    """
    parts: list[str] = []
    offsets: list[tuple[int, int]] = []
    pos = 0
    prev: tuple[int, int, int] | None = None
    for word in words:
        if prev is not None:
            sep = " " if word.line_key == prev else (
                "\n" if word.line_key[0] == prev[0] else "\n\n"
            )
            parts.append(sep)
            pos += len(sep)
        offsets.append((pos, pos + len(word.text)))
        parts.append(word.text)
        pos += len(word.text)
        prev = word.line_key
    return "".join(parts), offsets


def _is_low_conf(word: OcrWord) -> bool:
    """Слово читается ненадёжно и содержит значимые символы."""
    if word.conf >= LOW_CONF:
        return False
    alnum = sum(ch.isalnum() for ch in word.text)
    return alnum >= LOW_CONF_MIN_ALNUM or any(ch.isdigit() for ch in word.text)


class ImageMasker:
    """Маскирует изображения.

    Args:
        ocr: Распознаватель текста.
        detector: Детектор ПДн из пакета pseudonymizer.
        faces: Размыватель лиц.
    """

    def __init__(self, ocr: TesseractOcr, detector: PiiDetector, faces: FaceBlurrer) -> None:
        self._ocr = ocr
        self._detector = detector
        self._faces = faces

    def mask_bytes(self, data: bytes) -> MaskedImage:
        """Декодирует, маскирует и перекодирует изображение.

        Raises:
            MediaRefusedError: Не декодируется, слишком большое или сбой любого шага.
        """
        image, source_format = self._decode(data)
        masked, stats = self.mask_image(image)
        out_type, out = self.encode(masked, source_format)
        return MaskedImage(out_type, out, stats)

    def mask_image(self, image: Image.Image) -> tuple[Image.Image, MaskStats]:
        """Маскирует RGB-изображение (возвращает новое).

        Raises:
            MediaRefusedError: Сбой OCR/лиц или ПДн остались после MAX_PASSES.
        """
        image = image.copy()
        try:
            boxes = self._faces.find(image)
        except Exception as exc:  # cv2 бросает cv2.error и др.: любой сбой = отказ
            logger.error("face detection failed", extra={"exc_type": type(exc).__name__})
            raise MediaRefusedError(500, "face_detection_failed") from exc
        for box in boxes:
            self._faces.pixelate(image, box)
        # Повёрнутый текст OCR не читает: работаем на выпрямленной копии и без потерь
        # (поворот кратен 90) возвращаем назад
        rotation = self._rotation(image)
        if rotation:
            image = image.rotate(-rotation, expand=True)
        total_boxes = total_low = 0
        for _ in range(MAX_PASSES):
            words, rects, low = self._find_rects(image)
            if not rects:
                # Чистый проход: words - всё, что осталось читаемым после заливки
                if rotation:
                    image = image.rotate(rotation, expand=True)
                return image, MaskStats(len(words), total_boxes, len(boxes), total_low)
            total_boxes += len(rects)
            total_low += low
            draw = ImageDraw.Draw(image)
            for rect in rects:
                draw.rectangle(rect, fill=FILL_COLOR)
        raise MediaRefusedError(422, "pii_remains_after_masking")

    def _rotation(self, image: Image.Image) -> int:
        """Поворот страницы по OSD (на уменьшенной копии)."""
        scale = self._ocr_scale(image.size)
        gray = image.convert("L")
        if scale < 1.0:
            gray = gray.resize(
                (round(image.width * scale), round(image.height * scale)), Image.Resampling.BOX
            )
        try:
            return self._ocr.detect_rotation(gray)
        except OcrError as exc:
            raise MediaRefusedError(500, "ocr_failed") from exc

    def _find_rects(
        self, image: Image.Image
    ) -> tuple[list[OcrWord], list[tuple[int, int, int, int]], int]:
        """OCR + детектор: возвращает слова, прямоугольники заливки и число low-conf слов."""
        scale = self._ocr_scale(image.size)
        gray = ImageOps.autocontrast(image.convert("L"))
        if scale != 1.0:
            size = (round(image.width * scale), round(image.height * scale))
            gray = gray.resize(size, Image.Resampling.LANCZOS)
        try:
            words = self._ocr.recognize(gray, scale)
        except OcrError as exc:
            raise MediaRefusedError(500, "ocr_failed") from exc
        flagged = self._flagged_indices(words)
        low = sum(1 for i in flagged if _is_low_conf(words[i]))
        return words, self._merge_rects(words, flagged, image.size), low

    @staticmethod
    def _ocr_scale(size: tuple[int, int]) -> float:
        longest = max(size)
        if longest < OCR_TARGET_SIDE:
            return min(OCR_MAX_UPSCALE, OCR_TARGET_SIDE / longest)
        if longest > OCR_MAX_SIDE:
            return OCR_MAX_SIDE / longest
        return 1.0

    def _flagged_indices(self, words: list[OcrWord]) -> list[int]:
        """Индексы слов, пересекающих находки детектора, плюс слова с низкой уверенностью."""
        text, offsets = build_text(words)
        spans: list[tuple[int, int]] = []
        try:
            if len(text) <= MAX_WHOLE_TEXT_CHARS:
                spans += [(d.start, d.end) for d in self._detector.detect(text)]
            # Построчно: находки, зависящие от контекста страницы, и находки в одной строке
            # не должны зависеть друг от друга (NER на длинном тексте нестабилен)
            line_start = 0
            for line in text.split("\n"):
                if line.strip():
                    spans += [
                        (d.start + line_start, d.end + line_start)
                        for d in self._detector.detect(line)
                    ]
                line_start += len(line) + 1
        except Exception as exc:  # детектор упал: проверить нельзя - отказ
            logger.error("detector failed", extra={"exc_type": type(exc).__name__})
            raise MediaRefusedError(500, "detector_failed") from exc
        flagged = set()
        for i, (start, end) in enumerate(offsets):
            if _is_low_conf(words[i]) or any(s < end and e > start for s, e in spans):
                flagged.add(i)
        return sorted(flagged)

    @staticmethod
    def _merge_rects(
        words: list[OcrWord], flagged: list[int], size: tuple[int, int]
    ) -> list[tuple[int, int, int, int]]:
        """Сливает подряд идущие слова одной строки в один прямоугольник, добавляет поле."""
        groups: list[list[OcrWord]] = []
        prev_index = -2
        for i in flagged:
            word = words[i]
            if groups and i == prev_index + 1 and groups[-1][-1].line_key == word.line_key:
                groups[-1].append(word)
            else:
                groups.append([word])
            prev_index = i
        rects: list[tuple[int, int, int, int]] = []
        for group in groups:
            pad = max(PAD_MIN_PX, round(max(w.height for w in group) * PAD_SHARE))
            rects.append((
                max(0, min(w.left for w in group) - pad),
                max(0, min(w.top for w in group) - pad),
                min(size[0] - 1, max(w.left + w.width for w in group) + pad),
                min(size[1] - 1, max(w.top + w.height for w in group) + pad),
            ))
        return rects

    @staticmethod
    def _decode(data: bytes) -> tuple[Image.Image, str | None]:
        """Открывает картинку, поворачивает по EXIF, приводит к RGB."""
        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
        try:
            with Image.open(io.BytesIO(data)) as img:
                if img.width * img.height > MAX_IMAGE_PIXELS:
                    raise MediaRefusedError(413, "image_too_many_pixels")
                source_format = img.format
                img.load()
                img = ImageOps.exif_transpose(img)
                if img.mode in ("RGBA", "LA", "P"):
                    rgba = img.convert("RGBA")
                    base = Image.new("RGB", rgba.size, ALPHA_BACKGROUND)
                    base.paste(rgba, mask=rgba.getchannel("A"))
                    return base, source_format
                return img.convert("RGB"), source_format
        except MediaRefusedError:
            raise
        except Image.DecompressionBombError as exc:
            raise MediaRefusedError(413, "image_too_many_pixels") from exc
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            raise MediaRefusedError(422, "image_undecodable") from exc

    @staticmethod
    def encode(image: Image.Image, source_format: str | None) -> tuple[str, bytes]:
        """Кодирует заново: метаданные (EXIF, XMP, ICC, текстовые чанки) не переносятся."""
        buf = io.BytesIO()
        if source_format == "JPEG":
            image.save(buf, format="JPEG", quality=JPEG_QUALITY)
            return MEDIA_JPEG, buf.getvalue()
        image.save(buf, format="PNG")
        return MEDIA_PNG, buf.getvalue()
