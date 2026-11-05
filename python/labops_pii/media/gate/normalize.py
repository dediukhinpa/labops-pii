"""Нормализация картинок для модели зрения и лимиты работы с картинками (этап 110).

Зачем: в модель зрения нужны только jpeg/png/webp/gif со стороной не больше ~1568 px
(больше провайдер всё равно уменьшит, а токены и трафик потратятся зря). Вложения приходят
в bmp/tiff/gif/webp/heic и с EXIF-поворотом. Сервис documents уже держит Pillow, поэтому
приведение к одному виду делается здесь, а не в ядре.

Защита: размер входа ограничен до декодирования, число пикселей проверяется по заголовку
(decompression bomb), список форматов закрытый (Pillow умеет открывать, например, EPS через
ghostscript - это не нужно). HEIC/HEIF без плагина Pillow не открывает: возвращаем понятную
ошибку «формат не поддержан», пакеты не добавляются.
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass

from PIL import Image, ImageOps, UnidentifiedImageError

logger = logging.getLogger(__name__)

MIB = 1024 * 1024
# Сторона, больше которой модель зрения всё равно уменьшает картинку (документация провайдера)
DEFAULT_MAX_SIDE_PX = 1568
DEFAULT_MAX_INPUT_BYTES = 20 * MIB
# Результат (после сжатия) не больше этого: лимит base64-блока картинки у провайдера ~5 МБ
DEFAULT_MAX_OUTPUT_BYTES = 5 * MIB
# 12-48 Мп - обычные фото телефонов; RGB 40 Мп - около 120 МиБ, jpeg декодируется сразу
# в уменьшенном виде (draft), поэтому реальный пик заметно ниже
DEFAULT_MAX_IMAGE_PIXELS = 40_000_000
JPEG_QUALITIES = (85, 72, 60, 45)
MIME_JPEG = "image/jpeg"
MIME_PNG = "image/png"
# Закрытый список форматов Pillow на входе (MPO - jpeg с несколькими кадрами у телефонов)
ALLOWED_FORMATS = ("JPEG", "MPO", "PNG", "GIF", "BMP", "TIFF", "WEBP")
# Если плагин HEIF/AVIF поставлен в образ, Pillow их откроет - разрешаем и их
OPTIONAL_FORMATS = ("HEIF", "AVIF")
# Белый фон под прозрачностью при сведении png в jpeg
FLATTEN_BACKGROUND = (255, 255, 255)
ALPHA_MODES = frozenset({"RGBA", "LA", "PA", "La", "RGBa"})
# Бренды ISO-BMFF (ftyp), по которым узнаём heic/heif, даже когда Pillow его не открывает
HEIF_BRANDS = frozenset({
    b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs", b"mif1", b"msf1",
})
FTYP_OFFSET = 4
BRAND_OFFSET = 8
BRAND_SIZE = 4
DETAIL_UNSUPPORTED = "формат не поддержан"
DETAIL_HEIC = "формат не поддержан: HEIC/HEIF не читается без плагина, пересохраните как JPEG"
DETAIL_TOO_BIG_PIXELS = "изображение слишком большое по числу пикселей"
DETAIL_TOO_BIG_BYTES = "изображение слишком большое по размеру файла"
DETAIL_CORRUPT = "изображение повреждено или не читается"
DETAIL_OUTPUT_TOO_BIG = "после сжатия изображение всё ещё больше допустимого размера"


class ImageUnsupportedError(Exception):
    """Формат изображения не поддерживается (в том числе HEIC без плагина)."""


class ImageTooLargeError(Exception):
    """Файл или число пикселей выше лимита (в том числе decompression bomb)."""


class ImageCorruptError(Exception):
    """Данные не читаются как изображение заявленного формата."""


@dataclass(frozen=True)
class ImageLimits:
    """Лимиты картинок: нормализация и извлечение из документов.

    Attributes:
        max_side_px: Наибольшая сторона результата, px (нормализация и рендер страниц pdf).
        max_input_bytes: Максимальный размер входной картинки (в байтах).
        max_output_bytes: Максимальный размер картинки после сжатия.
        max_image_pixels: Максимум пикселей на входе (защита от decompression bomb).
        max_images_per_document: Сколько картинок отдаётся из одного документа.
        max_images_total_bytes: Суммарный размер отданных картинок документа.
        min_image_side_px: Картинки с меньшей стороной (логотипы, иконки, линейки) отбрасываются.
        pdf_render_pages: Сколько страниц pdf без текста рендерится в картинки (в пределах
            общего лимита числа картинок).
    """

    max_side_px: int = DEFAULT_MAX_SIDE_PX
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_image_pixels: int = DEFAULT_MAX_IMAGE_PIXELS
    max_images_per_document: int = 20
    max_images_total_bytes: int = 30 * MIB
    min_image_side_px: int = 80
    pdf_render_pages: int = 20

    def __post_init__(self) -> None:
        """Отсекает значения, при которых картинки обрабатывать нельзя."""
        for name in ("max_side_px", "max_input_bytes", "max_output_bytes", "max_image_pixels"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} должен быть не меньше 1")
        for name in ("max_images_per_document", "min_image_side_px", "pdf_render_pages"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} не может быть отрицательным")


# Имя переменной окружения для каждого поля ImageLimits (DOCUMENTS_<ИМЯ>)
IMAGE_ENV_NAMES = {
    "max_side_px": "DOCUMENTS_IMAGE_MAX_SIDE_PX",
    "max_input_bytes": "DOCUMENTS_IMAGE_MAX_INPUT_BYTES",
    "max_output_bytes": "DOCUMENTS_MAX_IMAGE_BYTES",
    "max_image_pixels": "DOCUMENTS_MAX_IMAGE_PIXELS",
    "max_images_per_document": "DOCUMENTS_MAX_IMAGES_PER_DOCUMENT",
    "max_images_total_bytes": "DOCUMENTS_MAX_IMAGES_TOTAL_BYTES",
    "min_image_side_px": "DOCUMENTS_MIN_IMAGE_SIDE_PX",
    "pdf_render_pages": "DOCUMENTS_PDF_RENDER_PAGES",
}


@dataclass(frozen=True)
class NormalizedImage:
    """Результат нормализации.

    Attributes:
        data: Байты jpeg или png.
        mime: `image/jpeg` или `image/png`.
        width: Ширина результата, px.
        height: Высота результата, px.
        source_format: Формат входа по Pillow (JPEG, PNG, BMP, ...).
        resized: Картинка уменьшена до `max_side_px`.
    """

    data: bytes
    mime: str
    width: int
    height: int
    source_format: str
    resized: bool


def _allowed_formats() -> list[str]:
    """Разрешённые форматы: базовые и плагины HEIF/AVIF, если они зарегистрированы."""
    Image.init()
    # MPO и плагины HEIF/AVIF есть не в каждой сборке Pillow: берём только зарегистрированные
    return [f for f in (*ALLOWED_FORMATS, *OPTIONAL_FORMATS) if f in Image.OPEN]


def looks_like_heif(data: bytes) -> bool:
    """HEIC/HEIF по сигнатуре контейнера (ftyp + бренд)."""
    head = data[: BRAND_OFFSET + BRAND_SIZE]
    return (
        len(head) == BRAND_OFFSET + BRAND_SIZE
        and head[FTYP_OFFSET:BRAND_OFFSET] == b"ftyp"
        and head[BRAND_OFFSET:] in HEIF_BRANDS
    )


def open_image(data: bytes, limits: ImageLimits) -> Image.Image:
    """Открывает картинку лениво (заголовок), проверив размер и число пикселей.

    Raises:
        ImageTooLargeError: Файл больше `max_input_bytes` или пикселей больше лимита.
        ImageUnsupportedError: Формат не из списка или HEIC без плагина.
        ImageCorruptError: Заголовок не читается.
    """
    if len(data) > limits.max_input_bytes:
        raise ImageTooLargeError(DETAIL_TOO_BIG_BYTES)
    # Страховка Pillow на случай, если картинку откроют в обход этой функции
    Image.MAX_IMAGE_PIXELS = limits.max_image_pixels
    try:
        image = Image.open(io.BytesIO(data), formats=_allowed_formats())
    except UnidentifiedImageError as exc:
        if looks_like_heif(data):
            raise ImageUnsupportedError(DETAIL_HEIC) from None
        raise ImageUnsupportedError(DETAIL_UNSUPPORTED) from exc
    except Image.DecompressionBombError as exc:
        raise ImageTooLargeError(DETAIL_TOO_BIG_PIXELS) from exc
    except (OSError, ValueError, SyntaxError) as exc:
        raise ImageCorruptError(DETAIL_CORRUPT) from exc
    width, height = image.size
    if width < 1 or height < 1 or width * height > limits.max_image_pixels:
        image.close()
        raise ImageTooLargeError(DETAIL_TOO_BIG_PIXELS)
    return image


def _has_alpha(image: Image.Image) -> bool:
    """Есть ли в картинке реально прозрачные пиксели (а не просто альфа-канал)."""
    if image.mode in ALPHA_MODES:
        alpha = image.getchannel("A") if "A" in image.getbands() else None
        if alpha is None:
            return True
        low, _high = alpha.getextrema()
        return low < 255
    return image.mode == "P" and "transparency" in image.info


def _to_8bit(image: Image.Image) -> Image.Image:
    """Приводит 16/32-битные и вещественные режимы к 8 бит (иначе convert даёт мусор)."""
    if image.mode.startswith("I;16"):
        return image.point(lambda value: value / 256).convert("L")
    if image.mode == "I":
        return image.point(lambda value: value / 256).convert("L")
    if image.mode == "F":
        return image.convert("L")
    return image


def _encode_jpeg(image: Image.Image, limits: ImageLimits) -> bytes:
    """jpeg с понижением качества, пока не влезет в `max_output_bytes`."""
    for quality in JPEG_QUALITIES:
        buffer = io.BytesIO()
        image.save(buffer, "JPEG", quality=quality, optimize=True)
        if buffer.tell() <= limits.max_output_bytes:
            return buffer.getvalue()
    raise ImageTooLargeError(DETAIL_OUTPUT_TOO_BIG)


def normalize_image(data: bytes, limits: ImageLimits) -> NormalizedImage:
    """Приводит картинку к jpeg (или png при прозрачности) со стороной до `max_side_px`.

    Учитывается EXIF-ориентация; многокадровые (gif, tiff) берут первый кадр. Картинка
    только уменьшается, увеличения нет.

    Args:
        data: Байты картинки bmp/tiff/gif/webp/png/jpeg.
        limits: Лимиты.

    Raises:
        ImageUnsupportedError: Формат не поддержан (в том числе HEIC без плагина).
        ImageTooLargeError: Слишком большой вход или результат.
        ImageCorruptError: Картинка не читается.
    """
    image = open_image(data, limits)
    source_format = image.format or ""
    try:
        if source_format in ("JPEG", "MPO"):
            # Декодирование сразу в уменьшенном виде: пик памяти фото 48 Мп падает в разы
            image.draft("RGB", (limits.max_side_px, limits.max_side_px))
        try:
            image.seek(0)
            image.load()
            work = ImageOps.exif_transpose(image)
        except Image.DecompressionBombError as exc:
            raise ImageTooLargeError(DETAIL_TOO_BIG_PIXELS) from exc
        except (OSError, ValueError, SyntaxError, EOFError) as exc:
            raise ImageCorruptError(DETAIL_CORRUPT) from exc
        work = _to_8bit(work)
        transparent = _has_alpha(work)
        resized = max(work.size) > limits.max_side_px
        if resized:
            work.thumbnail((limits.max_side_px, limits.max_side_px), Image.Resampling.LANCZOS)
        if transparent:
            png = work.convert("RGBA")
            buffer = io.BytesIO()
            png.save(buffer, "PNG", optimize=True)
            if buffer.tell() <= limits.max_output_bytes:
                return NormalizedImage(
                    buffer.getvalue(), MIME_PNG, png.width, png.height, source_format, resized
                )
            # Слишком тяжёлый png: сводим в jpeg на белом фоне
            flat = Image.new("RGB", png.size, FLATTEN_BACKGROUND)
            flat.paste(png, mask=png.getchannel("A"))
            work = flat
        rgb = work.convert("RGB")
        return NormalizedImage(
            _encode_jpeg(rgb, limits), MIME_JPEG, rgb.width, rgb.height, source_format, resized
        )
    finally:
        image.close()
