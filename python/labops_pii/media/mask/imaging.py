"""Маскирование одного изображения: лица, OCR, детектор ПДн, заливка, перекодирование."""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageOps, UnidentifiedImageError

from labops_pii.detector import PiiDetector
from labops_pii.media.mask.codes import CodeFinder, CodeHit
from labops_pii.media.mask.config import MAX_IMAGE_PIXELS
from labops_pii.media.mask.faces import FaceBlurrer
from labops_pii.media.mask.ocr import OcrError, OcrWord, TesseractOcr
from labops_pii.media.mask.unreadable import find_unreadable

logger = logging.getLogger(__name__)

# Слово с уверенностью ниже порога читается ненадёжно. С 1.1.3 по умолчанию такие слова НЕ
# закрашиваются (решение владельца: закрашиваются только находки детектора); включается
# настройкой paint_low_conf (MEDIA_MASKER_PAINT_LOW_CONF). Слова ниже порога не идут в
# распознанный текст. Короткий мусор без цифр не считается.
LOW_CONF = 40.0
LOW_CONF_MIN_ALNUM = 3
# Сколько раз закрашивать и перечитывать картинку: после заливки её читают заново. Чистая
# картинка стоит одного OCR. После MAX_PASSES проходов закраски идёт ещё один, проверочный
# OCR-проход (он ничего не закрашивает по находкам): ПДн в нём - отказ, иначе остаток
# неразборчивых слов закрашивается и картинка отдаётся.
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
# Предел распознанного текста одной картинки в ответе, символов (дальше - обрезка по строке)
MAX_RECOGNIZED_CHARS = 30_000


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
        original_kept: Картинка отдана без закраски (режим «оригинал, если чисто»).
        pii_kinds: Типы ПДн, которые нашёл детектор за все проходы (без значений, по алфавиту).
            Нужны прокси, чтобы предложить владельцу отправить оригинал.
    """

    words: int = 0
    masked_boxes: int = 0
    faces: int = 0
    low_conf_boxes: int = 0
    codes: int = 0
    unreadable_boxes: int = 0
    original_kept: bool = False
    pii_kinds: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CodeText:
    """Содержимое найденного кода (область на картинке закрашена в любом случае).

    Attributes:
        kind: qr или barcode.
        text: Расшифровка в читаемом виде; пусто, если расшифровать не удалось.
    """

    kind: str
    text: str


@dataclass(frozen=True, slots=True)
class Recognized:
    """Что нашли на картинке локально. Идёт прокси, который заменит ПДн метками.

    Attributes:
        text: Распознанный текст в порядке чтения (строки через перевод строки). Слова с
            низкой уверенностью OCR не включаются: на картинке они закрашены.
        codes: Содержимое QR-кодов и штрихкодов.
        hidden_text: Часть текста нераспознана (рукопись, подпись, нечитаемые слова) и
            закрашена.
    """

    text: str = ""
    codes: tuple[CodeText, ...] = ()
    hidden_text: bool = False


@dataclass(frozen=True, slots=True)
class MaskedImage:
    """Результат: перекодированная картинка, счётчики и распознанное содержимое."""

    media_type: str
    data: bytes
    stats: MaskStats
    recognized: Recognized = Recognized()


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


def _kind_of(detection: object) -> str:
    """Тип находки детектора строкой (PHONE, PERSON...); подставной детектор без типа - PII."""
    kind = getattr(detection, "pii_type", None)
    return str(kind) if kind is not None else "PII"


@dataclass(frozen=True, slots=True)
class _Scan:
    """Результат одного OCR-прохода.

    Attributes:
        words: Распознанные слова.
        rects: Прямоугольники заливки (находки детектора и слова с низкой уверенностью).
        low: Сколько слов с низкой уверенностью помечено.
        pii_words: Сколько слов пересекают находки детектора ПДн (низкая уверенность сама по
            себе не считается: нечитаемый мусор - не доказательство ПДн).
        pii_rects: Прямоугольники только слов, пересекающих находки детектора.
        pii_kinds: Типы находок детектора (без значений).
    """

    words: list[OcrWord]
    rects: list[tuple[int, int, int, int]]
    low: int
    pii_words: int
    pii_rects: list[tuple[int, int, int, int]]
    pii_kinds: frozenset[str] = frozenset()


class ImageMasker:
    """Маскирует изображения.

    Args:
        ocr: Распознаватель текста.
        detector: Детектор ПДн из пакета labops_pii.
        faces: Размыватель лиц.
        hide_unreadable: Закрашивать нераспознанный текст (рукопись, подпись). По умолчанию
            нет: закрашиваются только находки детектора ПДн, лица и QR-коды.
        codes: Поиск QR-кодов и штрихкодов.
        paint_low_conf: Закрашивать слова с низкой уверенностью OCR без находки детектора.
            По умолчанию нет.
    """

    def __init__(
        self,
        ocr: TesseractOcr,
        detector: PiiDetector,
        faces: FaceBlurrer,
        hide_unreadable: bool = False,
        codes: CodeFinder | None = None,
        paint_low_conf: bool = False,
    ) -> None:
        self._ocr = ocr
        self._detector = detector
        self._faces = faces
        self._hide_unreadable = hide_unreadable
        self._paint_low_conf = paint_low_conf
        self._codes = codes if codes is not None else CodeFinder()

    def mask_bytes(self, data: bytes, original_if_clean: bool = False) -> MaskedImage:
        """Декодирует, маскирует и перекодирует изображение.

        Args:
            data: Байты картинки.
            original_if_clean: Режим «оригинал, если чисто» (см. `mask_original_if_clean`). Выключен
                по умолчанию: включает его только явная настройка агента.

        Raises:
            MediaRefusedError: Не декодируется, слишком большое или сбой любого шага.
        """
        image, source_format = self._decode(data)
        if original_if_clean:
            kept, stats, recognized = self.mask_original_if_clean(image)
            out_type, out = self.encode(kept, source_format)
            return MaskedImage(out_type, out, stats, recognized)
        masked, stats, recognized = self.mask_image_ex(image)
        out_type, out = self.encode(masked, source_format)
        return MaskedImage(out_type, out, stats, recognized)

    def mask_original_if_clean(
        self, image: Image.Image
    ) -> tuple[Image.Image, MaskStats, Recognized]:
        """Режим «оригинал, если чисто»: без лиц, QR-кодов и закраски нечитаемого текста.

        Нужен для картинок, где ПДн по смыслу нет (реклама, схемы): полная маскировка портит
        их, а OCR-шум каждый раз находит «новый» фрагмент. Один OCR-проход: если детектор по
        распознанному тексту ничего не нашёл (слова с низкой уверенностью сами по себе не ПДн),
        картинка возвращается как есть (метаданные снимает перекодирование). Если нашёл -
        закрашиваются ТОЛЬКО слова, пересекающиеся с находками, затем проверочный OCR; новые
        находки закрашиваются дальше, до MAX_PASSES проходов закраски. Лица и QR-коды в этом
        режиме НЕ проверяются - решение владельца, режим включается только явной настройкой.

        Raises:
            MediaRefusedError: Сбой OCR/детектора или ПДн остались после MAX_PASSES закрасок.
        """
        work = image.copy()
        rotation = self._rotation(work)
        if rotation:
            work = work.rotate(-rotation, expand=True)
        total_boxes = 0
        kinds: set[str] = set()
        recognized = Recognized()
        for attempt in range(MAX_PASSES + 1):
            scan = self._scan(work)
            kinds |= scan.pii_kinds
            if attempt == 0:
                # Распознанное берётся до закраски: прокси сам заменит в тексте ПДн метками.
                # Ничего нечитаемого не закрашивается, поэтому hidden_text всегда False.
                recognized = self._recognized(scan.words, [], False)
            if not scan.pii_words:
                if rotation:
                    work = work.rotate(rotation, expand=True)
                stats = MaskStats(
                    len(scan.words), total_boxes, original_kept=total_boxes == 0,
                    pii_kinds=tuple(sorted(kinds)),
                )
                return (image if total_boxes == 0 else work), stats, recognized
            if attempt == MAX_PASSES:
                break
            total_boxes += len(scan.pii_rects)
            draw = ImageDraw.Draw(work)
            for rect in scan.pii_rects:
                draw.rectangle(rect, fill=FILL_COLOR)
        raise MediaRefusedError(422, "pii_remains_after_masking")

    def mask_image(self, image: Image.Image) -> tuple[Image.Image, MaskStats]:
        """Маскирует RGB-изображение (возвращает новое), без распознанного содержимого.

        Raises:
            MediaRefusedError: Сбой OCR/лиц или ПДн остались после MAX_PASSES.
        """
        masked, stats, _recognized = self.mask_image_ex(image)
        return masked, stats

    def mask_image_ex(self, image: Image.Image) -> tuple[Image.Image, MaskStats, Recognized]:
        """Маскирует RGB-изображение и отдаёт распознанное содержимое.

        Порядок: лица, поворот, коды (закрашиваются всегда), OCR с детектором ПДн, поиск
        нераспознанного текста (закрашивается). Распознанный текст берётся с первого прохода,
        до закраски: прокси сам заменит в нём ПДн метками.

        Raises:
            MediaRefusedError: Сбой OCR/лиц/кодов или ПДн остались после MAX_PASSES.
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
        codes = self._hide_codes(image)
        total_boxes = total_low = unreadable = 0
        kinds: set[str] = set()
        recognized = Recognized()
        # Проходов закраски MAX_PASSES плюс один проверочный (attempt == MAX_PASSES)
        for attempt in range(MAX_PASSES + 1):
            scan = self._scan(image)
            kinds |= scan.pii_kinds
            words, rects, low = scan.words, scan.rects, scan.low
            if attempt == 0:
                extra = self._unreadable_rects(image, words, codes)
                unreadable = len(extra)
                rects = rects + extra
                recognized = self._recognized(words, codes, low > 0 or bool(extra))
            verifying = attempt == MAX_PASSES
            if verifying and scan.pii_words:
                # Даже после закраски детектор находит ПДн: защита не ослабляется
                raise MediaRefusedError(422, "pii_remains_after_masking")
            if not rects or verifying:
                # Чистый проход, либо проверочный без находок детектора. Если включена
                # закраска слабых слов (paint_low_conf), в rects остались только они: закраска
                # лишь убирает информацию, поэтому красим без нового OCR и отдаём картинку.
                if rects:
                    total_boxes += len(rects)
                    total_low += low
                    draw = ImageDraw.Draw(image)
                    for rect in rects:
                        draw.rectangle(rect, fill=FILL_COLOR)
                if rotation:
                    image = image.rotate(rotation, expand=True)
                stats = MaskStats(
                    len(words), total_boxes, len(boxes), total_low, len(codes), unreadable,
                    pii_kinds=tuple(sorted(kinds)),
                )
                return image, stats, recognized
            total_boxes += len(rects)
            total_low += low
            draw = ImageDraw.Draw(image)
            for rect in rects:
                draw.rectangle(rect, fill=FILL_COLOR)
        raise MediaRefusedError(422, "pii_remains_after_masking")  # недостижимо: цикл возвращает

    def _hide_codes(self, image: Image.Image) -> list[CodeHit]:
        """Находит QR и штрихкоды и закрашивает их на месте (содержимое возвращается)."""
        try:
            hits = self._codes.find(image)
        except Exception as exc:  # cv2.error и др.: код не проверить - отказ
            logger.error("code detection failed", extra={"exc_type": type(exc).__name__})
            raise MediaRefusedError(500, "code_detection_failed") from exc
        draw = ImageDraw.Draw(image)
        for hit in hits:
            draw.rectangle(hit.rect, fill=FILL_COLOR)
        return hits

    def _unreadable_rects(
        self, image: Image.Image, words: list[OcrWord], codes: list[CodeHit]
    ) -> list[tuple[int, int, int, int]]:
        """Области с признаками письма, которые OCR не распознал (рукопись, подпись)."""
        if not self._hide_unreadable:
            return []
        known = [(w.left, w.top, w.left + w.width, w.top + w.height) for w in words]
        known += [hit.rect for hit in codes]
        try:
            return find_unreadable(image, known).rects
        except Exception as exc:  # cv2.error и др.: проверить нельзя - отказ
            logger.error("unreadable scan failed", extra={"exc_type": type(exc).__name__})
            raise MediaRefusedError(500, "unreadable_scan_failed") from exc

    @staticmethod
    def _recognized(words: list[OcrWord], codes: list[CodeHit], hidden: bool) -> Recognized:
        """Распознанное содержимое: надёжные слова в порядке чтения и тексты кодов."""
        # Слова ниже порога на картинке закрашены (или это короткий мусор): в текст не идут
        readable = [w for w in words if w.conf >= LOW_CONF]
        text, _offsets = build_text(readable)
        if len(text) > MAX_RECOGNIZED_CHARS:
            text = text[:MAX_RECOGNIZED_CHARS].rsplit("\n", 1)[0]
        found = tuple(CodeText(c.kind, c.text) for c in codes)
        return Recognized(text.strip(), found, hidden)

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

    def _scan(self, image: Image.Image) -> _Scan:
        """OCR + детектор: слова, прямоугольники заливки, число low-conf слов и находок ПДн."""
        scale = self._ocr_scale(image.size)
        gray = ImageOps.autocontrast(image.convert("L"))
        if scale != 1.0:
            size = (round(image.width * scale), round(image.height * scale))
            gray = gray.resize(size, Image.Resampling.LANCZOS)
        try:
            words = self._ocr.recognize(gray, scale)
        except OcrError as exc:
            raise MediaRefusedError(500, "ocr_failed") from exc
        pii, pii_kinds = self._pii_indices(words)
        to_paint = set(pii)
        if self._paint_low_conf:
            to_paint |= {i for i, w in enumerate(words) if _is_low_conf(w)}
        flagged = sorted(to_paint)
        low = sum(1 for i in flagged if _is_low_conf(words[i]))
        return _Scan(
            words,
            self._merge_rects(words, flagged, image.size),
            low,
            len(pii),
            self._merge_rects(words, pii, image.size),
            pii_kinds,
        )

    @staticmethod
    def _ocr_scale(size: tuple[int, int]) -> float:
        longest = max(size)
        if longest < OCR_TARGET_SIDE:
            return min(OCR_MAX_UPSCALE, OCR_TARGET_SIDE / longest)
        if longest > OCR_MAX_SIDE:
            return OCR_MAX_SIDE / longest
        return 1.0

    def _pii_indices(self, words: list[OcrWord]) -> tuple[list[int], frozenset[str]]:
        """Индексы слов, пересекающих находки детектора ПДн, и типы находок.

        Returns:
            Индексы слов (по возрастанию) и множество типов находок (без значений).
        """
        text, offsets = build_text(words)
        spans: list[tuple[int, int]] = []
        kinds: set[str] = set()
        try:
            if len(text) <= MAX_WHOLE_TEXT_CHARS:
                for d in self._detector.detect(text):
                    spans.append((d.start, d.end))
                    kinds.add(_kind_of(d))
            # Построчно: находки, зависящие от контекста страницы, и находки в одной строке
            # не должны зависеть друг от друга (NER на длинном тексте нестабилен)
            line_start = 0
            for line in text.split("\n"):
                if line.strip():
                    for d in self._detector.detect(line):
                        spans.append((d.start + line_start, d.end + line_start))
                        kinds.add(_kind_of(d))
                line_start += len(line) + 1
        except Exception as exc:  # детектор упал: проверить нельзя - отказ
            logger.error("detector failed", extra={"exc_type": type(exc).__name__})
            raise MediaRefusedError(500, "detector_failed") from exc
        indices = [
            i for i, (start, end) in enumerate(offsets)
            if any(s < end and e > start for s, e in spans)
        ]
        # Типы только тех находок, что легли на слова картинки: находка без слов не закрашена
        return indices, frozenset(kinds) if indices else frozenset()

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
