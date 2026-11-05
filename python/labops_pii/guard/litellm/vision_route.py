"""Маршрут зрения: картинки в запросе к модели, проверка ФОРМЫ и текста вместо скана тела.

Решение владельца (этап 110, вариант 2): фотографии из прайсов, вложений задач, чатов и с диска
уходят в модель напрямую, без маскирования ПДн на картинке. Позже (вариант 1) перед отправкой
встанет локальный OCR с закраской областей с ПДн; шлюзу это не мешает - он проверяет только
форму запроса и текстовые части.

Как основной маршрут `/v1/messages` обходится с base64 сейчас (проверено по коду и замером):
  * блок `image` в нём не запрещён и не понимается: `scan_body` прогоняет детектор ПДн по сырому
    телу и по каждой строке JSON, то есть и по base64-строке картинки целиком. Детектор ищет
    длинные цифровые последовательности (телефон, ИНН, СНИЛС, карта, счёт); в случайном base64
    такие серии встречаются, замер на случайных 300 КБ данных (400 КБ base64) даёт ложный отказ
    422 примерно в 1 запросе из 40, и вероятность растёт с размером;
  * проверка стоит процессорного времени (замер ~0,3 с на 400 КБ base64, то есть секунды на
    5 МБ) и занимает поток из пула из 4 потоков, а смысла в ней нет: ПДн в пикселях детектор
    всё равно не увидит;
  * общий предел тела 8 МиБ (`MAX_BODY_BYTES`, `client_max_body_size 8m`) ограничивает
    несколько картинок в одном запросе, но поднимать его для основного маршрута нельзя:
    предел одновременно служит пределом сканирования и памяти для всех запросов;
  * форма не проверяется: клиент мог бы протащить `tools`, произвольные блоки и параметры.
Поэтому нужен отдельный маршрут: картинки не сканируются детектором (иначе ложные отказы и
нагрузка), зато жёстко проверяются форма, mime, base64, размер, размеры в пикселях и число
картинок, запрещены tools, а текстовые части (`system`, текст сообщения) проверяются детектором
ПДн так же, как на основном маршруте (отказ 422). Модуль не логирует содержимое: в журнал идёт
только mime, размер и префикс sha256 каждой картинки.

Размеры картинок читаются из заголовков PNG/JPEG/GIF/WebP вручную (Pillow в pii-guard нет).
"""

import base64
import binascii
import hashlib
import json
import os
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from labops_pii.guard.detector import find_pii_types
from labops_pii.guard.litellm.search_route import (
    REASON_ENCODING,
    REASON_KEYS,
    REASON_MESSAGES,
    REASON_METHOD,
    REASON_NOT_JSON,
    REASON_PARAMS,
    REASON_QUERY,
    REASON_SIZE,
    REASON_STREAM,
    REASON_TOOL_CHOICE,
    REASON_TOOLS,
    _params_ok,
    first_path_segment,
    parse_allowed_models,
)
from labops_pii.guard.policy import split_findings

# Единственный путь маршрута и пространство имён под ним (всё, кроме точного пути, - 403).
VISION_ROUTE_PATH = "/vision/v1/messages"
VISION_NAMESPACE_SEGMENT = "vision"
# Путь в апстриме: запрос уходит в обычный /v1/messages, а не под /vision/.
VISION_UPSTREAM_PATH = "/v1/messages"
VISION_FORM_CODE = "vision_route_form"
VISION_ENABLED_ENV = "VISION_ROUTE_ENABLED"
VISION_ALLOWED_MODELS_ENV = "VISION_ALLOWED_MODELS"
# Решение владельца: зрение идёт той же моделью, что агенты. Запрос уходит в LiteLLM
# (/v1/messages), поэтому model - алиас LiteLLM `agent-main` (его модель задаёт MAIN_MODEL);
# пустой VISION_ALLOWED_MODELS не снимает ограничение, а даёт этот алиас. Отдельного алиаса нет.
DEFAULT_VISION_MODEL = "agent-main"

# Пределы по умолчанию (переопределяются env, см. VisionLimits.from_env).
VISION_MAX_IMAGES_ENV = "VISION_MAX_IMAGES"
DEFAULT_MAX_IMAGES = 10
VISION_MAX_IMAGE_B64_BYTES_ENV = "VISION_MAX_IMAGE_B64_BYTES"
# Предел провайдера модели на одну картинку - 5 МБ; считаем длину base64-строки.
DEFAULT_MAX_IMAGE_B64_BYTES = 5 * 1024 * 1024
VISION_MAX_IMAGE_SIDE_ENV = "VISION_MAX_IMAGE_SIDE"
# Больше 1568 px модель всё равно уменьшает сама (документация провайдера по vision), а токены и
# трафик тратятся впустую; нормализацию до этой стороны делает вызывающий (сервис documents).
DEFAULT_MAX_IMAGE_SIDE = 1568
VISION_MAX_BODY_BYTES_ENV = "VISION_MAX_BODY_BYTES"
# Тело с картинками: base64 раздувает на 4/3, предел памяти guard (mem_limit 1g, слоты по 16 МБ)
# рассчитан на тело до 16 МиБ, поэтому и здесь потолок 16 МиБ.
DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024
VISION_MAX_CONCURRENT_ENV = "VISION_MAX_CONCURRENT"
# Слоты по ~64 МиБ пика (см. бюджет памяти в gateway/README.md): mem_limit guard не поднимаем,
# поэтому число одновременных запросов зрения ограничено, а не память.
DEFAULT_MAX_CONCURRENT = 2
VISION_QUEUE_TIMEOUT_ENV = "VISION_QUEUE_TIMEOUT_SECONDS"
# Дольше 20 с ждать слот нет смысла: клиент (ядро) повторит запрос сам, а очередь не копит тела.
DEFAULT_QUEUE_TIMEOUT_SECONDS = 20
# Жёсткие потолки env: ошибочное значение не должно снять защиту памяти шлюза.
HARD_MAX_CONCURRENT = 4  # размер пула проверки: больше слотов пул всё равно не обслужит
HARD_QUEUE_TIMEOUT_SECONDS = 120
HARD_MAX_IMAGES = 20
HARD_MAX_BODY_BYTES = 32 * 1024 * 1024
HARD_MAX_IMAGE_SIDE = 8000
# Текст запроса фиксирован кодом ядра (инструкция режима), данных заказчика в нём нет.
VISION_MAX_TEXT_BYTES = 16384
VISION_MAX_TEXT_BLOCKS = 32
VISION_MODEL_MAX_LEN = 128

ALLOWED_TOP_KEYS = frozenset({"model", "max_tokens", "system", "messages", "temperature"})
ALLOWED_MIME = frozenset({"image/jpeg", "image/png", "image/webp", "image/gif"})
ALLOWED_IMAGE_BLOCK_KEYS = frozenset({"type", "source"})
ALLOWED_SOURCE_KEYS = frozenset({"type", "media_type", "data"})
ALLOWED_TEXT_BLOCK_KEYS = frozenset({"type", "text"})
IMAGE_BLOCK_TYPE = "image"
TEXT_BLOCK_TYPE = "text"
SOURCE_TYPE_BASE64 = "base64"
USER_ROLE = "user"
# Сколько hex-символов sha256 пишется в журнал: хватает для сопоставления, но не для подбора.
LOG_HASH_PREFIX_CHARS = 12

# Коды причин отказа (попадают в журнал и ответ; значения из тела не попадают никуда).
REASON_TEXT_SIZE = "text_size"
REASON_IMAGE_COUNT = "image_count"
REASON_IMAGE_BLOCK = "image_block"
REASON_IMAGE_MIME = "image_mime"
REASON_IMAGE_BASE64 = "image_base64"
REASON_IMAGE_SIZE = "image_size"
REASON_IMAGE_FORMAT = "image_format"
REASON_IMAGE_DIMENSIONS = "image_dimensions"
# Не форма, а содержимое: ответ 422 как на основном маршруте, а не 403.
REASON_PII = "pii"

# Сигнатуры и константы форматов
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_IHDR_END = 24  # 8 сигнатура + 4 длина + 4 "IHDR" + 4 ширина + 4 высота
_GIF_SIGNATURES = (b"GIF87a", b"GIF89a")
_GIF_HEADER_END = 10
_RIFF = b"RIFF"
_WEBP = b"WEBP"
_JPEG_SOI = b"\xff\xd8"
# SOF-маркеры JPEG (кадр с размерами); C4 (DHT), C8 (JPG), CC (DAC) - не кадры.
_JPEG_SOF_MARKERS = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
# Маркеры без длины/данных (RSTn, SOI, EOI, TEM)
_JPEG_STANDALONE = frozenset({0x01, 0xD8, 0xD9, *range(0xD0, 0xD8)})
_JPEG_MARKER_PREFIX = 0xFF
_JPEG_SOS = 0xDA
_WEBP_MIN_LEN = 21
_WEBP_VP8_END = 30
_WEBP_VP8L_END = 25
_WEBP_VP8X_END = 30
_JPEG_SOF_MIN_LEN = 9  # длина + точность + высота + ширина + число компонент


@dataclass(frozen=True)
class VisionLimits:
    """Пределы маршрута зрения."""

    max_images: int = DEFAULT_MAX_IMAGES
    max_image_b64_bytes: int = DEFAULT_MAX_IMAGE_B64_BYTES
    max_image_side: int = DEFAULT_MAX_IMAGE_SIDE
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_concurrent: int = DEFAULT_MAX_CONCURRENT
    queue_timeout_seconds: int = DEFAULT_QUEUE_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "VisionLimits":
        """Читает пределы из окружения.

        Args:
            env: Окружение (по умолчанию os.environ).

        Returns:
            Пределы; не заданное берётся из значений по умолчанию.

        Raises:
            ValueError: Значение не целое, не положительное или выше жёсткого потолка
                (приложение не запускается, как при неверном MAX_BODY_BYTES).
        """
        source = os.environ if env is None else env
        return cls(
            max_images=_env_int(source, VISION_MAX_IMAGES_ENV, DEFAULT_MAX_IMAGES, HARD_MAX_IMAGES),
            max_image_b64_bytes=_env_int(
                source, VISION_MAX_IMAGE_B64_BYTES_ENV, DEFAULT_MAX_IMAGE_B64_BYTES,
                HARD_MAX_BODY_BYTES,
            ),
            max_image_side=_env_int(
                source, VISION_MAX_IMAGE_SIDE_ENV, DEFAULT_MAX_IMAGE_SIDE, HARD_MAX_IMAGE_SIDE
            ),
            max_body_bytes=_env_int(
                source, VISION_MAX_BODY_BYTES_ENV, DEFAULT_MAX_BODY_BYTES, HARD_MAX_BODY_BYTES
            ),
            max_concurrent=_env_int(
                source, VISION_MAX_CONCURRENT_ENV, DEFAULT_MAX_CONCURRENT, HARD_MAX_CONCURRENT
            ),
            queue_timeout_seconds=_env_int(
                source, VISION_QUEUE_TIMEOUT_ENV, DEFAULT_QUEUE_TIMEOUT_SECONDS,
                HARD_QUEUE_TIMEOUT_SECONDS,
            ),
        )


def _env_int(env: Mapping[str, str], name: str, default: int, ceiling: int) -> int:
    """Целое из env в диапазоне 1..ceiling или default, если переменная не задана."""
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} должна быть целым числом") from exc
    if not 1 <= value <= ceiling:
        raise ValueError(f"{name} должна быть в диапазоне 1..{ceiling}")
    return value


@dataclass(frozen=True)
class ImageMeta:
    """Метаданные картинки для журнала: никакого содержимого."""

    mime: str
    size: int  # размер после декодирования, байт
    sha256_prefix: str
    width: int
    height: int

    def log_text(self) -> str:
        """Строка для журнала: mime, размер, размеры, префикс хэша."""
        return (
            f"{self.mime}:{self.size}:{self.width}x{self.height}:{self.sha256_prefix}"
        )


@dataclass
class VisionVerdict:
    """Итог проверки: причина отказа (или None), находки ПДн в тексте, метаданные картинок."""

    reason: str | None = None
    pii_types: frozenset[str] = frozenset()
    # Находки, которые не блокируют (ФИО и адрес в log_only): только журнал и метрика
    observed_types: frozenset[str] = frozenset()
    images: list[ImageMeta] = field(default_factory=list)


def parse_vision_models(raw: str | None) -> frozenset[str]:
    """Допустимые model маршрута зрения; пусто - только алиас агентов `agent-main`."""
    return parse_allowed_models(raw) or frozenset({DEFAULT_VISION_MODEL})


def is_vision_namespace(path: str) -> bool:
    """Относится ли путь к пространству /vision/ (без учёта регистра, %-кодирования, `//`)."""
    return first_path_segment(path) == VISION_NAMESPACE_SEGMENT


def image_dimensions(mime: str, data: bytes) -> tuple[int, int] | None:
    """Ширина и высота картинки из заголовка либо None, если формат не тот или заголовок битый.

    Args:
        mime: Заявленный mime (jpeg/png/webp/gif); сигнатура данных обязана ему соответствовать.
        data: Декодированные байты картинки.

    Returns:
        Пара (ширина, высота) в пикселях или None.
    """
    parsers = {
        "image/png": _png_size,
        "image/jpeg": _jpeg_size,
        "image/gif": _gif_size,
        "image/webp": _webp_size,
    }
    parser = parsers.get(mime)
    if parser is None:
        return None
    try:
        return parser(data)
    except (struct.error, IndexError):
        return None


def _png_size(data: bytes) -> tuple[int, int] | None:
    """PNG: сигнатура и первый чанк IHDR."""
    if len(data) < _PNG_IHDR_END or not data.startswith(_PNG_SIGNATURE):
        return None
    if data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:_PNG_IHDR_END])
    return width, height


def _gif_size(data: bytes) -> tuple[int, int] | None:
    """GIF: сигнатура и логический экран (16 бит, little-endian)."""
    if len(data) < _GIF_HEADER_END or data[:6] not in _GIF_SIGNATURES:
        return None
    width, height = struct.unpack("<HH", data[6:_GIF_HEADER_END])
    return width, height


def _jpeg_size(data: bytes) -> tuple[int, int] | None:
    """JPEG: проход по сегментам до первого SOF-маркера."""
    if not data.startswith(_JPEG_SOI):
        return None
    pos = 2
    total = len(data)
    while pos + 1 < total:
        if data[pos] != _JPEG_MARKER_PREFIX:
            # Мусор между сегментами пропускаем одним поиском, а не побайтовым циклом.
            next_prefix = data.find(bytes([_JPEG_MARKER_PREFIX]), pos)
            if next_prefix < 0:
                return None
            pos = next_prefix
            continue
        marker = data[pos + 1]
        if marker == _JPEG_MARKER_PREFIX:  # заполняющие 0xFF
            pos += 1
            continue
        pos += 2
        if marker in _JPEG_STANDALONE:
            continue
        if pos + 2 > total:
            return None
        (seg_len,) = struct.unpack(">H", data[pos:pos + 2])
        if marker in _JPEG_SOF_MARKERS:
            if seg_len < _JPEG_SOF_MIN_LEN or pos + _JPEG_SOF_MIN_LEN > total:
                return None
            height, width = struct.unpack(">HH", data[pos + 3:pos + 7])
            return width, height
        if marker == _JPEG_SOS:  # дальше только данные сканирования, кадра не было
            return None
        pos += seg_len
    return None


def _webp_size(data: bytes) -> tuple[int, int] | None:
    """WebP: RIFF-контейнер, чанк VP8 (lossy), VP8L (lossless) или VP8X (расширенный)."""
    if len(data) < _WEBP_MIN_LEN or data[:4] != _RIFF or data[8:12] != _WEBP:
        return None
    kind = data[12:16]
    if kind == b"VP8 ":
        if len(data) < _WEBP_VP8_END or data[23:26] != b"\x9d\x01\x2a":
            return None
        width, height = struct.unpack("<HH", data[26:30])
        return width & 0x3FFF, height & 0x3FFF
    if kind == b"VP8L":
        if len(data) < _WEBP_VP8L_END or data[20] != 0x2F:
            return None
        (bits,) = struct.unpack("<I", data[21:25])
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if kind == b"VP8X":
        if len(data) < _WEBP_VP8X_END:
            return None
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return width, height
    return None


def check_vision_head(method: str, query: str, content_encoding: str) -> str | None:
    """Проверка до чтения тела: метод, query-строка, кодирование.

    Returns:
        None или код причины отказа.
    """
    if method.upper() != "POST":
        return REASON_METHOD
    if query:
        return REASON_QUERY
    if content_encoding.strip().lower() not in ("", "identity"):
        return REASON_ENCODING
    return None


def _text_blocks(content: Any) -> list[str] | None:
    """Тексты system: строка либо непустой список блоков строго {type: text, text: str}."""
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list) or not content or len(content) > VISION_MAX_TEXT_BLOCKS:
        return None
    out: list[str] = []
    for block in content:
        if not isinstance(block, dict) or set(block) - ALLOWED_TEXT_BLOCK_KEYS:
            return None
        if block.get("type") != TEXT_BLOCK_TYPE or not isinstance(block.get("text"), str):
            return None
        out.append(block["text"])
    return out


def _check_image_block(block: Mapping[str, Any], limits: VisionLimits) -> ImageMeta | str:
    """Проверяет блок image: ключи, mime, base64, размер, формат и размеры в пикселях.

    Returns:
        ImageMeta при успехе, иначе код причины.
    """
    if set(block) - ALLOWED_IMAGE_BLOCK_KEYS:
        return REASON_IMAGE_BLOCK
    source = block.get("source")
    if not isinstance(source, dict) or set(source) != ALLOWED_SOURCE_KEYS:
        return REASON_IMAGE_BLOCK
    if source.get("type") != SOURCE_TYPE_BASE64:
        return REASON_IMAGE_BLOCK
    mime = source.get("media_type")
    if not isinstance(mime, str) or mime not in ALLOWED_MIME:
        return REASON_IMAGE_MIME
    encoded = source.get("data")
    if not isinstance(encoded, str) or not encoded:
        return REASON_IMAGE_BASE64
    if len(encoded) > limits.max_image_b64_bytes:
        return REASON_IMAGE_SIZE
    try:
        # Только ASCII-алфавит base64: ни пробелов, ни url-safe символов, ни переводов строки
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        return REASON_IMAGE_BASE64
    # Каноническая запись: лишний padding и ненулевые хвостовые биты декодер терпит, а мы нет
    if base64.b64encode(raw).decode("ascii") != encoded:
        return REASON_IMAGE_BASE64
    dims = image_dimensions(mime, raw)
    if dims is None:
        # Заявленный mime не совпал с содержимым либо заголовок повреждён
        return REASON_IMAGE_FORMAT
    width, height = dims
    if width < 1 or height < 1 or max(width, height) > limits.max_image_side:
        return REASON_IMAGE_DIMENSIONS
    digest = hashlib.sha256(raw).hexdigest()[:LOG_HASH_PREFIX_CHARS]
    return ImageMeta(mime=mime, size=len(raw), sha256_prefix=digest, width=width, height=height)


def check_vision_request(
    method: str,
    query: str,
    content_encoding: str,
    body: bytes,
    limits: VisionLimits | None = None,
    allowed_models: frozenset[str] | None = None,
) -> VisionVerdict:
    """Проверяет запрос зрения целиком (форма, картинки, ПДн в тексте).

    Args:
        method: HTTP-метод.
        query: Строка запроса без `?`.
        content_encoding: Значение заголовка Content-Encoding.
        body: Тело запроса.
        limits: Пределы (по умолчанию из значений по умолчанию).
        allowed_models: Допустимые значения model (None - любая строка до 128 символов).

    Returns:
        Вердикт: reason=None и пустой pii_types - запрос можно пересылать. Если в тексте
        найдены ПДн, reason == "pii" и заполнен pii_types (только имена категорий).
    """
    limits = limits or VisionLimits()
    head = check_vision_head(method, query, content_encoding)
    if head is not None:
        return VisionVerdict(reason=head)
    if len(body) > limits.max_body_bytes:
        return VisionVerdict(reason=REASON_SIZE)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return VisionVerdict(reason=REASON_NOT_JSON)
    if not isinstance(data, dict):
        return VisionVerdict(reason=REASON_NOT_JSON)
    # Инструменты запрещены полностью: ключ не должен быть даже пустым списком
    if "tools" in data:
        return VisionVerdict(reason=REASON_TOOLS)
    if "tool_choice" in data:
        return VisionVerdict(reason=REASON_TOOL_CHOICE)
    if "stream" in data:
        return VisionVerdict(reason=REASON_STREAM)
    if not set(data) <= ALLOWED_TOP_KEYS:
        return VisionVerdict(reason=REASON_KEYS)
    if not _params_ok(data, allowed_models):
        return VisionVerdict(reason=REASON_PARAMS)
    return _check_messages(data, limits)


def _check_messages(data: Mapping[str, Any], limits: VisionLimits) -> VisionVerdict:
    """Сообщение user с блоками image/text и необязательный system."""
    messages = data.get("messages")
    if not isinstance(messages, list) or len(messages) != 1:
        return VisionVerdict(reason=REASON_MESSAGES)
    message = messages[0]
    if not isinstance(message, dict) or set(message) - {"role", "content"}:
        return VisionVerdict(reason=REASON_MESSAGES)
    content = message.get("content")
    if message.get("role") != USER_ROLE or not isinstance(content, list) or not content:
        return VisionVerdict(reason=REASON_MESSAGES)
    texts: list[str] = []
    images: list[ImageMeta] = []
    for block in content:
        if not isinstance(block, dict):
            return VisionVerdict(reason=REASON_MESSAGES)
        kind = block.get("type")
        if kind == TEXT_BLOCK_TYPE:
            parsed = _text_blocks([block])
            if parsed is None:
                return VisionVerdict(reason=REASON_MESSAGES)
            texts.extend(parsed)
        elif kind == IMAGE_BLOCK_TYPE:
            if len(images) >= limits.max_images:
                return VisionVerdict(reason=REASON_IMAGE_COUNT)
            result = _check_image_block(block, limits)
            if isinstance(result, str):
                return VisionVerdict(reason=result)
            images.append(result)
        else:
            return VisionVerdict(reason=REASON_MESSAGES)
    if not images:
        return VisionVerdict(reason=REASON_IMAGE_COUNT)
    if len(texts) > VISION_MAX_TEXT_BLOCKS:
        return VisionVerdict(reason=REASON_MESSAGES)
    system = data.get("system")
    if system is not None:
        system_texts = _text_blocks(system)
        if system_texts is None:
            return VisionVerdict(reason=REASON_PARAMS)
        texts.extend(system_texts)
    if sum(len(t.encode("utf-8")) for t in texts) > VISION_MAX_TEXT_BYTES:
        return VisionVerdict(reason=REASON_TEXT_SIZE, images=images)
    found: set[str] = set()
    # Ещё и склейка: число, разрезанное между блоками, иначе прошло бы незамеченным
    for text in (*texts, "\n".join(texts)):
        found |= find_pii_types(text)
    findings = split_findings(found)
    if findings.blocking:
        return VisionVerdict(
            reason=REASON_PII, pii_types=findings.blocking,
            observed_types=findings.observed, images=images,
        )
    return VisionVerdict(observed_types=findings.observed, images=images)
