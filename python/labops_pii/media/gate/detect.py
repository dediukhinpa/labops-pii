"""Детектор текста на картинке через бинарь Tesseract (только «есть ли текст», не распознавание).

Зачем: ядру нужно решить, отправлять ли картинку-вложение в модель зрения. Распознанный текст
наружу не отдаётся и не логируется: ответ - одно из `no_text`, `text`, `not_recognized`.

Принципы:
- Tesseract вызывается отдельным процессом (`subprocess`, без shell, картинка идёт в stdin,
  временных файлов нет), новых pip-зависимостей нет.
- Картинка предварительно декодируется Pillow (проверка формата и числа пикселей, EXIF-поворот,
  градации серого) и передаётся в Tesseract как PNG: ориентацию Tesseract сам не читает.
- Любой сбой (нет бинаря, таймаут, ненулевой код, не декодируется) - `not_recognized`
  (fail closed), исключения наружу не выходят. Процесс по таймауту убивается.
- Число одновременных задач ограничено (`OcrGate`), очередь ожидания тоже: при переполнении
  вызывающий получает `OcrBusyError` (API отвечает 503 с Retry-After).
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from PIL import Image, ImageOps

from labops_pii.media.gate.normalize import (
    DETAIL_TOO_BIG_BYTES,
    DETAIL_TOO_BIG_PIXELS,
    ImageCorruptError,
    ImageLimits,
    ImageTooLargeError,
    ImageUnsupportedError,
    open_image,
)

logger = logging.getLogger(__name__)

RESULT_TEXT = "text"
RESULT_NO_TEXT = "no_text"
RESULT_NOT_RECOGNIZED = "not_recognized"

DEFAULT_BIN = "tesseract"
DEFAULT_LANGS = "rus+eng"
# Значимых слов, начиная с которых картинка считается «с текстом»
DEFAULT_MIN_WORDS = 3
# Уверенность Tesseract (0-100), с которой слово засчитывается
DEFAULT_MIN_CONF = 40
# Слово - не короче стольких буквенно-цифровых символов (отсекает шум вида «|», «-», «,»)
DEFAULT_MIN_WORD_CHARS = 2
DEFAULT_CONCURRENCY = 1
# Сколько запросов может ждать слот (сверх выполняющихся); остальные сразу получают 503
DEFAULT_QUEUE_MAX = 4
# Сколько мс запрос ждёт слот, прежде чем получить 503
DEFAULT_QUEUE_WAIT_MS = 5_000
DEFAULT_TIMEOUT_MS = 15_000
# Пикселей на входе (меньше общего предела картинок: Tesseract на 40 Мп слишком долог)
DEFAULT_MAX_PIXELS = 20_000_000
# Что отдаём клиенту в Retry-After при переполнении очереди, секунд
RETRY_AFTER_SECONDS = 5
MS_IN_SECOND = 1000
# Форматы входа детектора (MPO - jpeg с несколькими кадрами у телефонов)
ALLOWED_INPUT_FORMATS = frozenset({"JPEG", "MPO", "PNG", "WEBP"})
# Колонки tsv-вывода Tesseract: level page block par line word left top width height conf text
TSV_COLUMNS = 12
TSV_LEVEL_WORD = "5"
TSV_CONF_INDEX = 10
TSV_TEXT_INDEX = 11
PNG_COMPRESS_LEVEL = 1
WHITE = (255, 255, 255)
ALPHA_MODES = ("RGBA", "LA", "PA")
# Переменные окружения дочернего процесса: только нужные ему, секреты сервиса не передаются
CHILD_ENV_PASSTHROUGH = ("PATH", "TESSDATA_PREFIX", "LD_LIBRARY_PATH")
DETAIL_UNSUPPORTED = "формат не поддержан: нужны jpeg, png или webp"


class OcrBusyError(Exception):
    """Очередь Tesseract переполнена или слот не освободился вовремя."""


@dataclass(frozen=True)
class OcrSettings:
    """Настройки детектора текста (`DOCUMENTS_OCR_*`).

    Attributes:
        binary: Путь или имя бинаря tesseract.
        langs: Языки для `-l` (например, `rus+eng`).
        min_words: Сколько значимых слов нужно для ответа `text`.
        min_conf: Минимальная уверенность слова (0-100).
        min_word_chars: Минимум буквенно-цифровых символов в значимом слове.
        concurrency: Сколько процессов Tesseract работает одновременно.
        queue_max: Сколько запросов может ждать слот.
        queue_wait_ms: Сколько мс запрос ждёт слот до ответа 503.
        timeout_ms: Таймаут процесса Tesseract, мс (по истечении процесс убивается).
        max_pixels: Предел числа пикселей картинки для детектора.
    """

    binary: str = DEFAULT_BIN
    langs: str = DEFAULT_LANGS
    min_words: int = DEFAULT_MIN_WORDS
    min_conf: float = DEFAULT_MIN_CONF
    min_word_chars: int = DEFAULT_MIN_WORD_CHARS
    concurrency: int = DEFAULT_CONCURRENCY
    queue_max: int = DEFAULT_QUEUE_MAX
    queue_wait_ms: int = DEFAULT_QUEUE_WAIT_MS
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    max_pixels: int = DEFAULT_MAX_PIXELS

    def __post_init__(self) -> None:
        """Отсекает значения, при которых детектор работать не может."""
        for name in ("min_words", "min_word_chars", "concurrency", "timeout_ms", "max_pixels"):
            if getattr(self, name) < 1:
                raise ValueError(f"DOCUMENTS_OCR: {name} должен быть не меньше 1")
        for name in ("queue_max", "queue_wait_ms"):
            if getattr(self, name) < 0:
                raise ValueError(f"DOCUMENTS_OCR: {name} не может быть отрицательным")
        if not self.binary or not self.langs:
            raise ValueError("DOCUMENTS_OCR: бинарь и языки не могут быть пустыми")


def load_ocr_settings() -> OcrSettings:
    """Читает настройки детектора из окружения (`DOCUMENTS_OCR_*`)."""
    env = os.environ
    return OcrSettings(
        binary=env.get("DOCUMENTS_OCR_BIN", DEFAULT_BIN),
        langs=env.get("DOCUMENTS_OCR_LANGS", DEFAULT_LANGS),
        min_words=int(env.get("DOCUMENTS_OCR_MIN_WORDS", DEFAULT_MIN_WORDS)),
        min_conf=float(env.get("DOCUMENTS_OCR_MIN_CONF", DEFAULT_MIN_CONF)),
        min_word_chars=int(env.get("DOCUMENTS_OCR_MIN_WORD_CHARS", DEFAULT_MIN_WORD_CHARS)),
        concurrency=int(env.get("DOCUMENTS_OCR_CONCURRENCY", DEFAULT_CONCURRENCY)),
        queue_max=int(env.get("DOCUMENTS_OCR_QUEUE_MAX", DEFAULT_QUEUE_MAX)),
        queue_wait_ms=int(env.get("DOCUMENTS_OCR_QUEUE_WAIT_MS", DEFAULT_QUEUE_WAIT_MS)),
        timeout_ms=int(env.get("DOCUMENTS_OCR_TIMEOUT_MS", DEFAULT_TIMEOUT_MS)),
        max_pixels=int(env.get("DOCUMENTS_OCR_MAX_PIXELS", DEFAULT_MAX_PIXELS)),
    )


class OcrGate:
    """Ограничитель параллелизма Tesseract с ограниченной очередью ожидания."""

    def __init__(self, settings: OcrSettings) -> None:
        self._settings = settings
        self._sem = asyncio.Semaphore(settings.concurrency)
        self._waiting = 0

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Занимает слот; `OcrBusyError`, если очередь полна или ждать пришлось слишком долго."""
        if self._sem.locked():
            if self._waiting >= self._settings.queue_max:
                raise OcrBusyError("очередь распознавания переполнена")
            self._waiting += 1
            try:
                await asyncio.wait_for(
                    self._sem.acquire(), self._settings.queue_wait_ms / MS_IN_SECOND
                )
            except TimeoutError as exc:
                raise OcrBusyError("слот распознавания не освободился вовремя") from exc
            finally:
                self._waiting -= 1
        else:
            await self._sem.acquire()
        try:
            yield
        finally:
            self._sem.release()


def count_significant_words(tsv: str, settings: OcrSettings) -> int:
    """Считает слова уровня 5 tsv с уверенностью не ниже порога и достаточной длиной."""
    count = 0
    for line in tsv.splitlines():
        parts = line.split("\t")
        if len(parts) < TSV_COLUMNS or parts[0] != TSV_LEVEL_WORD:
            continue
        try:
            conf = float(parts[TSV_CONF_INDEX])
        except ValueError:
            continue
        word = parts[TSV_TEXT_INDEX]
        significant = sum(1 for ch in word if ch.isalnum())
        if conf >= settings.min_conf and significant >= settings.min_word_chars:
            count += 1
    return count


def _prepare_png(data: bytes, limits: ImageLimits, settings: OcrSettings) -> bytes:
    """Декодирует картинку и готовит PNG в градациях серого для Tesseract.

    Raises:
        ImageUnsupportedError: Формат не jpeg/png/webp.
        ImageTooLargeError: Файл или число пикселей выше лимита.
        ImageCorruptError: Заголовок не читается.
        OSError: Тело картинки не декодируется (обрабатывается как `not_recognized`).
    """
    image = open_image(data, limits)
    try:
        if image.format not in ALLOWED_INPUT_FORMATS:
            raise ImageUnsupportedError(DETAIL_UNSUPPORTED)
        width, height = image.size
        if width * height > settings.max_pixels:
            raise ImageTooLargeError(DETAIL_TOO_BIG_PIXELS)
        image.seek(0)
        image.load()
        work = ImageOps.exif_transpose(image)
        if work.mode in ALPHA_MODES or (work.mode == "P" and "transparency" in work.info):
            # Прозрачность - на белый фон, иначе чёрный текст на прозрачном станет невидимым
            rgba = work.convert("RGBA")
            flat = Image.new("RGB", rgba.size, WHITE)
            flat.paste(rgba, mask=rgba.getchannel("A"))
            work = flat
        gray = work.convert("L")
        buffer = io.BytesIO()
        gray.save(buffer, "PNG", compress_level=PNG_COMPRESS_LEVEL)
        return buffer.getvalue()
    finally:
        image.close()


def check_input(data: bytes, limits: ImageLimits) -> None:
    """Дешёвая проверка заголовка до очереди: ошибки запроса не должны ждать слот.

    Raises:
        ImageUnsupportedError: Формат не jpeg/png/webp.
        ImageTooLargeError: Файл больше лимита байт (лишние пиксели - не ошибка, см. detect_text).
        ImageCorruptError: Заголовок не читается.
    """
    try:
        image = open_image(data, limits)
    except ImageTooLargeError as exc:
        if str(exc) == DETAIL_TOO_BIG_BYTES:
            raise
        return
    try:
        if image.format not in ALLOWED_INPUT_FORMATS:
            raise ImageUnsupportedError(DETAIL_UNSUPPORTED)
    finally:
        image.close()


def _child_env() -> dict[str, str]:
    """Окружение процесса Tesseract: один поток OpenMP и только нужные переменные."""
    env = {k: os.environ[k] for k in CHILD_ENV_PASSTHROUGH if k in os.environ}
    env["OMP_THREAD_LIMIT"] = "1"
    return env


def run_tesseract(png: bytes, settings: OcrSettings) -> str | None:
    """Запускает Tesseract (stdin -> tsv на stdout); None при любом сбое.

    Процесс убивается по таймауту. Содержимое вывода и картинки не логируется.
    """
    cmd = [settings.binary, "stdin", "stdout", "-l", settings.langs, "tsv"]
    try:
        proc = subprocess.Popen(  # noqa: S603 - shell не используется, аргументы фиксированы
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=_child_env(), shell=False,
        )
    except OSError:
        logger.warning("tesseract не запускается (бинарь не найден или нет прав)")
        return None
    try:
        out, _ = proc.communicate(png, timeout=settings.timeout_ms / MS_IN_SECOND)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        logger.warning("tesseract прерван по таймауту")
        return None
    except OSError:
        proc.kill()
        proc.wait()
        logger.warning("ошибка обмена с tesseract")
        return None
    if proc.returncode != 0:
        logger.warning("tesseract завершился с кодом %s", proc.returncode)
        return None
    return out.decode("utf-8", errors="replace")


def detect_text(data: bytes, limits: ImageLimits, settings: OcrSettings) -> str:
    """Возвращает `text`, `no_text` или `not_recognized` для байтов картинки.

    Args:
        data: Байты картинки jpeg/png/webp.
        limits: Лимиты картинок (размер файла, пиксели).
        settings: Настройки детектора.

    Raises:
        ImageUnsupportedError: Формат не поддержан.
        ImageTooLargeError: Файл больше лимита байт (слишком много пикселей - не ошибка
            запроса, а `not_recognized`).
        ImageCorruptError: Заголовок не читается.
    """
    try:
        png = _prepare_png(data, limits, settings)
    except ImageTooLargeError as exc:
        # Файл больше лимита байт - ошибка запроса (413); лишние пиксели - не распознали
        if str(exc) == DETAIL_TOO_BIG_BYTES:
            raise
        return RESULT_NOT_RECOGNIZED
    except (OSError, ValueError, SyntaxError, EOFError, Image.DecompressionBombError):
        return RESULT_NOT_RECOGNIZED
    tsv = run_tesseract(png, settings)
    if tsv is None:
        return RESULT_NOT_RECOGNIZED
    if count_significant_words(tsv, settings) >= settings.min_words:
        return RESULT_TEXT
    return RESULT_NO_TEXT


__all__ = [
    "ImageCorruptError", "OcrBusyError", "OcrGate", "OcrSettings", "RESULT_NOT_RECOGNIZED",
    "RESULT_NO_TEXT", "RESULT_TEXT", "RETRY_AFTER_SECONDS", "check_input", "detect_text",
    "load_ocr_settings",
]
