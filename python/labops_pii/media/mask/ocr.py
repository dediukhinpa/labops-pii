"""OCR через Tesseract: слова с координатами и уверенностью.

Tesseract вызывается подпроцессом, картинка передаётся через stdin в PNG (на диск ничего не
пишется, чтобы изображение с ПДн не оставалось во временных файлах).
"""

from __future__ import annotations

import io
import logging
import os
import subprocess
from dataclasses import dataclass

from PIL import Image

logger = logging.getLogger(__name__)

# Уровень «слово» в TSV Tesseract
TSV_LEVEL_WORD = 5
TSV_COLUMNS = 12
# Колонки TSV: level page block par line word left top width height conf text
COL_BLOCK, COL_PAR, COL_LINE = 2, 3, 4
COL_LEFT, COL_TOP, COL_WIDTH, COL_HEIGHT, COL_CONF, COL_TEXT = 6, 7, 8, 9, 10, 11
# Режим сегментации страницы: 3 - автоматический, без OSD (документ и фото с блоками текста)
PSM_AUTO = "3"
# Режим «только ориентация и письмо» и языковые данные для него
PSM_OSD = "0"
LANG_OSD = "osd"
# Ниже этой уверенности OSD поворот не применяется (на коротком тексте OSD ошибается)
MIN_ORIENTATION_CONF = 1.5
ROTATE_PREFIX = "Rotate:"
ORIENTATION_CONF_PREFIX = "Orientation confidence:"
# Один поток OpenMP: параллелизм даёт семафор сервиса, а не потоки одного OCR
OMP_THREADS = "1"


class OcrError(Exception):
    """Tesseract не смог обработать изображение (сбой, таймаут, нет бинаря)."""


@dataclass(frozen=True, slots=True)
class OcrWord:
    """Распознанное слово.

    Attributes:
        text: Текст слова.
        left: Левая граница, пикселей исходного изображения.
        top: Верхняя граница.
        width: Ширина.
        height: Высота.
        conf: Уверенность Tesseract 0..100.
        line_key: (блок, абзац, строка): слова одной строки имеют один ключ.
    """

    text: str
    left: int
    top: int
    width: int
    height: int
    conf: float
    line_key: tuple[int, int, int]


def parse_tsv(tsv: str, scale: float = 1.0) -> list[OcrWord]:
    """Разбирает вывод `tesseract ... tsv` в список слов.

    Args:
        tsv: Текст TSV.
        scale: Во сколько раз OCR-картинка больше исходной; координаты делятся на него.

    Returns:
        Слова в порядке чтения Tesseract (пустые и нетекстовые строки отброшены).
    """
    words: list[OcrWord] = []
    for row in tsv.splitlines()[1:]:
        cols = row.split("\t", TSV_COLUMNS - 1)
        if len(cols) < TSV_COLUMNS or int(cols[0]) != TSV_LEVEL_WORD:
            continue
        text = cols[COL_TEXT].strip()
        if not text:
            continue
        left, top = int(cols[COL_LEFT]) / scale, int(cols[COL_TOP]) / scale
        width, height = int(cols[COL_WIDTH]) / scale, int(cols[COL_HEIGHT]) / scale
        words.append(
            OcrWord(
                text=text,
                left=int(left),
                top=int(top),
                width=max(1, round(width)),
                height=max(1, round(height)),
                conf=float(cols[COL_CONF]),
                line_key=(int(cols[COL_BLOCK]), int(cols[COL_PAR]), int(cols[COL_LINE])),
            )
        )
    return words


def parse_osd(text: str) -> int:
    """Достаёт поворот из вывода `--psm 0`; при низкой уверенности или мусоре возвращает 0."""
    rotate = 0
    confidence = 0.0
    for line in text.splitlines():
        try:
            if line.startswith(ROTATE_PREFIX):
                rotate = int(line[len(ROTATE_PREFIX):].strip())
            elif line.startswith(ORIENTATION_CONF_PREFIX):
                confidence = float(line[len(ORIENTATION_CONF_PREFIX):].strip())
        except ValueError:
            return 0
    return rotate if confidence >= MIN_ORIENTATION_CONF and rotate in (90, 180, 270) else 0


class TesseractOcr:
    """Обёртка над бинарём tesseract.

    Args:
        cmd: Путь к бинарю или имя в PATH.
        langs: Языки через «+».
        timeout_s: Предел времени одного запуска.
        tessdata: Каталог данных (TESSDATA_PREFIX) или None.
    """

    def __init__(
        self, cmd: str, langs: str, timeout_s: float, tessdata: str | None = None
    ) -> None:
        self._cmd = cmd
        self._langs = langs
        self._timeout_s = timeout_s
        self._env = {**os.environ, "OMP_THREAD_LIMIT": OMP_THREADS}
        if tessdata:
            self._env["TESSDATA_PREFIX"] = tessdata

    def check_ready(self) -> None:
        """Проверяет, что бинарь запускается и нужные языки установлены.

        Raises:
            OcrError: Бинаря нет или языка не хватает.
        """
        try:
            done = subprocess.run(
                [self._cmd, "--list-langs"],
                capture_output=True, text=True, timeout=self._timeout_s, env=self._env,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OcrError(f"tesseract не запускается: {type(exc).__name__}") from exc
        have = set(done.stdout.split()) | set(done.stderr.split())
        missing = [lang for lang in self._langs.split("+") if lang not in have]
        if done.returncode != 0 or missing:
            raise OcrError(f"tesseract: нет языков {','.join(missing) or '?'}")

    def detect_rotation(self, image: Image.Image) -> int:
        """Определяет, на сколько градусов по часовой стрелке повернуть картинку, чтобы текст
        стал горизонтальным (0, 90, 180 или 270).

        Без этого повёрнутый текст не читается OCR и остаётся незакрашенным. Если текста мало
        или уверенность низка, возвращает 0.

        Raises:
            OcrError: Tesseract не запускается или завис.
        """
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        try:
            done = subprocess.run(
                [self._cmd, "stdin", "stdout", "--psm", PSM_OSD, "-l", LANG_OSD],
                input=buf.getvalue(), capture_output=True, timeout=self._timeout_s,
                env=self._env, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OcrError("tesseract osd: таймаут") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise OcrError(f"tesseract не запускается: {type(exc).__name__}") from exc
        if done.returncode != 0:
            # «Too few characters»: ориентацию определить не по чему
            return 0
        return parse_osd(done.stdout.decode("utf-8", "replace"))

    def recognize(self, image: Image.Image, scale: float = 1.0) -> list[OcrWord]:
        """Распознаёт слова на изображении.

        Args:
            image: Картинка (RGB или L), уже масштабированная для OCR.
            scale: Во сколько раз она больше исходной (для обратного пересчёта координат).

        Raises:
            OcrError: Сбой Tesseract.
        """
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        try:
            done = subprocess.run(
                [self._cmd, "stdin", "stdout", "-l", self._langs, "--psm", PSM_AUTO, "tsv"],
                input=buf.getvalue(),
                capture_output=True,
                timeout=self._timeout_s,
                env=self._env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OcrError("tesseract: таймаут") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise OcrError(f"tesseract не запускается: {type(exc).__name__}") from exc
        if done.returncode != 0:
            # stderr может содержать лишнее; в лог/ошибку идёт только код возврата
            raise OcrError(f"tesseract: код {done.returncode}")
        try:
            return parse_tsv(done.stdout.decode("utf-8"), scale)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OcrError("tesseract: непонятный вывод") from exc
