"""Поиск «технических» токенов (слова через «_», имена файлов, пути) за линейное время.

Прежний единый шаблон TECH_RE давал квадратичное время на длинных словах (до 35 с на
80 тыс. символов) и экспоненциальное на цепочках вида `a.b_b_b_...` (S-03). Здесь четыре
альтернативы шаблона считаются по отдельности по «областям» (максимальным цепочкам
допустимых символов), а результат собирается по правилу исходного шаблона: побеждает
самое левое начало, при равном начале — альтернатива с меньшим номером. Провал на начале
области означает провал на любом начале внутри неё, поэтому каждая область разбирается
один раз. Эквивалентность старому шаблону проверяется в tests/test_tech_tokens.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

FILE_EXTENSIONS = (
    "xlsx|xls|xlsm|csv|tsv|docx|doc|dotx|pdf|pptx|ppt|txt|md|rtf|odt|ods|json|xml|html|htm|"
    "zip|rar|7z|png|jpe?g|gif|msg|eml"
)

# Альтернатива 1: слово с «_» (плюс «.слово» хвосты)
_UNDERSCORE_RUN_RE = re.compile(r"[\w\-]+")
_UNDERSCORE_TOKEN_RE = re.compile(r"[\w\-]*_[\w\-]*(?:\.[\w\-]+)*")
# Альтернатива 2: имя файла с известным расширением
_FILE_REGION_RE = re.compile(r"[\w\-]+(?:\.[\w\-]+)*")
_EXT_RE = re.compile(rf"\.(?:{FILE_EXTENSIONS})(?![\w])", re.IGNORECASE)
_NAME_CHARS = re.compile(r"[\w\-]")
# Альтернатива 3: путь с корня
_ROOTED_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|~?/|\.{1,2}/)[^\s\"'<>|?*]*"
)
# Альтернатива 4: путь из 3+ сегментов
_SEGMENT_REGION_RE = re.compile(r"[\w.\-]+(?:[/\\][\w.\-]+)*")
_SEGMENT_PATH_RE = re.compile(r"[\w.\-]+(?:[/\\][\w.\-]+){2,}")

Span = tuple[int, int]


@dataclass(slots=True)
class _Finder:
    """Ленивый поиск следующего совпадения одной альтернативы с кэшем кандидата.

    Attributes:
        cached: Последний найденный кандидат.
        exhausted: Совпадений правее больше нет (верно и для любой позиции правее).
    """

    cached: Span | None = None
    exhausted: bool = False


def _find_underscore(text: str, pos: int) -> Span | None:
    """Ближайшее слово с «_» не левее pos (с хвостом из «.слово»)."""
    for run in _UNDERSCORE_RUN_RE.finditer(text, pos):
        if text.find("_", run.start(), run.end()) != -1:
            m = _UNDERSCORE_TOKEN_RE.match(text, run.start())
            if m is not None:
                return m.start(), m.end()
    return None


def _find_filename(text: str, pos: int) -> Span | None:
    """Ближайшее имя файла с расширением не левее pos."""
    for region in _FILE_REGION_RE.finditer(text, pos):
        start, end = region.start(), region.end()
        if text.find(".", start, end) == -1:
            continue
        # Жадный шаблон берёт самую правую точку расширения, перед которой стоит символ имени
        best: int | None = None
        for ext in _EXT_RE.finditer(text, start, end):
            if ext.start() > start and _NAME_CHARS.match(text, ext.start() - 1):
                best = ext.end()
        if best is not None:
            return start, best
    return None


def _find_rooted_path(text: str, pos: int) -> Span | None:
    """Ближайший путь, начинающийся с корня (`/`, `~/`, `./`, `C:\\`)."""
    m = _ROOTED_PATH_RE.search(text, pos)
    return (m.start(), m.end()) if m else None


def _find_segment_path(text: str, pos: int) -> Span | None:
    """Ближайший путь из трёх и более сегментов."""
    for region in _SEGMENT_REGION_RE.finditer(text, pos):
        seps = text.count("/", region.start(), region.end()) + text.count(
            "\\", region.start(), region.end()
        )
        if seps < 2:  # noqa: PLR2004 - три сегмента = два разделителя
            continue
        m = _SEGMENT_PATH_RE.match(text, region.start())
        if m is not None:
            return m.start(), m.end()
    return None


_FINDERS = (_find_underscore, _find_filename, _find_rooted_path, _find_segment_path)


def find_tech_spans(text: str) -> list[Span]:
    """Находит диапазоны технических токенов (слова через «_», имена файлов, пути).

    Args:
        text: Исходный текст.

    Returns:
        Непересекающиеся диапазоны (начало, конец) по порядку; время линейно по длине текста.
    """
    states = [_Finder() for _ in _FINDERS]
    spans: list[Span] = []
    pos = 0
    while pos < len(text):
        best: Span | None = None
        for state, finder in zip(states, _FINDERS):
            if state.exhausted:
                continue
            if state.cached is None or state.cached[0] < pos:
                state.cached = finder(text, pos)
                if state.cached is None:
                    state.exhausted = True
                    continue
            if best is None or state.cached[0] < best[0]:
                best = state.cached
        if best is None:
            break
        spans.append(best)
        pos = best[1]
    return spans
