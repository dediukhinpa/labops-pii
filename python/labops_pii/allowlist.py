"""Белый список слов, которые не являются ПДн (названия проектов и т.п.).

Механизм общий для сервиса и guard и не зашит в код: список слов по умолчанию пуст, слова
задаёт только переменная PII_ALLOWED_WORDS (основы через запятую).
Слово записывается основой (пример: «вектрик»; так же в PII_ALLOWED_WORDS). Допустимы любые
падежные формы: основа плюс до ALLOWED_ENDING_MAX букв окончания («Вектрика»,
«Вектрике», «Вектрикой»), в кавычках и без. Совпадать должно слово целиком;
«Вектрик Иванов» белым списком не покрывается, потому что в находке есть чужое слово.
"""

from __future__ import annotations

import os
import re


ALLOWED_WORDS_ENV = "PII_ALLOWED_WORDS"
# Слов по умолчанию нет: название проекта потребитель задаёт в PII_ALLOWED_WORDS
ALLOWED_WORDS_DEFAULT: tuple[str, ...] = ()
# Падежное окончание после основы: «вектрик» + «а/у/е/ой/ами/...»
ALLOWED_ENDING_MAX = 3
# Притяжательные квантификаторы (++, *+): после слова ничего не следует, откат не нужен, а обычный
# (?:...)* копит в памяти стек отката на каждый дефис («a-a-a-…» из миллионов слов: сотни МиБ)
WORD_RE = re.compile(r"[А-Яа-яЁёA-Za-z]++(?:-[А-Яа-яЁёA-Za-z]++)*+")
# Инициал вплотную перед словом: заглавная буква и точка («С.»)
GLUED_INITIAL_RE = re.compile(r"[А-ЯЁA-Z]\.")
GLUED_INITIAL_LEN = 2


def allowed_stems() -> tuple[str, ...]:
    """Основы разрешённых слов из PII_ALLOWED_WORDS (нижний регистр, без повторов)."""
    extra = [w.strip() for w in os.environ.get(ALLOWED_WORDS_ENV, "").split(",")]
    stems = (*ALLOWED_WORDS_DEFAULT, *(w for w in extra if w))
    return tuple(dict.fromkeys(s.lower().replace("ё", "е") for s in stems))


def is_allowed_word(word: str, stems: tuple[str, ...] | None = None) -> bool:
    """Слово — разрешённое (основа + падежное окончание)."""
    low = word.lower().replace("ё", "е")
    for stem in stems if stems is not None else allowed_stems():
        if low.startswith(stem) and len(low) - len(stem) <= ALLOWED_ENDING_MAX:
            return True
    return False


def is_allowed_fragment(fragment: str) -> bool:
    """Все слова фрагмента разрешённые (кавычки и знаки вокруг не мешают); пустой — нет."""
    stems = allowed_stems()
    if not stems:
        return False
    words = WORD_RE.findall(fragment)
    return bool(words) and all(is_allowed_word(w, stems) for w in words)


def strip_allowed_words(text: str) -> str:
    """Заменяет разрешённые слова пробелами той же длины (позиции остальных не сдвигаются).

    Проход потоковый: результат собирается из срезов исходной строки между найденными словами,
    список символов не создаётся, пик памяти линеен от длины текста с малой константой.
    """
    stems = allowed_stems()
    if not stems:
        return text
    # Длиннее основы + окончания слово разрешённым быть не может: копию слова не делаем
    max_word_len = max(len(s) for s in stems) + ALLOWED_ENDING_MAX
    parts: list[str] = []
    pos = 0  # всё левее pos уже перенесено в parts
    for match in WORD_RE.finditer(text):
        word_start, word_end = match.span()
        if word_end - word_start > max_word_len:
            continue
        if not is_allowed_word(match.group(), stems):
            continue
        start = word_start
        # Инициал, приклеенный к разрешённому слову без пробела (марка «С.ОРЛОВЪ»), - часть марки:
        # иначе после затирания слова оставалось «Пектин С.», и guard видел «Фамилия И.»
        glued = text[max(start - GLUED_INITIAL_LEN, 0):start]
        if GLUED_INITIAL_RE.fullmatch(glued) and (
            start == GLUED_INITIAL_LEN or not text[start - GLUED_INITIAL_LEN - 1].isalpha()
        ):
            start -= GLUED_INITIAL_LEN
        start = max(start, pos)  # затёртые ранее позиции не трогаем повторно
        parts.append(text[pos:start])
        parts.append(" " * (word_end - start))
        pos = word_end
    if not parts:
        return text
    parts.append(text[pos:])
    return "".join(parts)
