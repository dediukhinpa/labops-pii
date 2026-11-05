"""Белый список слов, которые не являются ПДн (названия проектов и т.п.).

Механизм общий для сервиса и guard и не зашит в шаблоны: список слов задаётся профилем
(`Profile.allowed_words`) и расширяется переменной PII_ALLOWED_WORDS (через запятую).
Слово записывается основой («прагматик»; так же в PII_ALLOWED_WORDS). Допустимы любые
падежные формы: основа плюс до ALLOWED_ENDING_MAX букв окончания («Прагматика»,
«Прагматике», «Прагматикой»), в кавычках и без. Совпадать должно слово целиком;
«Прагматик Иванов» белым списком не покрывается, потому что в находке есть чужое слово.
"""

from __future__ import annotations

import os
import re

from labops_pii.profiles import get_profile

ALLOWED_WORDS_ENV = "PII_ALLOWED_WORDS"
# Падежное окончание после основы: «прагматик» + «а/у/е/ой/ами/...»
ALLOWED_ENDING_MAX = 3
WORD_RE = re.compile(r"[А-Яа-яЁёA-Za-z]+(?:-[А-Яа-яЁёA-Za-z]+)*")


def allowed_stems() -> tuple[str, ...]:
    """Основы разрешённых слов: профиль плюс переменная окружения (нижний регистр)."""
    extra = [w.strip() for w in os.environ.get(ALLOWED_WORDS_ENV, "").split(",")]
    stems = (*get_profile().allowed_words, *(w for w in extra if w))
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
    """Заменяет разрешённые слова пробелами той же длины (позиции остальных не сдвигаются)."""
    stems = allowed_stems()
    if not stems:
        return text
    return WORD_RE.sub(
        lambda m: " " * len(m.group()) if is_allowed_word(m.group(), stems) else m.group(),
        text,
    )
