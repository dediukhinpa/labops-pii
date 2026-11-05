"""ФИО в guard с морфологией (необязательный режим, extras: natasha и pymorphy3).

По умолчанию guard ищет ФИО эвристикой по окончаниям (names.py), без морфологии: образ
шлюза лёгкий. Здесь тот же вопрос («есть ли ФИО») решает детектор псевдонимизатора: он
знает падежи и словари имён и реже срабатывает на обычные слова. Включается переменной
PII_GUARD_NAMES_MORPH=on (по умолчанию для всех профилей выключено) и только вместе с
режимом ФИО не off. Модель грузится лениво при первом вызове.
"""

from __future__ import annotations

import os
import re
import threading
from typing import TYPE_CHECKING

from labops_pii.profiles import get_profile

if TYPE_CHECKING:
    from labops_pii.detector import PiiDetector

NAMES_MORPH_ENV = "PII_GUARD_NAMES_MORPH"
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_LOCK = threading.Lock()
_DETECTOR: PiiDetector | None = None
# Слово находки: буквы, без инициалов-точек и знаков
_WORD_RE = re.compile(r"[A-Za-zА-Яа-яЁё]+")
# Прозвища и порядковые номера правителей: «Петр Первый», «Иван Грозный» - не ПДн клиента
_REGNAL_RE = re.compile(
    r"\b(?:Перв(?:ый|ая)|Втор(?:ой|ая)|Трет(?:ий|ья)|Велик(?:ий|ая)|Грозный|Мудрый|Святой|"
    r"Тишайший|Освободитель|I{1,3}|IV|VI{0,3}|IX|X)\b"
)


def names_morph_enabled() -> bool:
    """Включена ли морфология ФИО (окружение главнее профиля).

    Неизвестное значение трактуется как включённое: морфология только добавляет находки,
    а при сомнении безопаснее найти больше (fail closed).
    """
    raw = os.environ.get(NAMES_MORPH_ENV, "").strip().lower()
    if not raw:
        return get_profile().guard_names_morph
    return raw not in _FALSE


def has_person_morph(text: str) -> bool:
    """Есть ли в тексте ФИО по детектору с морфологией (значения наружу не отдаются)."""
    from labops_pii.detector import PiiDetector, PiiType

    global _DETECTOR
    with _LOCK:
        if _DETECTOR is None:
            _DETECTOR = PiiDetector(mask_addresses=False)
        detector = _DETECTOR
    return any(
        _counts_as_person(text, text[d.start:d.end])
        for d in detector.detect(text)
        if d.pii_type is PiiType.PERSON
    )


def _counts_as_person(text: str, span: str) -> bool:
    """Считается ли находка NER ФИО для guard.

    Замер на names_labels.json: без этого фильтра морфология давала 7 ложных из 130 - одиночные
    имена («Иван», «Позвони Ивану»), фамилия без контекста («Иванов») и правители
    («Петр Первый»). Guard блокирует запрос, поэтому одиночное слово засчитываем, только если
    это фамилия по словарю и она стоит в предложении, а не одна. Из 2+ слов - если два из них
    части ФИО по словарю или есть инициал.
    """
    from labops_pii.morph import name_gramme

    if _REGNAL_RE.search(span):
        return False
    words = _WORD_RE.findall(span)
    if len(words) >= 2:
        # NER склеивает в «ФИО» модели и сорта («Лада Гранта», «Дуб Классик»): нужно минимум
        # два слова-части ФИО по словарю или инициал («Иванов И.»)
        name_words = sum(name_gramme(w) is not None for w in words)
        return name_words >= 2 or any(len(w) == 1 for w in words)
    if not words or len(_WORD_RE.findall(text)) == 1:
        return False
    return name_gramme(words[0]) == "Surn"
