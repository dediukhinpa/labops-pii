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
# Инициал: заглавная буква с точкой, не внутри слова («И.», но не «т.бут» и не «Н-р»)
_INITIAL_RE = re.compile(r"(?<![А-Яа-яЁёA-Za-z])[А-ЯЁA-Z]\.")
# Сколько слов-частей ФИО нужно в находке без инициала
MIN_NAME_WORDS = 2
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

    Правило строже, чем у сервиса: guard блокирует запрос. Замер 05.11.26 на 75 752 названиях
    товаров и поставщиков БД Прагматики: прежнее правило («два слова из словаря» или «одно
    слово с инициалом», одиночная фамилия в предложении) добавляло 396 ложных блокировок -
    сокращения «Н-р»/«т.бут» шли как инициалы, иностранные и нарицательные слова pymorphy
    размечает как имена («Ванджэ», «Фань»), одиночные «фамилии» - сорта и бренды. Теперь:
    инициал - только заглавная буква с точкой рядом с фамилией; иначе нужно два слова-части
    ФИО по словарю, и одно из них - фамилия или отчество. Одиночное слово - не ФИО.
    """
    del text  # контекст строки больше не нужен: одиночное слово не засчитывается
    from labops_pii.morph import name_gramme

    if _REGNAL_RE.search(span):
        return False
    words = [w for w in _WORD_RE.findall(span) if len(w) > 1]
    # ФИО пишут с заглавной; строчные пары NER («флэт уайт», «стрейч мини») - напитки и товары
    if any(not w[0].isupper() for w in words):
        return False
    grams = [name_gramme(w) for w in words]
    if _INITIAL_RE.search(span) and "Surn" in grams:
        return True
    if len(words) < MIN_NAME_WORDS:
        return False
    named = sum(g is not None for g in grams)
    return named >= MIN_NAME_WORDS and any(g in ("Surn", "Patr") for g in grams)
