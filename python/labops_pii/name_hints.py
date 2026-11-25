"""Дополнительные правила поиска ФИО: латиница и значения JSON-полей по ключу.

Natasha NER разбирает только русский текст и не знает контекста полей, поэтому два вида ФИО
уходили в модель открытыми (тесты на HR-данных, 13.11.2026): имя латиницей («Ivanov Ivan»,
«Elena Sidorova») и значение поля карточки `"name": "Иванов Иван"` без остатка закрывалось
лишь у каждого пятого. Модуль даёт чистые функции: позиции находок, без доступа к сервису.
Все регулярные выражения ограничены по длине и идут по тексту один раз (проверено на
враждебных телах: длинные повторы, большой JSON).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Латинская часть живёт в latin_names (без морфологии, её берёт и guard); имена ниже
# остаются доступными отсюда для прежних импортов
from labops_pii.latin_names import (
    KIND_FIRST,
    KIND_PATR,
    KIND_SURN,
    LATIN_FIRST_NAMES as LATIN_FIRST_NAMES,
    LATIN_LETTERS as LATIN_LETTERS,
    LATIN_LOWER as LATIN_LOWER,
    LATIN_UPPER as LATIN_UPPER,
    NOT_A_NAME_WORDS,
    find_latin_name_spans as find_latin_name_spans,
    latin_word_kind,
    translit_variants as translit_variants,
)
from labops_pii.morph import (
    is_inanimate_common_noun,
    is_non_name_word,
    is_surname_candidate,
    name_gramme,
)

# Длина значения поля, дольше которой это не имя.
MAX_FIELD_VALUE_CHARS = 100
MAX_FIELD_VALUE_WORDS = 5
# Ключ поля: имя до 40 знаков; ограничение держит разбор линейным на любом тексте.
MAX_FIELD_KEY_CHARS = 40

# --- значения JSON-полей по ключу ----------------------------------------------------------

# Поля, в которых значение по смыслу ФИО: годится любая строка, похожая на слова-имя.
STRONG_FIELD_KEYS = frozenset({
    "fullname", "fio", "firstname", "lastname", "middlename", "surname", "patronymic",
    "familyname", "givenname", "contactname", "candidatename", "applicantname",
    "employeename", "clientname", "managername", "recruitername", "ownername",
    "authorname", "personname", "customername", "namefull", "fiofull", "secondname",
    "contactperson", "contactfullname", "candidatefullname", "recipientname", "sendername",
    # русские ключи
    "фио", "фамилия", "отчество", "фамилияимяотчество", "контактноелицо", "фиокандидата",
    "имякандидата", "полноеимя",
})
# Двусмысленные поля («name» бывает названием товара или файла): нужен признак имени у значения.
WEAK_FIELD_KEYS = frozenset({
    "name", "contact", "candidate", "author", "applicant", "owner", "manager", "recruiter",
    "person", "employee", "client", "customer", "creator", "sender", "recipient",
    "responsible", "assignee", "reporter", "signatory",
    # русские ключи
    "имя", "кандидат", "контакт", "автор", "владелец", "менеджер", "рекрутер", "клиент",
    "сотрудник", "ответственный",
})
# Язык в конце ключа («fio_ru», «nameEn») не меняет смысл поля
_KEY_LANG_SUFFIXES = ("ru", "en", "lat", "rus", "eng")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# Пара «"ключ": "значение"»; кавычки могут быть экранированы (JSON внутри JSON-строки).
_FIELD_RE = re.compile(
    r"(?P<kq>\\?[\"'])(?P<key>[A-Za-zА-Яа-яЁё_][A-Za-zА-Яа-яЁё0-9_ -]{0,"
    + str(MAX_FIELD_KEY_CHARS - 1) + r"})"
    r"(?P=kq)[ \t]*:[ \t]*"
    r"(?P<vq>\\?[\"'])(?P<value>[^\"'\\\n\r]{2," + str(MAX_FIELD_VALUE_CHARS) + r"})(?P=vq)"
)
_WORD_PART_RE = re.compile(r"[A-Za-zА-Яа-яЁё]+(?:['’-][A-Za-zА-Яа-яЁё]+)*\.?")
_SPLIT_RE = re.compile(r"[ \t]+")
_NOT_NAME_CHARS_RE = re.compile(r"[0-9@:/\\{}\[\]<>=#$%^&*_+|~`]")
_INITIAL_RE = re.compile(r"^[A-Za-zА-ЯЁа-яё]\.$")


def normalize_field_key(raw: str) -> str:
    """Ключ без регистра, `_`, `-`, пробелов и языкового суффикса: `fullName` -> `fullname`."""
    key = _CAMEL_RE.sub("_", raw).lower()
    key = re.sub(r"[\s_-]+", "", key)
    for suffix in _KEY_LANG_SUFFIXES:
        if key.endswith(suffix) and key[: -len(suffix)] in STRONG_FIELD_KEYS | WEAK_FIELD_KEYS:
            return key[: -len(suffix)]
    return key


def _has_name_evidence(words: list[str]) -> bool:
    """Есть ли у слов значения признак имени: словарь имён, фамилия по форме или инициалы."""
    for word in words:
        if _INITIAL_RE.match(word):
            return True
        bare = word.rstrip(".")
        if bare.isascii():
            if latin_word_kind(bare) in (KIND_FIRST, KIND_PATR, KIND_SURN):
                return True
        elif any(name_gramme(part) is not None for part in bare.split("-")):
            return True
    return False


def looks_like_person_name(value: str, strong: bool) -> bool:
    """Похоже ли значение поля на имя человека (не пустое, не число, не URL и не код).

    Args:
        value: Значение поля без кавычек.
        strong: Поле однозначно про человека (`full_name`, `fio`): достаточно формы слов.
            Иначе (`name`, `author`) нужен ещё признак имени у одного из слов.
    """
    text = value.strip()
    if not text or _NOT_NAME_CHARS_RE.search(text):
        return False
    words = [w for w in _SPLIT_RE.split(text) if w]
    if not words or len(words) > MAX_FIELD_VALUE_WORDS:
        return False
    if not all(_WORD_PART_RE.fullmatch(w) for w in words):
        return False
    if sum(ch.isalpha() for ch in text) < 2:
        return False
    if any(w.lower().rstrip(".") in NOT_A_NAME_WORDS for w in words):
        return False
    return strong or _has_name_evidence(words)


@dataclass(frozen=True, slots=True)
class FieldName:
    """Значение поля-имени: позиции значения в тексте (без кавычек)."""

    start: int
    end: int


def find_json_field_names(text: str) -> list[FieldName]:
    """Значения полей вида `"full_name": "..."`, которые по ключу и форме являются ФИО.

    Ищет и обычный JSON, и пары с экранированными кавычками. Значение возвращается без
    кавычек, поэтому замена токеном оставляет JSON корректным.
    """
    found: list[FieldName] = []
    for match in _FIELD_RE.finditer(text):
        key = normalize_field_key(match.group("key"))
        strong = key in STRONG_FIELD_KEYS
        if not (strong or key in WEAK_FIELD_KEYS):
            continue
        value = match.group("value")
        if looks_like_person_name(value, strong):
            start = match.start("value")
            found.append(FieldName(start, match.end("value")))
    return found


# --- ячейки таблиц `| Фамилия Имя Отчество | ... |` -----------------------------------------

# Natasha в строке таблицы теряет имя без контекста: на реальных данных ФИО в ячейке между
# «|» закрывалось у трети (34 из 100), тогда как то же имя отдельной строкой - у 84 из 100.
# Здесь контекстом служит сама ячейка: 2-3 слова с заглавной, и все они - слова ФИО.
_TABLE_WORD = r"[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?"
_TABLE_CELL_RE = re.compile(
    rf"(?:^|\|)[ \t]*(?P<cell>{_TABLE_WORD}(?:[ \t]+{_TABLE_WORD}){{1,2}})[ \t]*(?=\|)",
    re.MULTILINE,
)
_TABLE_EVIDENCE = frozenset({"Name", "Patr"})
# Фамилии, которых нет в словаре pymorphy, узнаём по окончанию
_SURNAME_ENDINGS = (
    "ов", "ова", "ев", "ева", "ёв", "ёва", "ин", "ина", "ын", "ына", "ский", "ская", "цкий",
    "цкая", "ой", "ых", "их", "ко", "ук", "юк", "ян", "дзе", "швили", "ич",
)


def _table_cell_is_name(cell: str) -> bool:
    """Все слова ячейки - слова ФИО, и есть имя или отчество (не только «слово + слово»)."""
    words = cell.split()
    grams = [name_gramme(w.split("-")[0]) for w in words]
    if any(w.lower() in NOT_A_NAME_WORDS for w in words):
        return False
    if not any(g in _TABLE_EVIDENCE for g in grams):
        return False  # «Сергиев Посад»: без имени или отчества это не человек
    has_patronymic = "Patr" in grams
    return all(
        gram is not None
        or has_patronymic
        or word.lower().endswith(_SURNAME_ENDINGS)
        or is_surname_candidate(word)
        for word, gram in zip(words, grams)
    )


def find_table_cell_names(text: str) -> list[tuple[int, int]]:
    """Позиции ФИО в ячейках markdown-таблиц (ячейка целиком состоит из слов ФИО)."""
    return [
        m.span("cell")
        for m in _TABLE_CELL_RE.finditer(text)
        if _table_cell_is_name(m.group("cell"))
    ]


# --- ФИО в кавычках без слов вокруг: «Белоусова Анна Сергеевна» -----------------------------

# Natasha не размечает ФИО, зажатое кавычками без слова-подсказки («Кандидат «...»» находит,
# голое «...» и «ФИО: «...»» нет): в новостном корпусе имя в кавычках - название, а не
# человек. Контекстом служит сама пара кавычек: внутри только 2-3 слова ФИО. Название
# («Ромашка», «Сбер Банк Онлайн», «Красная Роза Трейд») такой проверки не проходит: у него
# есть словарное существительное или слово, которое не бывает именем, фамилией и отчеством.
# Открывающие и закрывающие кавычки заданы наборами: «‹ „ “ " и » › “ ” ". Перед прямой
# кавычкой допустим «\»: так она выглядит в JSON внутри JSON-строки.
_QUOTE_OPEN = r"(?:\\?\"|[«‹„“‟])"
_QUOTE_CLOSE = r"(?:\\?\"|[»›“”])"
_QUOTED_NAME_RE = re.compile(
    rf"{_QUOTE_OPEN}[ \t]*(?P<cell>{_TABLE_WORD}(?:[ \t]+{_TABLE_WORD}){{1,2}})[ \t]*{_QUOTE_CLOSE}"
)
# Допустимые пары слов ФИО из двух слов: «фамилия + имя» или «имя + отчество» (по словарю)
_QUOTED_PAIRS = frozenset({("Surn", "Name"), ("Name", "Surn"), ("Name", "Patr")})


def _quoted_cell_is_name(cell: str) -> bool:
    """Слова в кавычках - ФИО: полный набор частей, каждое слово - слово ФИО, нет названий.

    Строже ячейки таблицы: название в кавычках встречается куда чаще, поэтому слова из
    словаря не-имён и словарные существительные («Дом», «Банк», «Война») ФИО не пускают, а
    из двух слов нужна пара «фамилия + имя» или «имя + отчество» по словарю целиком.
    """
    words = cell.split()
    if not _table_cell_is_name(cell):
        return False
    parts = [word.split("-")[0] for word in words]
    if any(is_inanimate_common_noun(part) or is_non_name_word(part) for part in parts):
        return False
    grams = [name_gramme(part) for part in parts]
    if len(words) == 2:
        return (grams[0], grams[1]) in _QUOTED_PAIRS
    # Три слова: есть отчество (фамилия может быть незнакомой) либо все три слова - по словарю
    return "Patr" in grams or all(gram is not None for gram in grams)


def find_quoted_name_spans(text: str) -> list[tuple[int, int]]:
    """Позиции ФИО из 2-3 слов, стоящих в кавычках без других слов внутри.

    Args:
        text: Исходный текст.

    Returns:
        Позиции слов ФИО без кавычек: токен заменяет само имя, кавычки остаются на месте.
    """
    return [
        m.span("cell")
        for m in _QUOTED_NAME_RE.finditer(text)
        if _quoted_cell_is_name(m.group("cell"))
    ]
