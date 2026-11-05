"""Склонение подписанта договора в родительный падеж: «в лице генерального директора ...».

Модель видит ФИО токеном и просклонять его не может, поэтому строка «должность и ФИО в
родительном падеже» строится здесь, на РФ, по настоящему значению. Всё, что словарь не
разобрал уверенно, возвращается как None: тогда вопрос задаётся сотруднику, а не
подставляется догадка.
"""

from __future__ import annotations

import re

from pymorphy3.analyzer import Parse

from labops_pii.morph import NAME_GRAMMEMES, _analyzer

GENITIVE = "gent"
NOMINATIVE = "nomn"
GENDERS = ("masc", "femn")
COMMON_GENDER = "ms-f"  # фамилии вроде «Ткаченко»: один вид для обоих полов
FIXED = "Fixd"  # несклоняемое слово
ABBREVIATION = "Abbr"
SUBSTANTIVIZED = "Subx"  # определение, которое бывает и существительным
MIN_NAME_WORDS = 2
MAX_NAME_WORDS = 4
MAX_POSITION_WORDS = 8
# Части речи, которые в начале должности стоят перед главным словом («генеральный»)
POSITION_MODIFIERS = frozenset({"ADJF", "PRTF"})
WORD_RE = re.compile(r"[А-Яа-яЁё]+(?:-[А-Яа-яЁё]+)*")
INITIAL_RE = re.compile(r"[А-ЯЁ]\.")

# Окончания русских фамилий, которых нет в словаре («Дудоров»): (пол, окончание, замена).
# Длинные окончания раньше коротких: «-ский» проверяется до «-ий».
SURNAME_SUFFIX_RULES: tuple[tuple[str, str, str], ...] = (
    ("masc", "ский", "ского"),
    ("masc", "цкий", "цкого"),
    ("masc", "ской", "ского"),
    ("masc", "ов", "ова"),
    ("masc", "ев", "ева"),
    ("masc", "ёв", "ёва"),
    ("masc", "ин", "ина"),
    ("masc", "ын", "ына"),
    ("femn", "ская", "ской"),
    ("femn", "цкая", "цкой"),
    ("femn", "ова", "овой"),
    ("femn", "ева", "евой"),
    ("femn", "ёва", "ёвой"),
    ("femn", "ина", "иной"),
    ("femn", "ына", "ыной"),
)


def _match_case(original: str, inflected: str) -> str:
    """Переносит регистр исходного слова на просклонённое (по частям через дефис)."""
    parts = []
    for source, target in zip(original.split("-"), inflected.split("-"), strict=False):
        if source.isupper() and len(source) > 1:
            parts.append(target.upper())
        elif source[:1].isupper():
            parts.append(target[:1].upper() + target[1:])
        else:
            parts.append(target)
    return "-".join(parts)


def _name_parses(word: str, grammemes: tuple[str, ...]) -> list[Parse]:
    """Разборы слова в именительном падеже с одной из граммем имени, лучшие первыми."""
    return [
        parse
        for parse in _analyzer().parse(word.lower())
        if NOMINATIVE in parse.tag and any(g in parse.tag for g in grammemes)
    ]


def _gender(words: list[str]) -> str | None:
    """Пол по отчеству, а без него - по имени; None, если по ним не понять."""
    for grammeme in ("Patr", "Name"):
        for word in words:
            for parse in _name_parses(word, (grammeme,)):
                gender = next((g for g in GENDERS if g in parse.tag), None)
                if gender is not None:
                    return gender
    return None


def _surname_by_suffix(word: str, gender: str) -> str | None:
    """Склоняет фамилию, которой нет в словаре, по типичному окончанию."""
    lowered = word.lower()
    for rule_gender, suffix, replacement in SURNAME_SUFFIX_RULES:
        if rule_gender == gender and lowered.endswith(suffix) and len(lowered) > len(suffix):
            return lowered[: -len(suffix)] + replacement
    return None


def _inflect_name_part(part: str, gender: str) -> str | None:
    """Одна часть ФИО (без дефиса) в родительном падеже или None, если не разобрана."""
    for parse in _name_parses(part, NAME_GRAMMEMES):
        if gender not in parse.tag and COMMON_GENDER not in parse.tag:
            continue
        if FIXED in parse.tag:
            return part.lower()
        inflected = parse.inflect({GENITIVE})
        if inflected is not None:
            return inflected.word
    return _surname_by_suffix(part, gender)


def inflect_person_genitive(full_name: str) -> str | None:
    """ФИО в родительном падеже: «Дудорова Марина Евгеньевна» -> «Дудоровой Марины Евгеньевны».

    Args:
        full_name: ФИО полностью, слова в любом порядке.

    Returns:
        Просклонённое ФИО или None, если пол или хотя бы одно слово не разобраны (например,
        вместо имени и отчества стоят инициалы).
    """
    words = full_name.split()
    if not MIN_NAME_WORDS <= len(words) <= MAX_NAME_WORDS:
        return None
    if any(INITIAL_RE.search(word) or not WORD_RE.fullmatch(word) for word in words):
        return None
    gender = _gender(words)
    if gender is None:
        return None
    result = []
    for word in words:
        parts = []
        for part in word.split("-"):
            inflected = _inflect_name_part(part, gender)
            if inflected is None:
                return None
            parts.append(inflected)
        result.append(_match_case(word, "-".join(parts)))
    return " ".join(result)


def inflect_position_genitive(position: str) -> str | None:
    """Должность в родительном падеже: «Генеральный директор» -> «генерального директора».

    Склоняются определения в начале и первое существительное (главное слово); всё после
    него («по продажам», «филиала») уже стоит в нужной форме и остаётся как есть.

    Args:
        position: Должность в именительном падеже.

    Returns:
        Должность в родительном падеже со строчной буквы или None, если главное слово не
        найдено.
    """
    words = position.split()
    if not 0 < len(words) <= MAX_POSITION_WORDS:
        return None
    result: list[str] = []
    for index, word in enumerate(words):
        if not WORD_RE.fullmatch(word):
            return None
        # Сокращения («ООО», «ИП») и несклоняемые слова главным словом не считаются
        parses = [
            p
            for p in _analyzer().parse(word.lower())
            if NOMINATIVE in p.tag and FIXED not in p.tag and ABBREVIATION not in p.tag
        ]
        # «Управляющий», «заведующий» - причастие в роли существительного (Subx)
        noun = next(
            (p for p in parses if p.tag.POS == "NOUN" or SUBSTANTIVIZED in p.tag), None
        )
        modifier = next((p for p in parses if p.tag.POS in POSITION_MODIFIERS), None)
        chosen = noun if noun is not None else modifier
        inflected = chosen.inflect({GENITIVE}) if chosen is not None else None
        if inflected is None:
            return None
        result.append(inflected.word)
        if chosen is noun:
            return " ".join([*result, *words[index + 1 :]])
    return None


def signatory_genitive(position: str, full_name: str) -> str | None:
    """Подписант для формулы «в лице ...»: должность и ФИО в родительном падеже.

    Args:
        position: Должность в именительном падеже.
        full_name: ФИО в именительном падеже.

    Returns:
        «генерального директора Дудоровой Марины Евгеньевны» или None, если одну из частей
        уверенно просклонять не удалось.
    """
    position_gent = inflect_position_genitive(position)
    name_gent = inflect_person_genitive(full_name)
    if position_gent is None or name_gent is None:
        return None
    return f"{position_gent} {name_gent}"


# Ключевое слово улицы в косвенных падежах -> именительный. Сокращения («ул.», «пр-т») не
# склоняются и сюда не входят.
STREET_WORD_NOMINATIVE: dict[str, str] = {
    **dict.fromkeys(("улице", "улицу", "улицы"), "улица"),
    **dict.fromkeys(("проспекта", "проспекте", "проспекту"), "проспект"),
    **dict.fromkeys(("переулка", "переулке", "переулку"), "переулок"),
    **dict.fromkeys(("бульвара", "бульваре", "бульвару"), "бульвар"),
    **dict.fromkeys(("набережной", "набережную"), "набережная"),
    "площади": "площадь",
    **dict.fromkeys(("проезда", "проезде", "проезду"), "проезд"),
    **dict.fromkeys(("тупика", "тупике", "тупику"), "тупик"),
    **dict.fromkeys(("аллеи", "аллее", "аллею"), "аллея"),
}
STREET_WORD_RE = re.compile(r"[А-Яа-яЁё]+")
# Род ключевого слова улицы в именительном падеже: по нему согласуется название-прилагательное
STREET_WORD_GENDER: dict[str, str] = {
    "улица": "femn", "набережная": "femn", "площадь": "femn", "аллея": "femn",
    "проспект": "masc", "переулок": "masc", "бульвар": "masc", "проезд": "masc", "тупик": "masc",
}
# Название из одного слова сразу после ключевого слова: «Складскую, д. 5», «Тверской 7».
# Составные названия («Красной Армии», «Яна Райниса») не трогаются: в них прилагательное
# часто стоит в родительном падеже уже в именительной форме улицы.
SINGLE_NAME_RE = re.compile(r"[ \t]+([А-ЯЁ][а-яё]+)(?=[ \t]*[,\d]|[ \t]+(?:д\.|дом)|[ \t]*$)")


def _adjective_nominative(word: str, gender: str) -> str | None:
    """Прилагательное из названия улицы в именительный падеж нужного рода или None."""
    for parse in _analyzer().parse(word.lower()):
        if parse.tag.POS != "ADJF" or gender not in parse.tag or NOMINATIVE in parse.tag:
            continue
        inflected = parse.inflect({NOMINATIVE, gender})
        if inflected is not None:
            return _match_case(word, inflected.word)
    return None


def address_street_word_nominative(address: str) -> str:
    """Ключевое слово улицы в начале адреса - в именительный падеж: «улицу Складскую, д. 5» ->
    «улица Складская, д. 5».

    Адрес хранится в написании первого упоминания («доставить на улицу Ленина»), а токен потом
    встречается и там, где падеж другой (поле «адрес доставки» в договоре, «по адресу [ADDRESS_1]»).
    Без предлога перед токеном подходит именительный падеж. Название улицы из одного слова
    склоняется, если это прилагательное («Складскую» -> «Складская»); название-существительное
    («Ленина», «Мира») и составные названия не меняются. Сокращения и адреса, начинающиеся не с
    ключевого слова улицы, возвращаются как есть.

    Args:
        address: Оригинал адреса из таблицы замен.

    Returns:
        Адрес с ключевым словом (и названием-прилагательным) в именительном падеже; регистр
        первой буквы ключевого слова сохранён.
    """
    match = STREET_WORD_RE.match(address)
    if match is None:
        return address
    nominative = STREET_WORD_NOMINATIVE.get(match.group().lower())
    if nominative is None:
        return address
    head = _match_case(match.group(), nominative)
    rest = address[match.end():]
    name = SINGLE_NAME_RE.match(rest)
    if name is not None:
        fixed = _adjective_nominative(name.group(1), STREET_WORD_GENDER[nominative])
        if fixed is not None:
            rest = rest[: name.start(1)] + fixed + rest[name.end(1):]
    return head + rest
