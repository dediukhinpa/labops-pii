"""Общие шаблоны и нормализация ПДн для двух слоёв защиты (R3-ALG-15).

КАНОНИЧЕСКИЙ ИСХОДНИК: этот модуль. Им пользуются и псевдонимизатор, и guard (раньше три
копии: shared/pii_patterns.py, pseudonymizer/ и pii-guard/ в проектах). Копий внутри
библиотеки нет; проекты получают модуль вендорингом всей библиотеки (tools/vendor.sh).
Модуль не зависит ни от одного из пакетов и не пишет в журнал значений ПДн.
"""

from __future__ import annotations

import re
import sys
import unicodedata

# --- Нормализация ----------------------------------------------------------------

# Все виды тире и дефисов (мягкий перенос, U+2010..2015, минус, малые/полноширинные формы)
_DASH_CODEPOINTS = (0x00AD, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2043,
                    0x2212, 0xFE58, 0xFE63, 0xFF0D)
# Косые черты, которыми набирают телефон («8/916/123/45/67»): дробная, делящая, полноширинная
_SLASH_CODEPOINTS = (0x2044, 0x2215, 0xFF0F)
# Невидимые символы нулевой ширины и BOM: превращаются в пробел, чтобы не склеивать цифры
_INVISIBLE_CODEPOINTS = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)
_ASCII_SLASH = ord("/")


def _build_fold_table() -> dict[int, int]:
    """Строит таблицу для str.translate один раз при импорте: длину строки не меняет никогда.

    Явные правила: тире и «/» -> «-», невидимые -> пробел. Затем отдельным шагом любая
    десятичная цифра Unicode (арабо-индийские, деванагари, тайские, полноширинные и т.д.,
    unicodedata.decimal) -> ASCII-цифра; NFKC такие цифры не трогает, а шаблоны ниже
    опираются на ASCII-классы («[3-9]», префикс «8»). Остальное: NFKC посимвольно, но
    только если результат ровно один символ (полноширинная «＠», NBSP и узкие пробелы).
    Символ, у которого NFKC даёт несколько знаков («№», «…»), остаётся как есть: смещение
    позиций сломало бы замену по найденным границам в псевдонимизаторе.

    Таблица статическая и хранит только неединичные отображения: str.translate оставляет
    символ без записи как есть. Раньше образ считался лениво и запоминался на каждый
    встреченный символ, и враждебное тело с множеством разных символов раздувало таблицу
    (+110 МБ) без предела; теперь размер фиксирован и не зависит от входа.
    """
    table: dict[int, int] = {}
    for code in range(sys.maxunicode + 1):
        char = chr(code)
        digit = unicodedata.decimal(char, None)
        if digit is not None:
            image = ord(str(digit))
        else:
            folded = unicodedata.normalize("NFKC", char)
            image = ord(folded) if len(folded) == 1 else code
        if image != code:
            table[code] = image
    # Явные правила сильнее общих и применяются поверх них
    for code in (*_DASH_CODEPOINTS, *_SLASH_CODEPOINTS, _ASCII_SLASH):
        table[code] = ord("-")
    for code in _INVISIBLE_CODEPOINTS:
        table[code] = ord(" ")
    return table


_FOLD = _build_fold_table()


def normalize_text(text: str) -> str:
    """Приводит текст к виду, удобному для поиска цифровых ПДн (длина не меняется).

    Цифры любых систем счисления -> ASCII, NFKC посимвольно (полноширинная «@», NBSP ->
    пробел), все виды тире и «/» -> «-», невидимые символы -> пробел. Позиции в результате
    совпадают с позициями исходной строки.

    Args:
        text: Исходный текст.

    Returns:
        Строка той же длины.
    """
    return text.translate(_FOLD)


# --- Телефоны --------------------------------------------------------------------

# Разделители групп цифр: после normalize_text это пробел, перевод строки, «-» и «.».
# Не больше 3 подряд: хватает «8 - 916», и поиск остаётся линейным.
_SEP_MAX = 3
SEP = rf"[ \t\r\n\-.]{{0,{_SEP_MAX}}}"
SEP_REQUIRED = rf"[ \t\r\n\-.]{{1,{_SEP_MAX}}}"
# Слева от номера нельзя цифру (в том числе через разделитель дробной части). В строгом
# варианте нельзя и «цифра + пробел» (разряд суммы): им защищены формы без префикса.
# Буквы и «_» разрешены: «тел89991234567», «прайс_89991234567.xlsx».
PHONE_LEFT = r"(?<!\d)(?<!\d[.,])"
PHONE_LEFT_STRICT = PHONE_LEFT + r"(?<!\d[ ])"
# Международный номер (E.164) вне РФ/BY: обязательный «+», код страны не 7 (российские формы
# разобраны выше), всего не меньше INTL_MIN_DIGITS цифр: «+10 200 000» (сумма) не телефон.
# Без «+» номер не ищем: цифровые группы без префикса слишком похожи на артикулы и суммы.
INTL_MIN_DIGITS = 9
INTL_MAX_COMPACT_DIGITS = 14
INTL_GROUP_MAX = 5
INTL_GROUP_MAX_DIGITS = 8
# Проверки международной ветки (вставляются сразу после «+»):
# не дата «2024-01-15» / «15.01.2024» сразу после кода страны (код 1-2 цифры + пробел)
_INTL_NOT_DATE = (
    r"(?!\d{1,3}[ \t\-.]\d{4}[ \-.]\d{2}[ \-.]\d{2}(?!\d))"
    r"(?!\d{1,3}[ \t\-.]\d{2}[ \-.]\d{2}[ \-.]\d{4}(?!\d))"
)
# не сумма: 1-2 цифры и затем только группы по 3 цифры («+1 200 000 000», «+20 000 000 000»)
_INTL_NOT_AMOUNT = r"(?!\d{1,2}(?:[ \t\r\n.\-]\d{3}){2,5}(?![ \t\r\n.\-]?\d))"
# в номере есть группа из 3+ цифр (после кода страны)
_INTL_HAS_LONG_GROUP = rf"(?:{SEP_REQUIRED}\(?\d{{1,{INTL_GROUP_MAX_DIGITS}}}\)?){{0,4}}" \
    rf"{SEP_REQUIRED}\(?\d{{3,{INTL_GROUP_MAX_DIGITS}}}"
# Минимум цифр (с кодом страны) для рядов коротких групп: «+33 6 12 34 56 78» - 11,
# «+45 12 34 56 78» - 10; «+3 15 20 25 30» (9) остаётся суммой/размерами.
INTL_MIN_DIGITS_ROWS = 10
INTL_ROW_GROUPS_MIN = 3
INTL_ROW_GROUPS_MAX = 5
# Начало международного номера: «+» (код любой, кроме 7) или «00» (код из списка стран).
_LEAD_PLUS = r"\(?\+(?!7)"
_LEAD_ZERO = r"00"
_ANY_CODE = r"[1-9]\d{0,2}"
# Коды стран E.164 (без 7): после «00» произвольные цифры слишком похожи на номера
# документов («0012 3456 789»), поэтому код проверяется по списку.
_COUNTRY_CODE_2 = r"(?:20|27|3[0-469]|4[013-9]|5[1-8]|6[0-6]|8[1246]|9[0-58])"
_COUNTRY_CODE = (
    rf"(?:1|{_COUNTRY_CODE_2}|2[1-69]\d|3[578]\d|42\d|50\d|59\d|6[7-9]\d|8[578]\d|9[679]\d)"
)
# три группы по 3 цифры: первая не с нуля, последняя не «000», не дробная часть суммы
_INTL_THREE_GROUPS = (
    rf"[1-9]\d{{2}}{SEP_REQUIRED}\d{{3}}{SEP_REQUIRED}(?!000)\d{{3}}(?!\d)(?![.,]\d)"
)


def _intl_grouped(lead: str, code: str) -> str:
    """Ветка международного номера группами с хотя бы одной группой из 3+ цифр.

    Args:
        lead: Начало номера («+» или «00»).
        code: Шаблон кода страны.

    Returns:
        Фрагмент шаблона (без внешних скобок).
    """
    return (
        rf"{PHONE_LEFT}{lead}{_INTL_NOT_DATE}{_INTL_NOT_AMOUNT}"
        rf"(?=(?:[ \t\r\n\-.()]{{0,4}}\d){{{INTL_MIN_DIGITS}}})"
        rf"{code}\)?(?={_INTL_HAS_LONG_GROUP})"
        rf"{SEP_REQUIRED}\(?[1-9]\d{{0,{INTL_GROUP_MAX_DIGITS - 1}}}\)?"
        rf"(?:{SEP_REQUIRED}\(?\d{{1,{INTL_GROUP_MAX_DIGITS}}}\)?){{1,{INTL_GROUP_MAX - 1}}}(?!\d)"
    )


def _intl_short_rows(lead: str, code: str) -> str:
    """Ветка международного номера рядом коротких групп (1-2 цифры), всего 10+ цифр."""
    return (
        rf"{PHONE_LEFT}{lead}"
        rf"(?=(?:[ \t\r\n\-.()]{{0,4}}\d){{{INTL_MIN_DIGITS_ROWS}}})"
        rf"{code}\)?{SEP_REQUIRED}\d{{1,2}}"
        rf"(?:{SEP_REQUIRED}\d{{2}}){{{INTL_ROW_GROUPS_MIN},{INTL_ROW_GROUPS_MAX}}}"
        rf"(?!\d)(?![.,]\d)"
    )


_PREFIX = r"(?:\+7|8|7)"
PHONE_RE = re.compile(
    # Быстрый отсев: номер начинается с цифры, «+» или «(»; без него 10 вариантов на каждом
    # символе давали секунды на теле в 8 МиБ
    r"(?=[\d+(])(?:"
    # +7/8/7 и код из 3 цифр: «+7 (916) 123-45-67», «8.916.123.45.67»
    rf"{PHONE_LEFT}{_PREFIX}{SEP}\(?\d{{3}}\)?{SEP}\d{{3}}{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    # код города из 4 цифр: «8 (3812) 12-34-56»
    rf"|{PHONE_LEFT}{_PREFIX}{SEP}\(?\d{{4}}\)?{SEP}\d{{2}}{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    # код города из 5 цифр: «8 (84922) 3-45-67»
    rf"|{PHONE_LEFT}{_PREFIX}{SEP}\(?\d{{5}}\)?{SEP}\d{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    # Беларусь: «+375 (29) 123-45-67», «00375…»
    rf"|{PHONE_LEFT}(?:\+375|00375){SEP}\(?\d{{2}}\)?{SEP}\d{{3}}{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    # без префикса, но с кодом в скобках: «(495) 123-45-67»
    rf"|{PHONE_LEFT}\(\d{{3}}\){SEP}\d{{3}}{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    rf"|{PHONE_LEFT}\(\d{{4}}\){SEP}\d{{2}}{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    rf"|{PHONE_LEFT}\(\d{{5}}\){SEP}\d{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    # десять цифр без префикса и скобок: «999 123 45 67», «999 1234567», «999.123.45.67»
    rf"|{PHONE_LEFT_STRICT}[3-9]\d{{2}}{SEP_REQUIRED}\d{{3}}{SEP}\d{{2}}{SEP}\d{{2}}(?!\d)"
    # только дефисы: «123-456-78-90»
    rf"|{PHONE_LEFT_STRICT}\d{{3}}-\d{{3}}-\d{{2}}-\d{{2}}(?!\d)"
    # международный, группами: «+86 138 0013 8000», «+1 (415) 555-0132», «+49 30 12345678»,
    # «(+44) 20 7946 0958», «+971-4-123-4567»; то же с префиксом «00» («0049 30 12345678»).
    # Отсекаются даты («+1 2024-01-15»), суммы с группами по 3 цифры («+20 000 000 000»),
    # ряды коротких групп короче INTL_MIN_DIGITS_ROWS цифр («+3 15 20 25 30»): нужна хотя бы
    # одна группа из 3+ цифр, первая группа не с нуля.
    rf"|{_intl_grouped(_LEAD_PLUS, _ANY_CODE)}"
    rf"|{_intl_grouped(_LEAD_ZERO, _COUNTRY_CODE)}"
    # «+код» и слитный национальный номер 9-11 цифр: «+86 13800138000», «+90 5321234567»
    rf"|{PHONE_LEFT}\+(?!7)[1-9]\d{{0,2}}{SEP_REQUIRED}[1-9]\d{{8,10}}(?!\d)(?![.,]\d)"
    rf"|{PHONE_LEFT}00{_COUNTRY_CODE}{SEP_REQUIRED}[1-9]\d{{8,10}}(?!\d)(?![.,]\d)"
    # код из 2 цифр и три группы по 3: «+48 123 456 789», «0034 612 345 678»; последняя
    # группа не «000» и без дробной части: «+12 345 000 000» и «+12 345 678 901,50» - суммы
    rf"|{PHONE_LEFT}\+(?!7)[1-9]\d{SEP_REQUIRED}{_INTL_THREE_GROUPS}"
    rf"|{PHONE_LEFT}00{_COUNTRY_CODE_2}{SEP_REQUIRED}{_INTL_THREE_GROUPS}"
    # ряды коротких групп при 10+ цифрах всего: «+33 6 12 34 56 78», «+45 12 34 56 78»
    rf"|{_intl_short_rows(_LEAD_PLUS, _ANY_CODE)}"
    rf"|{_intl_short_rows(_LEAD_ZERO, _COUNTRY_CODE)}"
    # международный с «(0)» после кода страны: «+44 (0)20 7946 0958»
    rf"|{PHONE_LEFT}\(?\+(?!7)(?=(?:[ \t\r\n\-.()]{{0,4}}\d){{{INTL_MIN_DIGITS}}})"
    rf"[1-9]\d{{0,2}}\)?{SEP}\(0\){SEP}[1-9]\d{{0,3}}"
    rf"(?:{SEP_REQUIRED}\d{{2,{INTL_GROUP_MAX_DIGITS}}}){{1,{INTL_GROUP_MAX - 1}}}(?!\d)"
    # международный слитно: «+4930123456789»
    rf"|{PHONE_LEFT}\+(?!7)[1-9]\d{{{INTL_MIN_DIGITS - 1},{INTL_MAX_COMPACT_DIGITS}}}(?!\d)"
    r")"
)
# Десять цифр подряд — телефон только после слова «тел» и т.п. (иначе это ИНН/артикул).
# Ключевое слово не должно быть концом другого слова («hotel», «intel»). Между словом и
# числом не больше BARE_PHONE_GAP нецифровых символов: хватает «Телефон для связи: ».
# В промежутке допускается один перевод строки (R9-A4-05): в подписях писем метка и номер
# часто стоят на разных строках («моб.\n9165550123»), и такой номер уходил в модель открытым.
# Предел длины проверяет опережающая проверка: первая цифра после слова не дальше
# BARE_PHONE_GAP символов, поэтому захват промежутка тоже не длиннее (перебор ограничен).
# Два перевода строки (пустая строка между меткой и числом) связь по-прежнему разрывают.
BARE_PHONE_GAP = 24
BARE_PHONE_RE = re.compile(
    r"(?<![A-Za-zА-Яа-яЁё])(?i:тел|phone|моб|факс|whatsapp|viber|tel|mob)"
    rf"(?=\D{{0,{BARE_PHONE_GAP}}}\d)(?:[^\d\n]*\n)?[^\d\n]*"
    r"(?<!\d)([3-9]\d{9})(?!\d)(?![.,]\d)"
)

# --- Банковские реквизиты --------------------------------------------------------

CARD_MIN_DIGITS = 16
CARD_MAX_DIGITS = 19
# Карта: 16-19 цифр подряд или группами по 4 через один и тот же разделитель; первая цифра
# 2-6 (Мир, Visa, Mastercard, UnionPay, Maestro) отсекает часть случайных длинных номеров.
# Совпадение подтверждается проверкой Luhn (is_luhn_valid), одного формата мало.
CARD_RE = re.compile(
    r"(?<![\d.,])[2-6]\d{3}(?:([ \-])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?|\d{12,15})(?!\d)"
)
# Расчётный счёт: 20 цифр, балансовый счёт 301/302/40[1-8]/423/426, группы 5-3-1-4-7 через
# один и тот же разделитель (или без него).
ACCOUNT_RE = re.compile(
    r"(?<![\d.,])(?:30[12]|40[1-8]|423|426)\d{2}([ \-]?)\d{3}\1\d\1\d{4}\1\d{7}(?!\d)"
)
# Счета организаций (301/302, 401-407) — реквизит юрлица, физлица (408, 423, 426) — ПДн.
ACCOUNT_PERSON_PREFIXES = ("408", "423", "426")


def is_luhn_valid(digits: str) -> bool:
    """Проверяет номер банковской карты алгоритмом Луна.

    Args:
        digits: Только цифры.

    Returns:
        True, если длина 16-19 цифр и контрольная сумма сходится.
    """
    if not digits.isdigit() or not CARD_MIN_DIGITS <= len(digits) <= CARD_MAX_DIGITS:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:  # noqa: PLR2004 - сумма цифр удвоенного значения
                value -= 9
        total += value
    return total % 10 == 0


# Ряд цен по тиражам («3050 2850 2620 2390 2180») — это четыре-пять столбцов таблицы, а не
# карта, хотя 16 цифр через пробел проходят Luhn примерно в 10 % случаев. Настоящая карта с
# подсказкой рядом («карта», «card», «Visa» ...) маскируется всегда.
CARD_CONTEXT_RE = re.compile(r"(?i)карт|card|visa|master\s?card|maestro|\bмир\b|\bpan\b|\bcvv\b")
CARD_CONTEXT_LEFT = 32
CARD_CONTEXT_RIGHT = 16
# Число-столбец рядом с группами: 3-5 цифр, отделённое тем же разделителем, без десятичной части.
PRICE_NEIGHBOR_DIGITS = "3,5"
PRICE_NEIGHBOR_MIN_LEN = 3
PRICE_NEIGHBOR_MAX_LEN = 5
# Символы, после которых число слева - не отдельный столбец (часть дроби или другого числа)
PRICE_LEFT_STOP = frozenset("0123456789.,")
# Предел соседей с каждой стороны: ряды тиражей короче, а без предела проверка росла с длиной
# текста на каждом кандидате в карту
PRICE_NEIGHBORS_MAX = 16
# Соседние цены в ряду тиражей отличаются не более чем в 1/0.6 раза (скидка за тираж).
PRICE_STEP_MIN_RATIO = 0.6
PRICE_ROW_MIN_NEIGHBORS = 2
CARD_GROUPS = 4


def _card_context_near(text: str, start: int, end: int) -> bool:
    """Есть ли рядом слово, указывающее на банковскую карту."""
    left = text[max(0, start - CARD_CONTEXT_LEFT) : start]
    right = text[end : end + CARD_CONTEXT_RIGHT]
    return bool(CARD_CONTEXT_RE.search(left) or CARD_CONTEXT_RE.search(right))


def _price_neighbors(text: str, start: int, end: int, sep: str) -> tuple[list[int], list[int]]:
    """Числа-столбцы (3-5 цифр) слева и справа вплотную к группам через тот же разделитель.

    Разбор ручной и ограничен PRICE_NEIGHBORS_MAX числами с каждой стороны: прежний поиск
    `re.search(..., text[:start])` с якорем «$» на каждом шаге сканировал всю голову текста, и
    длинный ряд «4242 4242 ...» обрабатывался кубическое время (часы на 70 000 символов).
    """
    sep_len = len(sep)
    left: list[int] = []
    pos = start
    while len(left) < PRICE_NEIGHBORS_MAX and pos >= sep_len and text[pos - sep_len : pos] == sep:
        digits_end = pos - sep_len
        digits_start = digits_end
        while digits_start > 0 and text[digits_start - 1].isdecimal() and (
            digits_end - digits_start < PRICE_NEIGHBOR_MAX_LEN + 1
        ):
            digits_start -= 1
        length = digits_end - digits_start
        if not PRICE_NEIGHBOR_MIN_LEN <= length <= PRICE_NEIGHBOR_MAX_LEN:
            break
        if digits_start > 0 and text[digits_start - 1] in PRICE_LEFT_STOP:
            break
        left.insert(0, int(text[digits_start:digits_end]))
        pos = digits_start
    right: list[int] = []
    pattern = re.compile(rf"{re.escape(sep)}(\d{{{PRICE_NEIGHBOR_DIGITS}}})(?![\d.,/])")
    pos = end
    while len(right) < PRICE_NEIGHBORS_MAX:
        found = pattern.match(text, pos)
        if not found:
            break
        right.append(int(found.group(1)))
        pos = found.end()
    return left, right


def _smooth_steps(values: list[int]) -> bool:
    """Соседние числа отличаются не более чем в 1/PRICE_STEP_MIN_RATIO раза."""
    return all(
        min(a, b) / max(a, b) >= PRICE_STEP_MIN_RATIO
        for a, b in zip(values, values[1:])
        if a and b
    )


def looks_like_price_row(text: str, start: int, end: int, sep: str) -> bool:
    """Группы по 4 цифры text[start:end] похожи на ряд цен по тиражам, а не на карту.

    Ряд цен — это либо >= 2 числа-столбца рядом с четырьмя группами (всего >= 6 чисел подряд)
    И весь ряд вместе с соседями идёт плавным шагом, либо четыре строго монотонные группы с
    плавным шагом И хотя бы одно соседнее число. CVV, год, сумма рядом с картой плавного шага
    не дают. Слитные цифры, дефисы и подсказка «карта» рядом исключают ряд цен всегда.

    Args:
        text: Исходный текст.
        start: Начало первой группы.
        end: Конец четвёртой группы.
        sep: Разделитель групп.

    Returns:
        True, если это ряд цен и карту маскировать не надо.
    """
    if sep != " " or _card_context_near(text, start, end):
        return False
    left, right = _price_neighbors(text, start, end, sep)
    # Ряд упёрся в предел соседей: дальше могли быть числа, ломающие плавный шаг, а без
    # предела они бы его сломали. Не видим ряд целиком - считаем картой (fail closed)
    if PRICE_NEIGHBORS_MAX in (len(left), len(right)):
        return False
    neighbors = len(left) + len(right)
    if neighbors < 1:
        return False
    values = [int(g) for g in text[start:end].split(sep)]
    if neighbors >= PRICE_ROW_MIN_NEIGHBORS:
        return _smooth_steps(left + values + right)
    pairs = list(zip(values, values[1:]))
    return _smooth_steps(values) and (
        all(b > a for a, b in pairs) or all(b < a for a, b in pairs)
    )


def card_span(text: str, match: "re.Match[str]") -> tuple[int, int] | None:
    """Границы карты внутри совпадения CARD_RE или None, если это не карта.

    Совпадение из 4 групп с хвостом (`... 5678 123`) может быть картой с CVV рядом: если 19
    цифр не проходят Luhn, проверяется префикс из 16 цифр.
    """
    sep = match.group(1) or ""
    start, end = match.start(), match.end()
    spans = [(start, end)]
    if sep and len(match.group().split(sep)) == CARD_GROUPS + 1:
        spans.append((start, start + CARD_GROUPS * 4 + (CARD_GROUPS - 1)))
    for lo, hi in spans:
        if is_luhn_valid(re.sub(r"\D", "", text[lo:hi])) and not looks_like_price_row(
            text, lo, hi, sep
        ):
            return lo, hi
    return None


def find_card_spans(text: str, start: int = 0, end: int | None = None) -> list[tuple[int, int]]:
    """Все карты в тексте; окна проверяются со сдвигом на 1 символ, не впритык друг к другу.

    Обычный finditer не пересекает совпадения: в «5000 4276 1600 1234 5675» первое окно
    (5000...1234) не карта, а настоящая карта со сдвигом пропускалась.
    """
    limit = len(text) if end is None else end
    spans: list[tuple[int, int]] = []
    pos = start
    while pos < limit:
        match = CARD_RE.search(text, pos, limit)
        if match is None:
            break
        span = card_span(text, match)
        if span is None:
            pos = match.start() + 1
        else:
            spans.append(span)
            pos = span[1]
    return spans


def is_card_match(text: str, match: "re.Match[str]") -> bool:
    """Совпадение CARD_RE — карта: Luhn сходится и это не ряд цен."""
    return card_span(text, match) is not None


# --- СНИЛС -----------------------------------------------------------------------

# Слово «СНИЛС» может стоять далеко от номера: «СНИЛС (страховой номер): 123-456-789 01».
# Номер рядом со словом псевдонимизатор маскирует и без контрольной суммы; guard контрольную
# сумму требует всегда (ложный отказ запросу дороже, чем не-СНИЛС с ключевым словом).
SNILS_KEYWORD_WINDOW = 40
SNILS_RE = re.compile(r"(?<!\d)\d{3}[ \-]?\d{3}[ \-]?\d{3}[ \-]?\d{2}(?!\d)")

# Правило «что шлюз считает СНИЛС» (R9-A4-04) - одно на оба слоя: guard отклоняет запрос с
# такой находкой, псевдонимизатор обязан замаскировать каждую такую находку (иначе запрос с
# артикулом «31234567846» получал отказ, ~1 % случайных 11-значных номеров). Две формы:
# ровно 11 цифр подряд и запись группами «123-456-789 01»; в обеих сходится контрольная сумма.
SNILS_LEN = 11
SNILS_NUMBER_LEN = 9
# Номера не больше этого выдавались без контрольного числа: по сумме их не опознать
SNILS_MIN_NUMBER = 1_001_998
SNILS_MOD = 101
SNILS_SPECIAL_SUM = 100
SNILS_BARE_RE = re.compile(rf"(?<!\d)\d{{{SNILS_LEN}}}(?!\d)")
SNILS_FMT_RE = re.compile(r"(?<!\d)\d{3}[ \-]\d{3}[ \-]\d{3}[ ]?\d{2}(?!\d)")
_NON_DIGIT_RE = re.compile(r"\D")


def is_snils_checksum_valid(digits: str) -> bool:
    """Проверяет контрольное число СНИЛС так, как его проверяет шлюз.

    Малые номера (не больше SNILS_MIN_NUMBER) контрольного числа не имеют и здесь не
    считаются СНИЛС: без ключевого слова их не отличить от любого числа.

    Args:
        digits: Только цифры.

    Returns:
        True, если 11 цифр и контрольное число сходится.
    """
    if len(digits) != SNILS_LEN or not digits.isdigit():
        return False
    number, check = int(digits[:SNILS_NUMBER_LEN]), int(digits[SNILS_NUMBER_LEN:])
    if number <= SNILS_MIN_NUMBER:
        return False
    total = sum(
        int(char) * (SNILS_NUMBER_LEN - index)
        for index, char in enumerate(digits[:SNILS_NUMBER_LEN])
    )
    if total < SNILS_SPECIAL_SUM:
        expected = total
    elif total <= SNILS_MOD:
        expected = 0
    else:
        expected = total % SNILS_MOD
        expected = 0 if expected >= SNILS_SPECIAL_SUM else expected
    return expected == check


def find_snils_spans(text: str, start: int = 0, end: int | None = None) -> list[tuple[int, int]]:
    """Находит СНИЛС по правилу шлюза: 11 цифр подряд или группами, сумма сходится.

    Ищет в нормализованном тексте (normalize_text). Левый контекст шаблоны видят за start,
    правый обрезан концом end (как у остальных шаблонов при поиске окнами).

    Args:
        text: Нормализованный текст.
        start: Начало области поиска.
        end: Конец области поиска (не включительно); None - до конца текста.

    Returns:
        Диапазоны (начало, конец) в порядке появления; формы могут совпасть по диапазону.
    """
    stop = len(text) if end is None else end
    spans: list[tuple[int, int]] = []
    for pattern in (SNILS_BARE_RE, SNILS_FMT_RE):
        for match in pattern.finditer(text, start, stop):
            if is_snils_checksum_valid(_NON_DIGIT_RE.sub("", match.group(0))):
                spans.append(match.span())
    return sorted(spans)

# --- E-mail ----------------------------------------------------------------------

# Кириллица и любой Unicode допустимы в локальной части и домене (IDN: «иван@пример.рф»)
EMAIL_LOCAL_EXTRA = frozenset("._%+-")
EMAIL_DOMAIN_RUN_RE = re.compile(r"[\w.\-]+")
EMAIL_TLD_RE = re.compile(r"\.[^\W\d_]{2,}")


def is_email_local_char(char: str) -> bool:
    """Допустим ли символ слева от «@» в локальной части адреса."""
    return char.isalnum() or char in EMAIL_LOCAL_EXTRA

# --- Контакты в мессенджерах (R4-SEC-9) ------------------------------------------

# Ник Telegram: «@» + латиница/цифры/«_» длиной 5-32, начинается с буквы (ник из цифр не
# бывает). Слева не слово, «.», «+», «-», «@»: внутри адреса («ivan@mail.ru»), артикула
# («АБ@12345») и цепочки «@@» ника нет. Справа не слово и не «.буквы» («@example.com» это
# домен, а не ник).
NICK_RE = re.compile(r"(?<![\w.+\-@])@[A-Za-z][A-Za-z0-9_]{4,31}(?![\w@]|\.[A-Za-z]{2})")
# Ссылка на Telegram: «t.me/ник», «t.me/+инвайт», «t.me/joinchat/…» (с протоколом или без).
# Слева не слово и не «.»/«@»: «dt.me/x» и «a@t.me/x» ссылкой не считаются.
TME_RE = re.compile(
    r"(?<![\w.@\-])(?i:(?:https?://)?(?:www\.)?(?:t|telegram)\.me)/[A-Za-z0-9_+]"
    r"[A-Za-z0-9_+/\-]{1,63}"
)

# --- Адреса (этап Г): улица + дом, квартира, индекс --------------------------------

# Маскируется адрес на уровне дома. Город («г. Москва,») остаётся открытым: он нужен
# шорт-листу и карточкам поставщиков. Улица без номера дома («на улице Ленина») адресом не
# считается. Шаблоны не зависят от морфологии (guard её не имеет): падежи ключевого слова
# («улица/улице/улицу») перечислены явно, название улицы - слова с заглавной буквы.
# Все квантификаторы ограничены, вложенных неограниченных повторов нет: время линейно по
# длине текста (проверяется тестом на враждебном вводе). Искать нужно в normalize_text-копии
# (тире и «/» уже «-»), позиции совпадают с исходным текстом.

# Слово названия улицы: «Ленина», «Красной», «Санкт-Петербургская», «ЛЕНИНА»
_ADDR_WORD = r"[А-ЯЁ][А-ЯЁа-яё]+(?:-[А-ЯЁа-яё]+)*"
# Слова, с которых название улицы не начинается: «Серия 5», «Заказ 12», «Партия 7» - не адрес.
# Без этого «Светильник ул. Серия 5000» и «в г. Москва, Заказ 5.» давали бы ложное срабатывание.
_ADDR_NAME_STOP = (
    "заказ|заказа|серия|серии|партия|партии|позиция|позиции|артикул|номер|код|тип|модель|"
    "размер|лот|этап|пункт|раздел|статья|приложение|договор|счет|счёт|накладная|спецификация|"
    "заявка|тираж|цех|склад|офис|корпус|строение|литера|квартира|этаж|комната|помещение|"
    "версия|вариант|группа|класс|уровень|сорт|марка|формат|цена|итого|всего|страница|лист"
)
_ADDR_NAME_GUARD = rf"(?!(?i:{_ADDR_NAME_STOP})(?![А-Яа-яЁё]))"
# Название: «Ленина», «Красной Армии», «1-я Тверская», «8 Марта», «50 лет Октября»
_ADDR_NAME = (
    r"(?:\d{1,3}-(?:я|й|е|го|ая|ой|ья|ий)[ \t]+|\d{1,3}[ \t]+(?:(?i:лет)[ \t]+)?)?"
    rf"{_ADDR_NAME_GUARD}{_ADDR_WORD}(?:[ \t]+{_ADDR_WORD}){{0,2}}"
)
# Название перед ключевым словом («Ленина ул., д. 5», «1-я Тверская ул., 5»)
_ADDR_NAME_POSTFIX = (
    rf"(?:\d{{1,3}}-(?:я|й|е|го|ая|ой|ья|ий)[ \t]+)?{_ADDR_NAME_GUARD}{_ADDR_WORD}"
    rf"(?:[ \t]+{_ADDR_WORD})?"
)
# Ключевое слово улицы: полные формы в падежах и сокращения. Короткие сокращения, которые
# бывают и другими словами («пр.» - примечание, «ш.», «пл.»), требуют точку.
_ADDR_DESIG = (
    r"(?:(?i:улиц(?:а|е|у|ы)|проспект(?:а|е|у)?|переул(?:ок|ка|ке|ку)|бульвар(?:а|е|у)?|"
    r"набережн(?:ая|ой|ую)|шоссе|площад(?:ь|и)|проезд(?:а|е|у)?|тупик(?:а|е|у)?|"
    r"алле(?:я|и|е|ю))"
    r"|(?:(?i:ул|пр-кт|пр-т|пер|б-р|бул|пр-д)\.?|(?i:наб|пл|ш|пр|просп)\.))"
    r"(?![а-яё])"
)
_ADDR_LEFT = r"(?<![А-Яа-яЁёA-Za-z0-9-])"
# Номер дома: «5», «5а», «12-14» (после normalize_text «12/14» тоже с дефисом)
_ADDR_HOUSE = r"\d{1,4}(?:-\d{1,4})?[А-Яа-я]?(?![А-Яа-яЁёA-Za-z0-9])"
# Пометка дома: «д.», «дом», «влд.», «№»
_ADDR_MARK = r"(?:(?i:д(?:ом)?|вл(?:д|адение)?)\.?[ \t]*(?:№[ \t]*)?|№[ \t]*)"
# Корпус, строение, литера, квартира, офис, этаж: «, кв. 12», «корп. 2», «стр. 1», «лит. А»
_ADDR_SUFFIX = (
    r"(?:[ \t]*(?:,[ \t]*)?(?:(?i:корп(?:ус)?|стр(?:оение)?|лит(?:ера)?|кв(?:артира)?|"
    r"оф(?:ис)?|пом(?:ещение)?|комн(?:ата)?|эт(?:аж)?)\.?|(?i:к|с)(?:\.|(?=\d)))"
    r"[ \t]*(?:№[ \t]*)?(?:\d{1,4}[А-Яа-я]?|[А-Я])(?![А-Яа-яЁёA-Za-z0-9]))"
)
_ADDR_SUFFIXES = rf"{_ADDR_SUFFIX}{{0,4}}"
# Запятая или пробелы между частями адреса
_ADDR_SEP = r"[ \t]*(?:,[ \t]*)?"
# Дом с пометкой не должен быть количеством: «д. 5 мм», «д. 5 шт» (единицы - только
# многобуквенные: «в», «м», «г» остаются предлогами и литерами).
_ADDR_UNIT_AFTER = (
    r"(?![ \t]*(?i:шт|штук|мм|см|кг|мкм|вт|квт|руб|рублей|коробок|упаковок|%)(?![а-яё]))"
)
# Дом без пометки («Ленина 5», «Ленина, 5») обязан закончиться знаком, концом строки или
# квартирой: «ул. Ленина 5 коробок» - это количество, не дом. Десятичная дробь не конец.
_ADDR_END = r"(?=[ \t]*(?:\Z|[\n\r]|\.(?!\d)|[,;:)!?»\"'\-](?!\d)))"
_ADDR_TAIL_INDEX = r"(?:[ \t]*,[ \t]*\d{6}(?!\d))?"


def _addr_house_part() -> str:
    """Дом с квартирой: либо с пометкой («д. 5»), либо голым номером на конце фразы."""
    return (
        rf"(?:{_ADDR_MARK}{_ADDR_HOUSE}{_ADDR_SUFFIXES}{_ADDR_UNIT_AFTER}"
        rf"|{_ADDR_HOUSE}{_ADDR_SUFFIXES}{_ADDR_END}){_ADDR_TAIL_INDEX}"
    )


# Контекст, после которого допустим адрес без ключевого слова улицы («Ленина 5»): город
# перед запятой («г. Москва, Ленина 5») или слово «адрес» («по адресу: Ленина 5»).
_ADDR_CONTEXT = (
    rf"(?:{_ADDR_LEFT}(?i:г(?:ород)?)\.?[ \t]*{_ADDR_WORD}(?:[ \t]+{_ADDR_WORD})?[ \t]*,[ \t]*"
    r"|(?<![А-Яа-яЁё])(?i:адрес\w{0,6})(?:[ \t]+[а-яё]{2,15}){0,2}(?:[ \t]*[:\-])?[ \t]*)"
)

ADDRESS_STREET_HOUSE_RE = re.compile(
    # 1) ключевое слово перед названием: «ул. Ленина, д. 5, кв. 12», «по улице Ленина 5»
    rf"{_ADDR_LEFT}(?P<pre>{_ADDR_DESIG}[ \t]*{_ADDR_NAME}{_ADDR_SEP}{_addr_house_part()})"
    # 2) название перед ключевым словом: «Ленина ул., д. 5»
    rf"|{_ADDR_LEFT}(?P<post>{_ADDR_NAME_POSTFIX}[ \t]+{_ADDR_DESIG}{_ADDR_SEP}"
    rf"{_addr_house_part()})"
    # 3) дом раньше улицы: «дом 5 по улице Ленина», «д. 5, ул. Ленина»
    rf"|{_ADDR_LEFT}(?P<house_first>(?i:д(?:ом)?)\.?[ \t]*(?:№[ \t]*)?{_ADDR_HOUSE}"
    rf"{_ADDR_SUFFIXES}{_ADDR_SEP}(?:(?i:по|на)[ \t]+)?{_ADDR_DESIG}[ \t]*{_ADDR_NAME})"
    # 4) без ключевого слова, но в адресном контексте: «г. Москва, Ленина 5»
    rf"|{_ADDR_CONTEXT}(?P<bare>{_ADDR_NAME}{_ADDR_SEP}{_addr_house_part()})"
)
_ADDR_DIGIT_RE = re.compile(r"\d")
_ADDR_GROUPS = ("pre", "post", "house_first", "bare")

# Индекс слева от адреса: «119019, ул. Арбат, д. 1» или «119019, г. Москва, ул. Арбат, 1».
# Между индексом и адресом допустимы до трёх сегментов без цифр (город, область).
_ADDR_INDEX_BEFORE_RE = re.compile(
    r"(?<![\d.,\-])(?P<idx>\d{6})(?!\d)(?P<gap>[ \t]*(?:,[ \t]*)?(?:[^\n,;\d]{1,40},[ \t]*){0,3})\Z"
)
ADDR_INDEX_WINDOW = 160  # сколько символов слева от улицы смотрим на индекс


def _street_house_matches(norm: str) -> list[tuple[int, int]]:
    """Диапазоны «улица + дом» (без индекса слева) в нормализованном тексте."""
    # Любая форма адреса содержит номер дома: текст без цифр (длинные списки инициалов, проза)
    # пропускается дешёвым поиском, а не прогоном тяжёлого шаблона по каждой позиции.
    if _ADDR_DIGIT_RE.search(norm) is None:
        return []
    spans: list[tuple[int, int]] = []
    for match in ADDRESS_STREET_HOUSE_RE.finditer(norm):
        for group in _ADDR_GROUPS:
            if match.group(group) is not None:
                spans.append(match.span(group))
                break
    return spans


def _address_parts(norm: str) -> list[tuple[int, int, bool]]:
    """Диапазоны адреса: (начало, конец, это_улица_с_домом). Индекс отдельно - False."""
    parts: list[tuple[int, int, bool]] = []
    for start, end in _street_house_matches(norm):
        index = _ADDR_INDEX_BEFORE_RE.search(norm, max(0, start - ADDR_INDEX_WINDOW), start)
        if index is None:
            parts.append((start, end, True))
        elif not index.group("gap").strip(" \t,"):
            # индекс вплотную к улице («119019, ул. Арбат, 1») входит в адрес
            parts.append((index.start("idx"), end, True))
        else:
            # город между индексом и улицей («119019, г. Москва, ул. ...»): город остаётся
            # открытым, поэтому индекс - отдельный диапазон
            parts.append((index.start("idx"), index.end("idx"), False))
            parts.append((start, end, True))
    return parts


def find_street_house_spans(text: str) -> list[tuple[int, int]]:
    """Диапазоны «улица + номер дома» (с квартирой и индексом, если он вплотную к улице).

    Это шаблон для guard: линейный, без морфологии. Город перед улицей в диапазон не входит.

    Args:
        text: Любой текст (внутри нормализуется, позиции совпадают с исходным).

    Returns:
        Непересекающиеся диапазоны (начало, конец), отсортированные по позиции.
    """
    return [(a, b) for a, b, street in _address_parts(normalize_text(text)) if street]


def find_address_spans(text: str) -> list[tuple[int, int]]:
    """Все диапазоны адреса к маскированию: «улица + дом» и индекс, отделённый городом.

    Args:
        text: Любой текст (внутри нормализуется, позиции совпадают с исходным).

    Returns:
        Непересекающиеся диапазоны (начало, конец), отсортированные по позиции.
    """
    return [(a, b) for a, b, _ in _address_parts(normalize_text(text))]


def has_street_house(text: str) -> bool:
    """Есть ли в тексте «улица + номер дома» (достаточно для отказа в guard)."""
    return bool(_street_house_matches(normalize_text(text)))
