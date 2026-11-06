"""Поиск персональных данных (ПДн) в тексте запроса.

Находки возвращаются только как типы. Само значение наружу не отдаётся и не логируется.
"""

import hashlib
import json
import logging
import os
import re
import threading
from collections import OrderedDict
from typing import Any

from labops_pii.allowlist import strip_allowed_words
from labops_pii.guard.address import ADDRESS_TYPE, AddressMode, address_mode
from labops_pii.guard.names import NAME_TYPE, NamesMode, has_person_name, names_mode
from labops_pii.pii_patterns import (
    ACCOUNT_RE,
    BARE_PHONE_RE,
    EMAIL_DOMAIN_RUN_RE,
    EMAIL_TLD_RE,
    PHONE_RE,
    find_card_spans,
    find_snils_spans,
    has_street_house,
    is_email_local_char,
    is_snils_checksum_valid,
    normalize_text,
)

# Предел анализируемого тела по умолчанию (байт). Отдельной настройки у детектора нет:
# приложение передаёт в scan_body свой предел тела (MAX_BODY_BYTES), поэтому предел
# сканирования всегда равен пределу тела и разойтись с ним не может. Больше предела не
# проверяем, а отказываем (fail closed): молча пропустить непроверенный хвост нельзя.
DEFAULT_MAX_SCAN_BYTES = 8 * 1024 * 1024

# Граница домена email по RFC 5321 (255). Локальная часть (до 64) отдельно не режется:
# достаточно одного допустимого символа слева от «@», длинная часть всё равно найдётся
EMAIL_DOMAIN_MAX = 255

# Типы находок
PHONE = "phone"
EMAIL = "email"
INN = "inn"
SNILS = "snils"
CARD = "card"
ACCOUNT = "account"
# ФИО (эвристика pii_guard/names.py). Искать ли его и блокировать ли - решает режим
# PII_GUARD_NAMES_MODE; детектор лишь сообщает факт, а политика отказа живёт в policy.py
NAME = NAME_TYPE
# Адрес («улица + дом», «индекс + улица»): шаблон общий с псевдонимизатором, режим -
# PII_GUARD_ADDRESS_MODE (pii_guard/address.py), политика отказа - в policy.py
ADDRESS = ADDRESS_TYPE

# Длины ИНН
INN_LEN_LEGAL = 10
INN_LEN_PERSON = 12

# Весовые коэффициенты контрольных сумм ИНН
INN10_WEIGHTS = (2, 4, 10, 3, 5, 9, 4, 6, 8)
INN12_WEIGHTS_1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
INN12_WEIGHTS_2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
CHECK_MOD = 11
CHECK_BASE = 10

# СНИЛС: длина и контрольное число - в общем модуле (pii_patterns), правило одно на оба слоя
SNILS_LEN = 11

# Токены-заменители вида [PERSON_1] не считаются ПДн; вырезаем их до поиска. Вырезаются
# только типы, которые реально выдаёт псевдонимизатор (PiiType в services/pseudonymizer), и
# порядковый номер до шести цифр: иначе оболочка «[INN_500100732259]» прятала бы ПДн.
TOKEN_TYPES = ("PERSON", "PHONE", "EMAIL", "INN", "OGRNIP", "OGRN", "SNILS", "PASSPORT",
               "CONTACT", "ORG", "CARD", "ACCOUNT", "ADDRESS")
TOKEN_NUMBER_MAX_DIGITS = 6
# Необязательная падежная метка - один код из закрытого набора («[PERSON_1|datv]»); фрагмент с
# другим кодом («[PERSON_1|дат]») не токен и проверяется как обычный текст.
TOKEN_CASE_CODES = ("nomn", "gent", "datv", "accs", "ablt", "loct")
TOKEN_RE = re.compile(
    rf"\[(?:{'|'.join(TOKEN_TYPES)})_\d{{1,{TOKEN_NUMBER_MAX_DIGITS}}}"
    rf"(?:\|(?:{'|'.join(TOKEN_CASE_CODES)}))?\]"
)
# Старый формат токенов прежнего edge-guard (восемь hex-знаков) - на переходный
# период. Восемь hex-знаков не вмещают ни телефон, ни ИНН, поэтому вырезание этих оболочек
# ПДн не прячет.
LEGACY_TOKEN_KINDS = ("PERSON", "PHONE", "EMAIL", "INN")
LEGACY_TOKEN_HASH_CHARS = 8
LEGACY_TOKEN_RE = re.compile(
    rf"\u27e6PII:(?:{'|'.join(LEGACY_TOKEN_KINDS)}):[0-9a-f]{{{LEGACY_TOKEN_HASH_CHARS}}}\u27e7"
)


def strip_tokens(text: str) -> str:
    """Заменяет токены-заменители пробелами (оба формата: текущий и старый v2).

    Args:
        text: Нормализованный текст.

    Returns:
        Текст без токенов.
    """
    return LEGACY_TOKEN_RE.sub(" ", TOKEN_RE.sub(" ", text))

# Хеши и UUID из проверки НЕ исключаются: строку вида «hex + ИНН» от хеша не отличить,
# и любое «вырезание похожего на хеш» открывает обход. Шлюз намеренно строгий: идентификаторы
# для модели должны формироваться без длинных цифровых серий (это забота отправителя).
# Шаблоны телефона, карт, счетов, СНИЛС и e-mail общие с псевдонимизатором (pii_patterns).
# Email ищется в два шага (поиск «@», затем ограниченные соседние части), а не одним
# регулярным выражением: прежний шаблон давал квадратичное время на длинных телах (S-04).
AT_RE = re.compile("@")
# Морфология ФИО (Natasha + pymorphy) убрана из guard в 0.7.0: на размеченном корпусе не нашла
# ни одного ФИО сверх эвристики, а на 75 752 реальных названиях товаров добавила 396
# ложных блокировок (известные люди, персонажи, сорта, сокращения). Переменная не действует.
NAMES_MORPH_ENV_REMOVED = "PII_GUARD_NAMES_MORPH"
_ENV_OFF_VALUES = frozenset({"", "0", "false", "no", "off"})
if os.environ.get(NAMES_MORPH_ENV_REMOVED, "").strip().lower() not in _ENV_OFF_VALUES:
    logging.getLogger(__name__).warning(
        "%s больше не действует (морфология ФИО убрана из guard в labops-pii 0.7.0)",
        NAMES_MORPH_ENV_REMOVED,
    )

DIGITS_RUN_RE = re.compile(r"(?<!\d)\d{10,12}(?!\d)")
# Списки чисел через ASCII «/» в названиях товаров: объёмы и размеры («425/660/1000 мл»,
# «M.2 2280/2260/2242/2230»). Нормализация делает из «/» дефис, и такой список выглядел
# как телефон 3-3-4 или карта 4-4-4-4 (замер на 75 752 названиях товаров, 05.11.26).
# Здесь «/» в таких списках меняется на «;» до нормализации (длина та же), чтобы группы не
# склеивались. Телефон «8/916/123/45/67» не трогается: в нём нет единицы измерения после
# списка и группы не по 4 цифры. Unicode-косые («⁄», «∕», «／») не трогаются вовсе.
# Предел элементов списка: без него на «7/ 7/ 7/ …» без единицы в конце поиск откатывался
# квадратично (часы на мегабайте). Списки размеров в названиях короче; длиннее - не трогаются.
SLASH_LIST_MAX_ITEMS = 12
_SLASH_LIST_MAX_TAIL = SLASH_LIST_MAX_ITEMS - 1
_SLASH_LIST_UNIT_RE = re.compile(
    r"(?<![\d/])\d+(?:[.,]\d+)?(?:\s?/\s?\d+(?:[.,]\d+)?)"
    rf"{{2,{_SLASH_LIST_MAX_TAIL}}}"
    r"(?=\s?(?:мл|л|г|гр|кг|мг|мм|см|м|шт|л\.|ml|l|g|kg|mm|cm|m|W|Вт|В|V|А|A)\b)",
    re.IGNORECASE,
)
_SLASH_LIST_FOUR_RE = re.compile(
    rf"(?<![\d/])\d{{4}}(?:/\d{{4}}){{2,{_SLASH_LIST_MAX_TAIL}}}(?![\d/])"
)


# Участок-кандидат вокруг каждой «/»: цифры, «/», пробелы и «.,» подряд. «/» ищется
# str.find, вправо участок дочитывается выражением без отката (*+), влево - циклом не дальше
# SLASH_RUN_MAX_CHARS: всё линейно, и ни один вызов не держит GIL на всё тело. Полное
# выражение списка запускается только на коротком участке (длиннее SLASH_RUN_MAX_CHARS - не
# список размеров из названия, остаётся как есть).
_SLASH_RUN_TAIL_RE = re.compile(r"[\d.,/\s]*+")
# «/» между цифрами - иначе это не список чисел (фиксированная длина, поиск без откатов)
_SLASH_BETWEEN_DIGITS_RE = re.compile(r"\d\s?/\s?\d")
_SLASH_RUN_PUNCT = frozenset("./,")
SLASH_RUN_MAX_CHARS = 256
# После участка - единица измерения: буквы до первой не-буквы (не больше предела)
_UNIT_TAIL_RE = re.compile(r"[^\W\d_]{0,8}")


def _is_run_char(char: str) -> bool:
    """Символ участка-кандидата (как [\\d.,/\\s] в выражении)."""
    return char.isdecimal() or char.isspace() or char in _SLASH_RUN_PUNCT


def _split_slash_lists(text: str) -> str:
    """Меняет «/» на «;» в списках размеров и объёмов (длина строки не меняется).

    Прямой re.sub по всему телу держал GIL целиком и откатывался на «7/ 7/ 7/ …» (секунды на
    мегабайте, цикл событий стоял). Здесь тяжёлое выражение видит только короткий участок
    с «/» и следующую за ним единицу измерения.
    """
    parts: list[str] = []
    done = 0
    size = len(text)
    hit = _SLASH_BETWEEN_DIGITS_RE.search(text) if "/" in text else None
    while hit is not None:
        slash = text.index("/", hit.start())
        tail = _SLASH_RUN_TAIL_RE.match(text, slash)
        end = tail.end() if tail is not None else slash + 1
        start = slash
        floor = max(0, end - SLASH_RUN_MAX_CHARS - 1)
        while start > floor and _is_run_char(text[start - 1]):
            start -= 1
        if end - start <= SLASH_RUN_MAX_CHARS:
            unit = _UNIT_TAIL_RE.match(text, end)
            stop = unit.end() if unit is not None else end
            # Символ после единицы нужен для \b; до участка - не цифра и не «/» по построению
            segment = text[start : min(stop + 1, size)]
            replaced = _SLASH_LIST_UNIT_RE.sub(_semicolons, segment)
            replaced = _SLASH_LIST_FOUR_RE.sub(_semicolons, replaced)
            if replaced != segment:
                parts.append(text[done:start])
                parts.append(replaced[: end - start])
                done = end
        hit = _SLASH_BETWEEN_DIGITS_RE.search(text, end)
    if not parts:
        return text
    parts.append(text[done:])
    return "".join(parts)


def _semicolons(match: re.Match[str]) -> str:
    return match.group(0).replace("/", ";")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


# Регулярные выражения в Python не отпускают GIL, поэтому длинный текст сканируется окнами:
# между окнами поток уступает GIL, и цикл событий не стоит секундами (R3-SEC-15). Окна
# перекрываются на OVERLAP символов: любое совпадение короче перекрытия целиком попадает
# хотя бы в одно окно. Совпадения короче WINDOW_CUT_LOOKBACK не режутся посередине слова:
# граница сдвигается к ближайшему пробелу.
SCAN_WINDOW = 256 * 1024
SCAN_OVERLAP = 512
WINDOW_CUT_LOOKBACK = 1024


class BodyTooLargeError(ValueError):
    """Тело больше предела сканирования: проверка не выполняется, запрос отклоняется."""


class BodyNotJsonError(ValueError):
    """Тело не разбирается как JSON: проверять его как структуру нельзя, запрос отклоняется."""


def _windows(text: str) -> list[tuple[int, int]]:
    """Режет текст на перекрывающиеся окна (начало, конец) для поиска без блокировки GIL."""
    size = len(text)
    if size <= SCAN_WINDOW:
        return [(0, size)]
    result: list[tuple[int, int]] = []
    start = 0
    while start < size:
        cut = min(start + SCAN_WINDOW, size)
        if cut < size:
            space = max(
                text.rfind(" ", cut - WINDOW_CUT_LOOKBACK, cut),
                text.rfind("\n", cut - WINDOW_CUT_LOOKBACK, cut),
            )
            cut = space + 1 if space > start else cut
        result.append((start, min(cut + SCAN_OVERLAP, size)))
        if cut >= size:
            break
        start = max(cut - SCAN_OVERLAP, start + 1)
    return result


# Шаблон адреса тяжелее остальных и срезов не принимает, поэтому окно режется ещё мельче:
# между кусками поток уступает GIL (замер: ~0,3 с на окно 256 КБ против ~0,03 с на кусок).
# Куски перекрываются на SCAN_OVERLAP: адрес («индекс + город + улица + дом + квартира»)
# заведомо короче.
ADDRESS_SCAN_CHUNK = 32 * 1024


def _has_address(clean: str, start: int, end: int) -> bool:
    """Есть ли адрес в окне [start, end) нормализованного текста (кусками, без GIL-пауз)."""
    pos = start
    while pos < end:
        stop = min(pos + ADDRESS_SCAN_CHUNK, end)
        if has_street_house(clean[pos:min(stop + SCAN_OVERLAP, end)]):
            return True
        pos = stop
    return False


def has_email(text: str) -> bool:
    """Ищет email за линейное время.

    Для каждого «@» смотрим один символ слева и не больше EMAIL_DOMAIN_MAX справа.
    Домен: непустые метки (буквы любого алфавита, цифры, «-») через точку, последняя метка
    из 2+ букв; кириллические адреса («иван@пример.рф») ищутся наравне с латинскими.

    Args:
        text: Текст для проверки.

    Returns:
        True, если найден адрес.
    """
    for at in AT_RE.finditer(text):
        pos = at.start()
        if pos == 0 or not is_email_local_char(text[pos - 1]):
            continue
        run = EMAIL_DOMAIN_RUN_RE.match(text, pos + 1, pos + 1 + EMAIL_DOMAIN_MAX)
        if run is None:
            continue
        domain = run.group(0)
        if domain.startswith("."):
            continue
        # Пустая метка («..») обрывает допустимую часть домена
        empty = domain.find("..")
        if empty != -1:
            domain = domain[: empty + 1]
        if EMAIL_TLD_RE.search(domain):
            return True
    return False


def _inn10_valid(digits: str) -> bool:
    """Проверяет контрольную сумму ИНН юрлица (10 цифр)."""
    nums = [int(c) for c in digits]
    total = sum(w * n for w, n in zip(INN10_WEIGHTS, nums))
    return total % CHECK_MOD % CHECK_BASE == nums[9]


def _inn12_valid(digits: str) -> bool:
    """Проверяет обе контрольные цифры ИНН физлица (12 цифр)."""
    nums = [int(c) for c in digits]
    first = sum(w * n for w, n in zip(INN12_WEIGHTS_1, nums)) % CHECK_MOD % CHECK_BASE
    second = sum(w * n for w, n in zip(INN12_WEIGHTS_2, nums)) % CHECK_MOD % CHECK_BASE
    return first == nums[10] and second == nums[11]


def is_valid_inn(digits: str) -> bool:
    """Проверяет ИНН по длине и контрольной сумме."""
    if len(digits) == INN_LEN_LEGAL:
        return _inn10_valid(digits)
    if len(digits) == INN_LEN_PERSON:
        return _inn12_valid(digits)
    return False


def is_valid_snils(digits: str) -> bool:
    """Проверяет СНИЛС (11 цифр) по контрольному числу (общее правило pii_patterns)."""
    return is_snils_checksum_valid(digits)


def _find_digit_types(clean: str, start: int, end: int) -> set[str]:
    """Ищет телефоны, ИНН, СНИЛС, карты и счета в окне [start, end) нормализованного текста.

    Левый контекст (lookbehind) шаблоны видят за границей окна, правый обрезан концом окна.
    """
    found: set[str] = set()
    if PHONE_RE.search(clean, start, end) or any(
        not is_valid_inn(m.group(1)) for m in BARE_PHONE_RE.finditer(clean, start, end)
    ):
        found.add(PHONE)
    for match in DIGITS_RUN_RE.finditer(clean, start, end):
        digits = match.group(0)
        # ИНН любой длины (организации тоже) - ПДн при любых настройках: решение владельца
        # 05.11.26, отменившее исключение для 10-значного ИНН в одном из профилей (0.7.0)
        if len(digits) != SNILS_LEN and is_valid_inn(digits):
            found.add(INN)
    # СНИЛС по общему правилу: псевдонимизатор маскирует ровно эти находки (R9-A4-04)
    if find_snils_spans(clean, start, end):
        found.add(SNILS)
    if find_card_spans(clean, start, end):
        found.add(CARD)
    if ACCOUNT_RE.search(clean, start, end):
        found.add(ACCOUNT)
    return found


def find_pii_types(text: str) -> set[str]:
    """Ищет ПДн в строке.

    Args:
        text: Текст для проверки.

    Returns:
        Множество типов находок (phone, email, inn, snils, card, account, name, address).
        Значения не возвращаются. «name» и «address» появляются, пока их режим не off;
        блокируют ли они запрос, решает labops_pii.guard.policy.
    """
    # Сначала нормализация (NFKC, тире и «/» -> «-», NBSP -> пробел), потом вырезание токенов
    clean = strip_tokens(normalize_text(_split_slash_lists(text)))
    found: set[str] = set()
    if has_email(clean):
        found.add(EMAIL)
    search_names = names_mode() is not NamesMode.OFF
    search_address = address_mode() is not AddressMode.OFF
    # Белый список слов (PII_ALLOWED_WORDS - не ФИО): слова затираются пробелами той же длины
    name_text = strip_allowed_words(clean) if search_names else clean
    for start, end in _windows(clean):
        found |= _find_digit_types(clean, start, end)
        # Окна общие с цифровыми детекторами: длинный текст не держит GIL одним проходом
        if search_names and NAME not in found and has_person_name(name_text, start, end):
            found.add(NAME)
        # Токены [ADDRESS_n] уже вырезаны выше; перекрытие окон больше любого адреса,
        # позиции наружу не отдаются
        if search_address and ADDRESS not in found and _has_address(clean, start, end):
            found.add(ADDRESS)
    return found


# Кэш прохода по строкам JSON: запрос к модели на каждом шаге агента несёт всю историю, то есть
# те же строки снова и снова (замер: ~800 мс CPU на 1,3 МБ). Ключ - только sha256 строки,
# значение - только типы находок: ни текста, ни значений ПДн в кэше нет. Предел и по числу
# записей, и по суммарному объёму учтённых строк (в символах), иначе кэш рос бы за телом.
STRING_CACHE_MAX_ENTRIES = 4096
STRING_CACHE_MAX_CHARS = 4 * 1024 * 1024
# Короче этого строку проще проверить заново, чем считать хэш и держать запись
STRING_CACHE_MIN_CHARS = 64


def _scan_modes() -> tuple[NamesMode, AddressMode]:
    """Режимы, от которых зависит результат find_pii_types (ключ актуальности кэша)."""
    return names_mode(), address_mode()


class _StringScanCache:
    """Ограниченный LRU: sha256(строка) -> frozenset типов находок.

    Потокобезопасен (проверки могут идти из разных потоков). Строка длиннее предела объёма
    в кэш не попадает вовсе. Результат детектора от кэша не зависит: find_pii_types чистая
    функция строки, кэш лишь не даёт посчитать её дважды.
    """

    def __init__(self, max_entries: int, max_chars: int) -> None:
        self._max_entries = max_entries
        self._max_chars = max_chars
        self._items: OrderedDict[bytes, tuple[frozenset[str], int]] = OrderedDict()
        self._chars = 0
        self._mode = _scan_modes()
        self._lock = threading.Lock()

    def find(self, text: str) -> frozenset[str]:
        """Возвращает типы находок в строке, пользуясь кэшем."""
        size = len(text)
        if size < STRING_CACHE_MIN_CHARS or size > self._max_chars:
            return frozenset(find_pii_types(text))
        # surrogatepass: строки из JSON могут нести одиночные суррогаты, хэш не должен падать
        key = hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).digest()
        # От режимов ФИО и адреса зависит, ищутся ли «name» и «address»: после смены режима (в бою -
        # только
        # перезапуск, в тестах - переменная окружения) записи прежнего режима устарели
        mode = _scan_modes()
        if mode != self._mode:
            self.clear()
            self._mode = mode
        with self._lock:
            hit = self._items.get(key)
            if hit is not None:
                self._items.move_to_end(key)
                return hit[0]
        types = frozenset(find_pii_types(text))
        with self._lock:
            if key not in self._items:
                self._items[key] = (types, size)
                self._chars += size
                while self._items and (
                    len(self._items) > self._max_entries or self._chars > self._max_chars
                ):
                    _, (_, dropped) = self._items.popitem(last=False)
                    self._chars -= dropped
        return types

    def clear(self) -> None:
        """Очищает кэш (для тестов)."""
        with self._lock:
            self._items.clear()
            self._chars = 0

    def stats(self) -> tuple[int, int]:
        """Возвращает (число записей, суммарный объём в символах)."""
        with self._lock:
            return len(self._items), self._chars


_STRING_CACHE = _StringScanCache(STRING_CACHE_MAX_ENTRIES, STRING_CACHE_MAX_CHARS)


def _walk_strings(node: Any) -> list[str]:
    """Собирает все строки (значения и ключи) из разобранного JSON, без рекурсии.

    Объекты разбираются списком пар, поэтому повторяющиеся ключи не теряют значения.
    """
    out: list[str] = []
    stack: list[Any] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            out.append(current)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
        elif isinstance(current, (int, float)) and not isinstance(current, bool):
            out.append(str(current))
    return out


def decode_body(body: bytes) -> str:
    """Декодирует тело по BOM/нулевым байтам так же, как это делает json.loads(bytes).

    Поддерживаются UTF-8 (с BOM и без), UTF-16 и UTF-32 (любой порядок байт). Ошибки
    декодирования заменяются, чтобы испорченный байт не отменял проверку остального.
    """
    try:
        encoding = json.detect_encoding(body)
    except (UnicodeDecodeError, ValueError):
        encoding = "utf-8"
    return body.decode(encoding, errors="replace")


def expand_unicode_escapes(text: str) -> str:
    """Раскрывает \\uXXXX (включая суррогатные пары) в сыром тексте без разбора JSON."""
    if "\\u" not in text:
        return text
    expanded = UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return expanded.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


# Почта аккаунта подписки, которую CLI сам вставляет в контекст каждого запроса
# («# userEmail»: The user's email address is <почта>. Use it only to identify the user...).
# Это логин аккаунта у самого провайдера, не данные клиента; отключить вставку CLI не даёт.
# Вырезается только почта ровно в этом шаблоне и только для апстримов, которым её разрешено
# видеть (allow_account_email); любая другая почта в теле по-прежнему находка.
# Между рамками допускается ровно один адрес почты: прежний шаблон брал любые 254 символа без
# пробелов, и в «почту» можно было вписать телефон, ИНН и карту через запятую (обход guard)
ACCOUNT_EMAIL_RE = re.compile(
    r"(The user's email address is )"
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,63}"
    r"(\. Use it only to identify the user)"
)


def strip_account_email(text: str) -> str:
    """Убирает почту аккаунта из шаблона CLI «# userEmail» (остальной текст не меняется)."""
    if "The user's email address is " not in text:
        return text
    return ACCOUNT_EMAIL_RE.sub(r"\1 \2", text)


def scan_body(
    body: bytes,
    max_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    require_json: bool = False,
    allow_account_email: bool = False,
) -> set[str]:
    """Проверяет тело запроса целиком (fail closed: разбор JSON ничего не пропускает).

    Проверяются всегда: сырой текст (в кодировке по BOM и как UTF-8), он же с раскрытыми
    \\u-экранированиями, и каждая строка разобранного JSON. Разбор не может провалом
    отменить остальные проверки: целые числа не преобразуются (нет предела цифр), BOM и
    UTF-16/32 декодируются, при ошибке разбора остаются первые две проверки.

    Args:
        body: Тело запроса.
        max_bytes: Предел размера тела; приложение передаёт свой настроенный предел.
        require_json: Тело обязано быть JSON (так шлюз и принимает запросы); иначе отказ.
        allow_account_email: Не считать находкой почту аккаунта в шаблоне CLI «# userEmail».

    Returns:
        Множество типов находок.

    Raises:
        BodyTooLargeError: Тело больше max_bytes.
        BodyNotJsonError: require_json задан, а тело не разбирается как JSON.
    """
    if len(body) > max_bytes:
        raise BodyTooLargeError("body exceeds scan limit")
    # Один decode_body на тело: раньше он считался дважды (набор текстов и разбор JSON)
    parsed_text = decode_body(body)
    texts = {parsed_text, body.decode("utf-8", errors="replace")}
    found: set[str] = set()
    if allow_account_email:
        texts = {strip_account_email(text) for text in texts}
    for raw in texts:
        found |= find_pii_types(raw)
        expanded = expand_unicode_escapes(raw)
        if expanded != raw:  # без экранирований второй проход ничего нового не даст
            found |= find_pii_types(expanded)
    try:
        parsed = json.loads(
            parsed_text.lstrip("\ufeff"), parse_int=str, parse_float=str,
            object_pairs_hook=list,
        )
    except (ValueError, RecursionError) as exc:
        if require_json:
            raise BodyNotJsonError("body is not valid json") from exc
        return found
    # Сырой проход выше кэша не использует: он один на тело. Строки же повторяются между
    # запросами, поэтому здесь кэш (результат тот же, что у прямого find_pii_types).
    for chunk in _walk_strings(parsed):
        found |= _STRING_CACHE.find(strip_account_email(chunk) if allow_account_email else chunk)
    return found
