"""Эвристика ФИО в тексте запроса (этап 187, часть В).

В образе guard нет морфологии (только fastapi, uvicorn, httpx), и добавлять её не нужно:
русское ФИО узнаётся по окончаниям, а не по лемме. Отчество однозначно по суффиксу
(-ович/-евич/-ьич, -овна/-евна/-ична) в любом падеже; фамилия узнаётся по суффиксу
(-ов/-ев/-ин/-ын/-ский/-цкий/-енко/-чук), имя - по компактному словарю частых имён с общим
набором падежных окончаний. Одно имя, одна фамилия или одно слово с заглавной буквы ПДн не
считаются: нужна связка (имя + отчество, фамилия + имя, фамилия + инициалы, инициалы +
фамилия, «ИП» + фамилия). Так отказов по обычным словам и названиям почти нет.

Известные пределы (ложноотрицательные, их меряет режим log_only): латиница
(«John Smith»), фамилия без суффикса и без инициалов («Цой Виктор»), одиночная фамилия,
имя в нижнем регистре без отчества.

Находки - только факт («есть ФИО»), позиции и значения наружу не отдаются.
Время линейное: один проход регулярным выражением по словам (слово не длиннее
TOKEN_MAX_LEN), в окне держится не больше CHAIN_MAX слов; вложенных повторов в шаблонах нет.
"""

from __future__ import annotations

import os
import re
from collections import deque
from enum import Enum
from functools import lru_cache


# Переменная окружения режима и значение по умолчанию
NAMES_MODE_ENV = "PII_GUARD_NAMES_MODE"
NAME_TYPE = "name"


class NamesMode(str, Enum):
    """Режим проверки ФИО."""

    OFF = "off"
    LOG_ONLY = "log_only"
    ENFORCE = "enforce"


# Нейтральное значение по умолчанию: ФИО в guard не ищутся, пока потребитель не задал
# PII_GUARD_NAMES_MODE (log_only или enforce)
DEFAULT_NAMES_MODE = NamesMode.OFF


def default_names_mode() -> NamesMode:
    """Режим ФИО по умолчанию (когда PII_GUARD_NAMES_MODE не задана)."""
    return DEFAULT_NAMES_MODE


def parse_names_mode(raw: str | None) -> NamesMode:
    """Разбирает значение PII_GUARD_NAMES_MODE строго.

    Пусто или не задано - режим по умолчанию (off). Неизвестное значение - ошибка:
    приложение при старте не запускается, чтобы опечатка («enforсe», «on») не превратилась
    молча в выключенную защиту.

    Raises:
        ValueError: Значение не из off / log_only / enforce.
    """
    if raw is None or not raw.strip():
        return default_names_mode()
    try:
        return NamesMode(raw.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in NamesMode)
        raise ValueError(f"{NAMES_MODE_ENV} должна быть одним из: {allowed}") from exc


def names_mode() -> NamesMode:
    """Режим из окружения на момент вызова.

    Неизвестное значение здесь (минуя проверку при старте приложения) трактуется как
    enforce: детектор не может бросить исключение посреди проверки, а при сомнении
    безопаснее отказать, чем пропустить (fail closed).
    """
    try:
        return parse_names_mode(os.environ.get(NAMES_MODE_ENV))
    except ValueError:
        return NamesMode.ENFORCE


# --- Параметры разбора -----------------------------------------------------------

# Слово длиннее этого не разбирается (защита от длинных «слов»); обычные слова короче
TOKEN_MAX_LEN = 64
# Между словами одного ФИО допустимы только пробелы/табы и не больше этого числа
GAP_MAX = 2
# Сколько последних слов держим в окне (нужны максимум три слова ФИО и одно перед ними)
CHAIN_MAX = 4
SURNAME_MIN_LEN = 5
PATRONYMIC_MIN_LEN = 5
NAME_STEM_MIN_LEN = 3

# Слово: кириллица, дефисные части, необязательная точка (конец предложения или инициал)
TOKEN_RE = re.compile(r"[А-Яа-яЁё]+(?:-[А-Яа-яЁё]+)*\.?")

# Фамилии: суффикс + падежное окончание. Слова приведены к нижнему регистру, «ё» -> «е».
_SURNAME_RE = re.compile(
    r"[а-я]+(?:"
    r"(?:ов|ев|ин|ын)(?:а|у|ым|е|ы|ых|ой|ою)?"
    r"|(?:ск|цк)(?:ий|ого|ому|им|ом|ая|ой|ую|ие|их)"
    r"|(?:енко|чук|юк)"
    r")"
)
# Отчества. Мужские и -овна/-евна распознаются сами; формы -ична/-инична (общие слова
# вроде «практична», «логична» им родственны по окончанию) принимаются только рядом с именем
_PATR_MALE_RE = re.compile(r"[а-я]*(?:(?:ов|ев)ич|ьич)(?:а|у|ем|е)?")
_PATR_FEMALE_RE = re.compile(r"[а-я]+(?:ов|ев)н(?:а|ы|е|у|ой|ою)")
_PATR_FEMALE_WEAK_RE = re.compile(r"[а-я]+ичн(?:а|ы|е|у|ой|ою)")
# Слова на -овна/-евна, не являющиеся отчествами
_PATR_EXCLUDED = frozenset({"королевна", "царевна", "королевне", "царевне"})

# Имена (именительный падеж, «е» вместо «ё»). Неоднозначные с нарицательными словами и
# марками (Роман, Вера, Надежда, Любовь, Роза, Лада, Мира, Марина) намеренно не включены:
# рядом с отчеством они всё равно находятся правилом «слово + отчество».
_NAMES = """
александр алексей анатолий андрей антон аркадий арсений артем артур борис вадим валентин
валерий василий виктор виталий владимир владислав вячеслав геннадий георгий григорий давид
даниил денис дмитрий евгений егор захар иван игорь илья кирилл константин лев леонид максим
матвей михаил никита николай олег павел петр роберт руслан савва семен сергей станислав
степан тимофей тимур федор филипп эдуард юрий яков ярослав марк глеб данил богдан назар
ринат рустам айрат ильдар марат радик рамиль камиль шамиль эльдар фарид азат мурат ахмед
магомед
александра алина алла анастасия анна антонина валентина валерия варвара василиса вероника
виктория галина дарья диана евгения екатерина елена елизавета жанна зинаида злата инна
ирина карина кира кристина ксения лариса лидия людмила маргарита мария милана наталья
наталия оксана олеся ольга полина раиса регина светлана софия софья тамара татьяна ульяна
юлия яна алена эльвира рената лилия гульнара айгуль ляйсан эльмира зарина дина эльза нина
"""
# Окончания, с которыми основа имени считается тем же именем (общий набор на все склонения:
# щедрость безопасна, потому что одно имя без фамилии/отчества ничего не значит)
_NAME_ENDINGS = frozenset(
    {"", "а", "я", "у", "ю", "е", "ы", "и", "й", "ь", "ом", "ем", "ой", "ей", "ою", "ею", "ью"}
)
_NAME_LAST_VOWELS = "айья"


def _stem(name: str) -> str:
    """Основа имени: без последней гласной/«й»/«ь»."""
    return name[:-1] if name and name[-1] in _NAME_LAST_VOWELS else name


_NAME_STEMS = frozenset(_stem(n) for n in _NAMES.split() if len(_stem(n)) >= NAME_STEM_MIN_LEN)
# Самое длинное окончание в наборе: столько символов с конца пробуем отрезать
_ENDING_MAX = max(len(e) for e in _NAME_ENDINGS)

# --- Белые списки ложных срабатываний ---------------------------------------------

# Слова, которые не бывают частью ФИО в нашей связке: должности, организационные формы,
# нарицательные слова на -ин/-ов, совпадающие с фамилией по суффиксу. «ИП» здесь НЕТ
# намеренно: ИП Иванов - это физлицо, ПДн (см. правило _is_ip_marker).
_STOP_WORDS = frozenset(
    """
    директор генеральный исполнительный коммерческий технический финансовый главный
    менеджер бухгалтер инженер начальник руководитель специалист заместитель администратор
    председатель президент учредитель кладовщик водитель продавец консультант оператор
    ооо ао пао зао оао нао гуп муп фгуп тоо нко ано фонд компания группа торговый дом
    магазин камин бензин витамин стойка склад сервис офис отдел цех база завод фабрика
    россия москва петербург область край республика район город
    инн огрн огрнип кпп снилс бик окпо оквэд паспорт телефон email почта
    """.split()
)
# Слово перед связкой, после которого фамилия - это название улицы, площади, учреждения
# («ул. Александра Невского», «имени Ивана Петрова»)
_CONTEXT_STOP = frozenset(
    """
    ул улица улице улицы пр проспект проспекте пер переулок пл площадь площади наб
    набережная бульвар бульваре шоссе проезд тупик им имени памяти школа гимназия
    """.split()
)
_IP_MARKERS = frozenset({"ип", "предприниматель"})


# Кэш признаков слова: в обычном тексте слова повторяются, а признаки зависят только от слова.
# Предел по числу записей ограничивает память (ключ - короткое слово до TOKEN_MAX_LEN).
WORD_CACHE_SIZE = 8192
# Общий хвост всех отчеств: дешёвая проверка перед регулярными выражениями
_PATR_TAILS = ("ич", "ича", "ичу", "ичем", "иче", "на", "ны", "не", "ну", "ной", "ною")


def _is_cap(raw: str) -> bool:
    """Слово начинается с заглавной; все буквы заглавные допустимы при длине от 3."""
    if not raw[0].isupper():
        return False
    rest = raw[1:]
    return len(raw) == 1 or rest.islower() or (len(raw) >= 3 and raw.isupper())


@lru_cache(maxsize=WORD_CACHE_SIZE)
def _is_name(word: str) -> bool:
    """Слово - частое имя в любом падеже (основа из словаря + допустимое окончание)."""
    for part in word.split("-"):
        if len(part) < NAME_STEM_MIN_LEN:
            continue
        for cut in range(min(_ENDING_MAX, len(part)) + 1):
            base = part[: len(part) - cut]
            if base in _NAME_STEMS and part[len(base):] in _NAME_ENDINGS:
                return True
    return False


@lru_cache(maxsize=WORD_CACHE_SIZE)
def _is_surname(word: str) -> bool:
    """Слово оканчивается как фамилия (любая дефисная часть)."""
    return any(
        len(p) >= SURNAME_MIN_LEN and _SURNAME_RE.fullmatch(p) is not None
        for p in word.split("-")
    )


@lru_cache(maxsize=WORD_CACHE_SIZE)
def _patr_kind(word: str) -> int:
    """0 - не отчество, 1 - отчество само по себе, 2 - слабое (-ична), нужно имя рядом."""
    if len(word) < PATRONYMIC_MIN_LEN or not word.endswith(_PATR_TAILS):
        return 0
    if word in _PATR_EXCLUDED:
        return 0
    if _PATR_MALE_RE.fullmatch(word) or _PATR_FEMALE_RE.fullmatch(word):
        return 1
    return 2 if _PATR_FEMALE_WEAK_RE.fullmatch(word) else 0


@lru_cache(maxsize=WORD_CACHE_SIZE)
def _is_stop(word: str) -> bool:
    """Слово из белого списка (должность, орг. форма, нарицательное)."""
    return any(p in _STOP_WORDS for p in word.split("-"))


class _Tok:
    """Слово текста: позиции и дешёвые признаки; остальное считается лениво по слову."""

    __slots__ = ("start", "end", "word", "cap", "initial", "sentence_end")

    def __init__(self, start: int, end: int, word: str, cap: bool, initial: bool,
                 sentence_end: bool) -> None:
        self.start = start
        self.end = end
        self.word = word  # нижний регистр, «ё» -> «е», без точки
        self.cap = cap  # с заглавной (или ЗАГЛАВНЫМИ при длине от 3)
        self.initial = initial  # одна заглавная буква с точкой
        self.sentence_end = sentence_end  # точка после слова, не инициал

    @property
    def name(self) -> bool:
        return _is_name(self.word)

    @property
    def surname(self) -> bool:
        return _is_surname(self.word)

    @property
    def patr(self) -> bool:
        return _patr_kind(self.word) == 1

    @property
    def patr_weak(self) -> bool:
        return _patr_kind(self.word) == 2

    @property
    def stop(self) -> bool:
        return _is_stop(self.word)


@lru_cache(maxsize=WORD_CACHE_SIZE)
def _is_inert(raw: str) -> bool:
    """Строчное слово, которое не может быть частью связки ФИО и не задаёт контекст.

    Такое слово просто разрывает цепочку (имя, «и», фамилия - не ФИО), поэтому объект слова
    для него не строится: это главная экономия времени на обычном тексте.
    """
    if not raw[0].islower():
        return False
    word = (raw[:-1] if raw[-1] == "." else raw).replace("ё", "е")
    return (
        word not in _CONTEXT_STOP
        and word not in _IP_MARKERS
        and _patr_kind(word) == 0
        and not _is_name(word)  # «иван иванович» в нижнем регистре
    )


def _classify(match: re.Match[str]) -> _Tok | None:
    """Строит слово; слишком длинные слова пропускаются."""
    raw = match.group(0)
    dotted = raw[-1] == "."
    text = raw[:-1] if dotted else raw
    if len(text) > TOKEN_MAX_LEN:
        return None
    initial = dotted and len(text) == 1 and text.isupper()
    if "-" in text:
        cap = all(_is_cap(p) for p in text.split("-"))
    else:
        cap = _is_cap(text)
    return _Tok(
        match.start(), match.end(), text.lower().replace("ё", "е"), cap, initial,
        dotted and not initial,
    )


def _near(text: str, prev: _Tok, cur: _Tok) -> bool:
    """Между словами только короткий пробел (у инициала с точкой допускается пустой)."""
    gap = cur.start - prev.end
    if gap == 0:
        return True
    return gap <= GAP_MAX and text[prev.end:cur.start].strip(" \t") == ""


def _is_person_chain(chain: list[_Tok], before: _Tok | None) -> bool:
    """Проверяет, что последнее слово цепочки замыкает ФИО (цепочка - слова подряд).

    Args:
        chain: Слова подряд (1..CHAIN_MAX), последнее - только что прочитанное.
        before: Слово перед цепочкой через пробел (для контекста улицы) или None.
    """
    cur = chain[-1]
    # Быстрый отказ: замыкать связку может заглавное слово, инициал или отчество; обычный
    # текст из строчных слов не доходит до остальных проверок
    if len(chain) < 2 or not (cur.cap or cur.initial or _patr_kind(cur.word)):
        return False
    if cur.stop:
        return False
    prev = chain[-2]
    if prev.stop:
        # Должность, орг. форма и нарицательное слово не часть ФИО («ИП» в стоп-списке нет)
        return False
    # Контекст улицы/учреждения: слово прямо перед связкой
    head = chain[0]
    if before is not None and before.word in _CONTEXT_STOP:
        return False
    if head.word in _CONTEXT_STOP:
        return False

    # Отчество: имя + отчество либо любое слово с заглавной + отчество
    if cur.patr and cur.cap and prev.cap and not prev.initial:
        return True
    if cur.patr and prev.name:
        return True
    if cur.patr_weak and prev.name and prev.cap:
        return True
    # Фамилия + имя / имя + фамилия (обе с заглавной; нужен суффикс фамилии и словарное имя)
    if cur.cap and prev.cap and not prev.initial and not cur.initial:
        if (cur.surname and prev.name) or (cur.name and prev.surname):
            return True
    # Инициалы: «Иванов И.И.», «Иванов И.» (фамилия по суффиксу), «Цой В.Р.» (два инициала)
    if cur.initial:
        if prev.initial and len(chain) >= 3:
            third = chain[-3]
            return third.cap and not third.initial and not third.stop
        return prev.cap and prev.surname and not prev.initial
    if prev.initial and cur.cap and not cur.initial:
        # «И.И. Иванов» (два инициала) или «И. Иванов» с фамилией по суффиксу
        if len(chain) >= 3 and chain[-3].initial:
            return True
        return cur.surname
    # ИП / индивидуальный предприниматель + фамилия или имя: это физлицо
    if prev.word in _IP_MARKERS and cur.cap and (cur.surname or cur.name):
        return True
    return False


def has_person_name(text: str, start: int = 0, end: int | None = None) -> bool:
    """Ищет ФИО в окне [start, end) текста за линейное время.

    Args:
        text: Текст (уже нормализованный: NFKC, NBSP -> пробел).
        start: Начало окна.
        end: Конец окна (по умолчанию конец текста).

    Returns:
        True, если найдена связка, похожая на ФИО. Значение не возвращается.
    """
    window: deque[_Tok] = deque(maxlen=CHAIN_MAX)
    for match in TOKEN_RE.finditer(text, start, len(text) if end is None else end):
        if match.end() - match.start() > TOKEN_MAX_LEN:
            # Слишком длинное «слово»: не имя; в кэши его не пускаем (ключи были бы огромными)
            window.clear()
            continue
        if _is_inert(match.group(0)):
            window.clear()
            continue
        tok = _classify(match)
        if tok is None:
            window.clear()
            continue
        if window and not _near(text, window[-1], tok):
            window.clear()
        if window:
            # Цепочка: до двух предыдущих слов; слово с точкой (конец предложения) её обрывает
            chain: list[_Tok] = [tok]
            index = len(window) - 1
            while index >= 0 and len(chain) < CHAIN_MAX - 1 and not window[index].sentence_end:
                chain.insert(0, window[index])
                index -= 1
            # Слово перед цепочкой (для контекста «ул.», «имени»); его точка не мешает
            before = window[index] if index >= 0 else None
            if _is_person_chain(chain, before):
                return True
        window.append(tok)
    return False
