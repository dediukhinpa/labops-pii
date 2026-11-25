"""ФИО по якорю «имя + отчество» без NER: детерминированная страховка от пропусков модели.

NER (Natasha) зависит от контекста: «Позвоните Иванов Сергей Петрович завтра.» и «Менеджер
Петрова Анна Сергеевна, отдел продаж» он не размечает вовсе, и полное ФИО уходило в модель
открытым (матрица кейсов 25.11.2026). Пара «словарное имя + отчество» почти никогда не бывает
ничем, кроме человека, поэтому служит якорем: от неё находка расширяется на фамилию слева
(«Иванов Сергей Петрович», «Иванов, Сергей Петрович») или справа («Сергей Петрович Иванов»).

Фамилию морфология узнаёт не всегда: «Головач» и «Белых» — словарные нарицательное и
прилагательное, «Пехтышева» вне словаря, у «Салтыков-Щедрин» дефис. Рядом с отчеством этого
достаточно: фамилией считается любое одушевлённое существительное, слово с разбором
«фамилия», слово вне словаря или прилагательное на «-ых/-их», но не роль, должность или
обращение из списка (`ROLE_LEMMAS`), не глагол, не местоимение и не предлог.
"""

from __future__ import annotations

import re
from functools import lru_cache

from labops_pii.morph import parse_word

# Слово кириллицей, части через дефис («Салтыков-Щедрин», «Новикова-Прибой»)
_WORD_RE = re.compile(r"[А-Яа-яЁё]+(?:-[А-Яа-яЁё]+)*")
# Промежуток между словами ФИО: пробелы, табуляция, неразрывные пробелы (не перевод строки)
_SPACE = "[ \t   ]"
_GAP_RE = re.compile(rf"{_SPACE}{{1,3}}")
# Фамилия через запятую перед «Имя Отчество»: «Иванов, Сергей Петрович»
_COMMA_GAP_RE = re.compile(rf"{_SPACE}{{0,2}},{_SPACE}{{1,3}}")
# Короче не бывает ни имени («Ян»), ни фамилии («Ли», «Ким»)
MIN_NAME_LEN = 2
MIN_PATRONYMIC_LEN = 5
MIN_SURNAME_LEN = 2
# Типичные окончания русских и соседних фамилий: по ним слово вне словаря считается фамилией
SURNAME_ENDINGS = (
    "ов", "ова", "ев", "ева", "ёв", "ёва", "ин", "ина", "ын", "ына", "ский", "ская", "цкий",
    "цкая", "ской", "енко", "ук", "юк", "чук", "ич", "ян", "янц", "дзе", "швили", "ых", "их",
    "ман", "берг", "штейн",
)
# Окончание фамилий-прилагательных во множественном числе: «Белых», «Черных», «Долгих»
_ADJ_SURNAME_ENDINGS = ("ых", "их")
# Части речи, которые не бывают фамилией рядом с именем: глагол, наречие, местоимение и т.п.
_NOT_SURNAME_POS = frozenset({
    "VERB", "INFN", "PRTF", "PRTS", "GRND", "ADVB", "NPRO", "PREP", "CONJ", "PRCL", "INTJ",
    "PRED", "COMP", "NUMR",
})
# Роли, должности, обращения и степени родства: одушевлённые существительные и прилагательные,
# которые стоят перед «Имя Отчество», но фамилией не являются («Менеджер Анна Сергеевна»).
ROLE_LEMMAS = frozenset(
    "заказчик поставщик покупатель продавец исполнитель подрядчик клиент контрагент плательщик "
    "получатель отправитель директор руководитель бухгалтер менеджер предприниматель "
    "представитель подписант ответственный уважаемый дорогой коллега доктор профессор "
    "господин госпожа товарищ гражданин гражданка сотрудник сотрудница специалист инженер "
    "юрист врач водитель курьер мастер начальник заместитель пациент студент студентка "
    "учитель учительница тётя тетя дядя бабушка дедушка мама папа сын дочь брат сестра муж "
    "жена автор агент оператор администратор кассир секретарь помощник ассистент консультант "
    "аналитик разработчик программист дизайнер логист кладовщик прораб технолог экономист "
    "кадровик эксперт партнёр партнер собственник владелец арендатор арендодатель должник "
    "кредитор истец ответчик заявитель абонент пользователь участник кандидат соискатель "
    "председатель генеральный финансовый коммерческий главный старший ведущий младший ученик "
    "президент губернатор мэр глава министр депутат судья нотариус адвокат следователь "
    "командир капитан майор полковник генерал лейтенант сержант рядовой отец мать дед "
    "внук внучка племянник племянница тёзка тезка друг подруга сосед соседка коллега "
    "сударь сударыня друг привет здравствуйте добрый спасибо".split()
)


def _style(word: str) -> str:
    """Регистр слова ФИО: «title» (каждая часть с заглавной), «upper», «lower» или пусто."""
    if len(word) > 1 and word.isupper():
        return "upper"
    if word.islower():
        return "lower"
    if all(part[:1].isupper() and part[1:].islower() for part in word.split("-")):
        return "title"
    return ""


@lru_cache(maxsize=8192)
def _tags(word: str) -> tuple[str, ...]:
    """Разборы слова как строки тегов (регистр и «ё» не важны)."""
    return tuple(str(p.tag) for p in parse_word(word))


@lru_cache(maxsize=8192)
def _known(word: str) -> bool:
    """Есть ли слово в словаре pymorphy (а не только догадка по окончанию)."""
    return any(p.is_known for p in parse_word(word))


@lru_cache(maxsize=8192)
def _lemma(word: str) -> str:
    """Начальная форма главного разбора (для сверки со списком ролей)."""
    parses = parse_word(word)
    return parses[0].normal_form if parses else word.lower()


def is_first_name(word: str) -> bool:
    """Словарное имя (любой разбор с грамемой Name), без дефиса."""
    return len(word) >= MIN_NAME_LEN and "-" not in word and any(
        "Name" in tag for tag in _tags(word)
    )


def is_patronymic(word: str) -> bool:
    """Отчество (любой разбор с грамемой Patr) в любом падеже."""
    return len(word) >= MIN_PATRONYMIC_LEN and "-" not in word and any(
        "Patr" in tag for tag in _tags(word)
    )


def _surname_part(part: str) -> bool:
    """Часть фамилии рядом с «Имя Отчество»: см. описание модуля."""
    if len(part) < MIN_SURNAME_LEN:
        return False
    lowered = part.lower().replace("ё", "е")
    if lowered in ROLE_LEMMAS or _lemma(part) in ROLE_LEMMAS:
        return False
    tags = _tags(part)
    if any("Surn" in tag for tag in tags) or not _known(part):
        return True
    best = tags[0] if tags else ""
    if best.split(",")[0].split(" ")[0] in _NOT_SURNAME_POS:
        return False
    if lowered.endswith(_ADJ_SURNAME_ENDINGS) and best.startswith("ADJF"):
        return True
    # Одушевлённое существительное вне списка ролей: «Головач», «Кузнец», «Соловей»
    return best.startswith("NOUN") and "anim" in best


def is_surname_near_patronymic(word: str) -> bool:
    """Фамилия по соседству с парой «имя + отчество».

    Слово через дефис годится, если хотя бы одна часть - фамилия, а остальные - любые
    существительные («Новикова-Прибой»: «прибой» неодушевлённое).
    """
    parts = word.split("-")
    if len(parts) == 1:
        return _surname_part(word)
    if not any(_surname_part(p) for p in parts):
        return False
    return all(
        _surname_part(p) or (_tags(p) and _tags(p)[0].startswith("NOUN")) for p in parts
    )


def find_name_patronymic_spans(text: str) -> list[tuple[int, int]]:
    """Диапазоны ФИО вокруг пар «имя + отчество» (с фамилией слева или справа, если есть).

    Слова находки - одного регистра (как написано: с заглавной, капсом или строчными) и
    разделены только пробелами (фамилия слева - ещё и запятой). Перевод строки находку
    разрывает: списки людей по строкам маскируются по человеку на строку.

    Args:
        text: Текст (длина и позиции как у оригинала).

    Returns:
        Непересекающиеся диапазоны [начало, конец) в порядке появления.
    """
    words = list(_WORD_RE.finditer(text))
    spans: list[tuple[int, int]] = []
    last_end = -1
    for i in range(len(words) - 1):
        first, patr = words[i], words[i + 1]
        if first.start() < last_end:
            continue
        style = _style(first.group())
        if not style or _style(patr.group()) != style:
            continue
        if not _GAP_RE.fullmatch(text, first.end(), patr.start()):
            continue
        if not (is_first_name(first.group()) and is_patronymic(patr.group())):
            continue
        start, end = first.start(), patr.end()
        # Слово, уже отданное предыдущему ФИО, второй раз фамилией не становится: иначе два
        # человека подряд («Анна Сергеевна Иванова Ольга Петровна») склеились бы в один
        if i > 0 and words[i - 1].start() >= last_end and _surname_at(
            text, words[i - 1], first.start(), style, left=True
        ):
            start = words[i - 1].start()
        elif i + 2 < len(words) and _surname_at(text, words[i + 2], patr.end(), style,
                                                left=False):
            end = words[i + 2].end()
        spans.append((start, end))
        last_end = end
    return spans


def _surname_at(text: str, word: re.Match[str], edge: int, style: str, left: bool) -> bool:
    """Соседнее слово - фамилия того же регистра, отделённая пробелами (слева и запятой)."""
    if _style(word.group()) != style:
        return False
    if left:
        gap_ok = _GAP_RE.fullmatch(text, word.end(), edge) or _COMMA_GAP_RE.fullmatch(
            text, word.end(), edge
        )
    else:
        gap_ok = _GAP_RE.fullmatch(text, edge, word.start())
    return bool(gap_ok) and is_surname_near_patronymic(word.group())


def is_dictionary_surname(word: str) -> bool:
    """Каждая часть слова - словарная фамилия (разбор Surn у слова из словаря pymorphy).

    Строже `is_surname_near_patronymic`: нужна рядом с ОДНИМ инициалом («Иванов С.»,
    «А. Кузнецов»), где одна буква с точкой бывает и сокращением («г.», «П. 3»).
    """
    return all(
        len(part) > MIN_SURNAME_LEN and _known(part) and any("Surn" in t for t in _tags(part))
        for part in word.split("-")
    )


def _best_is_name(word: str) -> bool:
    """Главный разбор слова - имя («Сергей», «Анна»; не «Роза» и не «Роман»)."""
    tags = _tags(word)
    return len(word) >= MIN_NAME_LEN and "-" not in word and bool(tags) and "Name" in tags[0]


def _pair_surname(word: str, style: str) -> bool:
    """Фамилия в паре с именем без отчества.

    С заглавной хватает признаков `is_surname_near_patronymic` (имя рядом - сильный признак);
    капсом и строчными, где такие слова бывают заголовком или обычной речью, нужна словарная
    фамилия.
    """
    if style != "title":
        return is_dictionary_surname(word)
    # Второе словарное имя - не фамилия: «Лада Веста», «Вера Надежда»
    if "-" not in word and _known(word) and _best_is_name(word):
        return False
    # Слово вне словаря без отчества рядом - часто бренд или калька («Роза Трейд», «Альфа
    # Групп»): фамилией оно считается только с фамильным окончанием («Пехтышева»).
    for part in word.split("-"):
        if not _known(part) and not part.lower().endswith(SURNAME_ENDINGS):
            return False
    return is_surname_near_patronymic(word)


# Слово перед парой, после которого «Имя Фамилия» - название улицы или учреждения
_NAMED_AFTER_RE = re.compile(
    r"ул|улица|улицы|улице|улицу|пр|просп|проспект|проспекта|пер|переулок|переулка|пл|площадь"
    r"|площади|б|бульвар|бульвара|наб|набережная|набережной|ш|шоссе|им|имени|мкр|пр-т|пр-д"
    r"|проезд|проезда|сквер|парк|станция|ст|метро|теплоход|судно|премия|премии|орден|ордена"
)


def find_surname_name_spans(text: str) -> list[tuple[int, int]]:
    """Пары «Фамилия Имя» и «Имя Фамилия» без отчества («Позвоните Иванов Сергей завтра.»).

    Имя - по главному разбору pymorphy (не «Роза», «Роман», «Вера» в значении слова), фамилия -
    см. `_pair_surname`. Слова одного регистра, между ними только пробелы.

    Args:
        text: Текст (длина и позиции как у оригинала).

    Returns:
        Диапазоны пар [начало, конец) в порядке появления (могут пересекаться с другими
        находками ФИО: детектор сводит пересечения сам).
    """
    words = list(_WORD_RE.finditer(text))
    spans: list[tuple[int, int]] = []
    last_end = -1
    for i in range(len(words) - 1):
        left, right = words[i], words[i + 1]
        # Пары не цепляются друг за друга: «Иван Петров Анна Сидорова» - два человека, а не
        # цепочка пересекающихся пар, которую детектор свёл бы в одно ФИО
        if left.start() < last_end:
            continue
        if i > 0 and _NAMED_AFTER_RE.fullmatch(words[i - 1].group().lower()):
            continue  # «ул. Ивана Франко», «школа имени Ивана Петрова»: название, не человек
        style = _style(left.group())
        if not style or _style(right.group()) != style:
            continue
        if not _GAP_RE.fullmatch(text, left.end(), right.start()):
            continue
        a, b = left.group(), right.group()
        if (_best_is_name(b) and _pair_surname(a, style)) or (
            _best_is_name(a) and _pair_surname(b, style)
        ):
            spans.append((left.start(), right.end()))
            last_end = right.end()
    return spans
