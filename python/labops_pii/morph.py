"""Нормализация ФИО: приведение слов к лемме, чтобы «Иванова» и «Иванов» совпали."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import lru_cache

import pymorphy3
from pymorphy3.analyzer import Parse

WORD_RE = re.compile(r"[А-Яа-яЁёA-Za-z]+(?:-[А-Яа-яЁёA-Za-z]+)*")
NAME_GRAMMEMES = ("Surn", "Name", "Patr")
LEMMA_CACHE_SIZE = 4096
MIN_FILE_NAME_LEN = 3  # короче — инициалы и предлоги, в именах файлов ФИО не ищем


@lru_cache(maxsize=1)
def _analyzer() -> pymorphy3.MorphAnalyzer:
    """Лениво создаёт морфологический анализатор (загрузка словаря ~сотни мс)."""
    return pymorphy3.MorphAnalyzer()


@lru_cache(maxsize=LEMMA_CACHE_SIZE)
def _parse_cached(lowered: str) -> tuple[Parse, ...]:
    """Разбор слова pymorphy с кэшем (R5-PY-2): parse стоит ~0.75 мс на слово.

    Возвращает кортеж, а не список: значение лежит в общем кэше и вызывающий не должен
    его менять. Объекты Parse неизменяемы (namedtuple), предикаты только читают их.

    Args:
        lowered: Слово в нижнем регистре, «ё» заменена на «е».
    """
    return tuple(_analyzer().parse(lowered))


@dataclass(slots=True)
class _RequestMemo:
    """Разборы и ключи ФИО одного запроса (R9-A4-08).

    Общий LRU на `LEMMA_CACHE_SIZE` слов при тексте больше ~4 000 разных слов вытесняет
    разбор до повторного обращения: детектор проходит по словам несколькими детекторами, и
    pymorphy звался на каждое слово заново (повтор плотного списка ФИО 70 000 знаков в том
    же треде - 9,2 с CPU при таймауте клиента 10 с). Память запроса живёт только до конца
    `detect`, поэтому не растит процесс навсегда, как вырос бы общий кэш на 65 536 слов.
    """

    parses: dict[str, tuple[Parse, ...]] = field(default_factory=dict)
    person_keys: dict[str, str] = field(default_factory=dict)


# Контекстная, а не глобальная: запросы идут параллельно в потоках одного процесса.
_request_memo: ContextVar[_RequestMemo | None] = ContextVar("morph_request_memo", default=None)


@contextmanager
def request_cache() -> Iterator[None]:
    """Включает память разборов и ключей ФИО на время одного запроса.

    Вложенный вызов пользуется памятью внешнего. Без контекста функции модуля работают
    как прежде, только через общий LRU.
    """
    if _request_memo.get() is not None:
        yield
        return
    token = _request_memo.set(_RequestMemo())
    try:
        yield
    finally:
        _request_memo.reset(token)


def _parse(lowered: str) -> tuple[Parse, ...]:
    """Разбор слова: сначала память запроса, затем общий LRU `_parse_cached`.

    Args:
        lowered: Слово в нижнем регистре, «ё» заменена на «е».
    """
    memo = _request_memo.get()
    if memo is None:
        return _parse_cached(lowered)
    parses = memo.parses.get(lowered)
    if parses is None:
        parses = _parse_cached(lowered)
        memo.parses[lowered] = parses
    return parses



def parse_word(word: str) -> tuple[Parse, ...]:
    """Разборы pymorphy слова в любом регистре и с «ё» (из памяти запроса, как `_parse`)."""
    return _parse(word.lower().replace("ё", "е"))

@lru_cache(maxsize=LEMMA_CACHE_SIZE)
def lemma(word: str) -> str:
    """Возвращает лемму слова, предпочитая разбор «фамилия/имя/отчество».

    Args:
        word: Слово в любом падеже.

    Returns:
        Лемма в нижнем регистре (для инициалов — одна буква).
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) == 1:
        return lowered
    parses = _parse(lowered)
    named = [p for p in parses if any(g in p.tag for g in NAME_GRAMMEMES)]
    # Разбор во множественном числе пропускается (R9-A4-06): у «Борисов», «Семенов»,
    # «Абрамов» первым идёт «Борис/Семён/Абрам, мн.ч. род.п.», и лемма именительного падежа
    # выходила «борис», а косвенных («Борисова», «Борисову») — «борисов». Страховка
    # known_lemmas тогда не ловила фамилию в косвенном падеже, а формы одного человека
    # получали разные ключи и токены. Слово только с разборами мн.ч. («Ивановы») — как раньше.
    best = next((p for p in named if "plur" not in p.tag), named[0] if named else None)
    if best is not None:
        return best.normal_form.replace("ё", "е")
    return parses[0].normal_form.replace("ё", "е") if parses else lowered


@lru_cache(maxsize=LEMMA_CACHE_SIZE)
def common_lemma(word: str) -> str:
    """Лемма слова как обычного слова, без предпочтения разбора «фамилия/имя/отчество».

    Нужна названиям улиц: `lemma` читает «Тверской» как фамилию и оставляет форму как есть,
    а прилагательное «Тверская/Тверской/Тверскую» должно давать одну лемму.

    Args:
        word: Слово в любом падеже.

    Returns:
        Лемма в нижнем регистре; «ё» заменена на «е».
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) == 1:
        return lowered
    parses = _parse(lowered)
    # Прилагательное первым: «Тверская» словарь читает и как топоним-существительное, но
    # формы «Тверской/Тверскую» одинаково сводятся к прилагательному «тверской».
    plain = next((p for p in parses if p.tag.POS == "ADJF"), None) or next(
        (p for p in parses if not any(g in p.tag for g in NAME_GRAMMEMES)), None
    )
    best = plain if plain is not None else (parses[0] if parses else None)
    return best.normal_form.replace("ё", "е") if best is not None else lowered


# Род в ключе ФИО хранится служебным «словом» с этим префиксом: он не буква и не часть леммы,
# поэтому обычные слова ключа (known_lemmas, индекс) его не путают, а старые ключи без него
# остаются совместимыми с любым родом.
GENDER_PREFIX = "\x01"
GENDER_MALE = "m"
GENDER_FEMALE = "f"
PATRONYM_MALE_ENDINGS = ("ович", "евич", "ьич", "ич")
PATRONYM_FEMALE_ENDINGS = ("овна", "евна", "ична", "инична", "ьична")
# Окончания женской формы фамилии на -ов/-ев/-ин/-ын: «Ивановой». «Иванову» сюда не входит
# (мужской дательный или женский винительный): без уверенности рода нет.
SURNAME_FEMALE_SUFFIXES = frozenset({"ой"})
# Окончание без рода: «Иванову» - и «к Иванову (Ивану)», и «на Иванову (Анну)». Раньше считалось
# мужским, и женщина в винительном падеже получала токен мужчины с тем же ключом (ревью 25.11)
SURNAME_GENDERLESS_SUFFIX = "у"
# «Иванова» — женский именительный или мужской родительный/винительный (R9-A4-07). Без
# других признаков форма по-прежнему считается женской (R3-ALG-14: «Иванова И.И.» не
# сливается с «Ивановым И.И.»), но её снимают признаки мужского косвенного падежа:
# предлог перед ФИО (см. `with_preposition_gender`) или имя, которое тоже может быть
# мужским родительным («Петрова Александра», «Петрова Дмитрия»).
SURNAME_AMBIGUOUS_SUFFIX = "а"
# Служебная метка голоса фамилии на «-а»; в ключ не попадает.
_SURNAME_FEMALE_OR_MALE_OBLIQUE = "f?"
# Падежи, в которых мужское имя совпадает по форме с женским именительным («Александра»).
_MALE_OBLIQUE_CASES = ("gent", "accs")
ADJ_SURNAME_FEMALE_SUFFIXES = frozenset({"ая", "яя", "ой", "ей", "ую", "юю"})
ADJ_SURNAME_ENDINGS = ("ий", "ый", "ой")
# Фамилии с этими окончаниями меняются по родам: совпадение формы с леммой значит мужской род
SURNAME_MALE_ENDINGS = ("ов", "ев", "ёв", "ин", "ын", "ский", "цкий", "ой", "ий", "ый")


@lru_cache(maxsize=LEMMA_CACHE_SIZE)
def _name_vote(word: str) -> str | None:
    """Род по имени или отчеству: только если все разборы слова согласны."""
    lowered = word.lower().replace("ё", "е")
    if len(lowered) <= 1:  # инициал: рода не несёт, разбор не нужен
        return None
    if len(lowered) > MIN_FILE_NAME_LEN:
        if lowered.endswith(PATRONYM_FEMALE_ENDINGS):
            return GENDER_FEMALE
        if lowered.endswith(PATRONYM_MALE_ENDINGS):
            return GENDER_MALE
    genders = {
        g
        for p in _parse(lowered)
        if "Name" in p.tag
        for g in (GENDER_MALE if "masc" in p.tag else GENDER_FEMALE if "femn" in p.tag else "",)
        if g
    }
    return genders.pop() if len(genders) == 1 else None


@lru_cache(maxsize=LEMMA_CACHE_SIZE)
def _surname_vote(word: str) -> str | None:
    """Род по форме фамилии относительно её леммы (мужская начальная форма или женская)."""
    lowered = word.lower().replace("ё", "е")
    if len(lowered) <= 1:
        return None
    surn = next((p for p in _parse(lowered) if "Surn" in p.tag), None)
    if surn is None:
        return None
    base = surn.normal_form.replace("ё", "е")
    if lowered == base:
        return GENDER_MALE if base.endswith(SURNAME_MALE_ENDINGS) else None
    adjectival = base.endswith(ADJ_SURNAME_ENDINGS)
    stem = base[:-2] if adjectival else base
    if not lowered.startswith(stem):
        return None
    suffix = lowered[len(stem):]
    if not adjectival and suffix == SURNAME_AMBIGUOUS_SUFFIX:
        return _SURNAME_FEMALE_OR_MALE_OBLIQUE
    if not adjectival and suffix == SURNAME_GENDERLESS_SUFFIX:
        return None  # «Иванову»: мужской дательный или женский винительный - рода нет
    female = ADJ_SURNAME_FEMALE_SUFFIXES if adjectival else SURNAME_FEMALE_SUFFIXES
    return GENDER_FEMALE if suffix in female else GENDER_MALE


@lru_cache(maxsize=LEMMA_CACHE_SIZE)
def _likely_male_oblique_name(word: str) -> bool:
    """Говорит, что имя скорее мужское в родительном/винительном падеже, чем женское.

    «Александра», «Дмитрия», «Артёма» — у pymorphy есть и мужской косвенный, и женский
    именительный разбор, поэтому `_name_vote` рода не даёт. Рядом с фамилией на «-а»
    («Петрова Александра») оба прочтения согласованы по падежу. Решает частота разборов:
    «Юлия», «Валентина» (формально и «Юлий», «Валентин» в род. п.) остаются женскими.
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) <= 1:
        return False
    male_oblique = female_nominative = 0.0
    for p in _parse(lowered):
        if "Name" not in p.tag:
            continue
        if "masc" in p.tag and any(c in p.tag for c in _MALE_OBLIQUE_CASES):
            male_oblique += p.score
        elif "femn" in p.tag and "nomn" in p.tag:
            female_nominative += p.score
    return male_oblique > female_nominative


def gender_of(words: list[str], after_preposition: bool = False) -> str | None:
    """Определяет род человека по словам ФИО или None, если уверенности нет.

    Сильные признаки (отчество, имя) главнее формы фамилии; если они спорят, рода нет.

    Args:
        words: Слова ФИО (инициалы допускаются, рода они не несут).
        after_preposition: Перед ФИО стоит предлог. Женская фамилия на «-а» бывает только
            в именительном падеже, а после предлога его нет: «от Петрова» — мужчина.
    """
    strong = {v for w in words if (v := _name_vote(w))}
    if strong:
        return strong.pop() if len(strong) == 1 else None
    weak = {v for w in words if (v := _surname_vote(w))}
    if _SURNAME_FEMALE_OR_MALE_OBLIQUE in weak:
        weak.discard(_SURNAME_FEMALE_OR_MALE_OBLIQUE)
        if after_preposition:
            weak.add(GENDER_MALE)
        elif not any(_likely_male_oblique_name(w) for w in words):
            weak.add(GENDER_FEMALE)  # прежнее поведение (R3-ALG-14)
        # иначе («Петрова Александра») форма фамилии голоса не даёт: решают остальные слова
    return weak.pop() if len(weak) == 1 else None


def split_key(key: str) -> tuple[list[str], str | None]:
    """Разбирает ключ ФИО на слова (леммы и инициалы) и род (или None)."""
    words: list[str] = []
    gender: str | None = None
    for part in key.split():
        if part.startswith(GENDER_PREFIX):
            gender = part[len(GENDER_PREFIX):] or None
        else:
            words.append(part)
    return words, gender


def person_key(text: str) -> str:
    """Строит ключ ФИО: отсортированные леммы слов через пробел и род, если он известен.

    Порядок слов не важен («Иванов Иван» == «Иван Иванов»); падеж не важен. Род отделяет
    «Иванов И.И.» от «Иванова И.И.»: раньше обе записи сливались в один токен, и /restore
    возвращал женщине написание мужчины (R3-ALG-14).
    """
    memo = _request_memo.get()
    if memo is not None:
        known = memo.person_keys.get(text)
        if known is not None:
            return known
    raw = WORD_RE.findall(text)
    parts = sorted(lemma(w) for w in raw)
    gender = gender_of(raw)
    if gender:
        parts.append(f"{GENDER_PREFIX}{gender}")
    key = " ".join(parts)
    if memo is not None:
        memo.person_keys[text] = key
    return key


def with_preposition_gender(key: str, text: str) -> str:
    """Уточняет род ключа ФИО, перед которым в тексте стоит предлог (R9-A4-07).

    «Нет ответа от Петрова»: без контекста форма «Петрова» считается женской, и мужчина
    в треде получал второй токен. Меняется только пометка рода, леммы ключа остаются.

    Args:
        key: Ключ, построенный `person_key` по тому же фрагменту.
        text: Фрагмент текста ФИО (без предлога).

    Returns:
        Ключ с уточнённым родом (или тот же ключ, если уточнять нечего).
    """
    words, gender = split_key(key)
    if gender != GENDER_FEMALE:
        return key
    refined = gender_of(WORD_RE.findall(text), after_preposition=True)
    if refined == gender:
        return key
    if refined:
        words.append(f"{GENDER_PREFIX}{refined}")
    return " ".join(words)


def with_female_subject(key: str) -> str:
    """Помечает ключ ФИО без рода женским: ФИО - подлежащее при глаголе женского рода.

    «Петрова Александра подписала договор»: форма «Петрова Александра» сама по себе - и
    женский именительный, и мужской родительный (R9-A4-07), поэтому рода в ключе нет, и она
    сопоставлялась с «Петров Александр» того же треда. Глагол женского рода после ФИО в
    начале фразы снимает неоднозначность. Ключ с родом не меняется.

    Args:
        key: Ключ, построенный `person_key`.

    Returns:
        Ключ с пометкой женского рода (или тот же ключ, если род уже есть).
    """
    words, gender = split_key(key)
    if gender is not None:
        return key
    return " ".join([*words, f"{GENDER_PREFIX}{GENDER_FEMALE}"])


# Частей имени у одного человека: фамилия, имя, отчество (или их инициалы) и слово-роль,
# которое NER нередко берёт в находку («Бухгалтер Павлова Елена Сергеевна»). Больше - склейка
# людей; две пары «имя фамилия» подряд делит на людей уже детектор (_drop_multi_person_spans)
MAX_PERSON_NAME_PARTS = 4
# Частицы в составе ФИО, которые частью имени не считаются: «Мамед оглы», «фон Берг»
NAME_PARTICLES = frozenset({"оглы", "огл", "кызы", "кзы", "ибн", "бен", "фон", "де", "ван", "дер"})


def _name_parts(words: list[str]) -> int:
    """Сколько частей имени в словах ключа (частицы не считаются)."""
    return sum(1 for w in words if w not in NAME_PARTICLES)


def keys_compatible(first: str, second: str) -> bool:
    """Решает, относятся ли два ключа ФИО к одному человеку.

    Совпадают, если полные слова одного ключа входят в другой и первые буквы
    всех слов (инициалы) одного — подмножество букв другого. Так «Иванов И.»
    и «Иванов Иван» — один человек, а «Иванов И.» и «Иванов Пётр» — разные.
    Известные и разные роды несовместимы; ключ без рода совместим с любым.
    """
    words_a, gender_a = split_key(first)
    words_b, gender_b = split_key(second)
    if gender_a and gender_b and gender_a != gender_b:
        return False
    # Больше четырёх частей имени - не один человек, а склейка («Петров А.Б. Сидоров В.Г.»).
    # Нечёткое сопоставление с ней отдавало бы токен склейки каждому её участнику, и restore
    # возвращал обоих; точное совпадение ключа (повтор того же написания) работает как раньше.
    if _name_parts(words_a) > MAX_PERSON_NAME_PARTS or _name_parts(words_b) > (
        MAX_PERSON_NAME_PARTS
    ):
        return False
    full_a = {w for w in words_a if len(w) > 1}
    full_b = {w for w in words_b if len(w) > 1}
    if not full_a or not full_b:
        return False
    if not (full_a <= full_b or full_b <= full_a):
        return False
    letters_a = sorted(w[0] for w in words_a)
    letters_b = sorted(w[0] for w in words_b)
    small, large = sorted((letters_a, letters_b), key=len)
    pool = list(large)
    for letter in small:
        if letter not in pool:
            return False
        pool.remove(letter)
    return True


NON_NAME_POS = frozenset(
    {"VERB", "INFN", "PRTF", "PRTS", "GRND", "ADVB", "PRCL", "CONJ", "PREP", "NPRO", "INTJ",
     "PRED", "COMP"}
)


def is_non_name_word(word: str) -> bool:
    """Говорит, что слово точно не часть ФИО (глагол, предлог и т.п.).

    Нужно, чтобы отсечь ложный захват NER вроде «Позвони Петрову».
    Инициалы (одна буква) за имя не считаются.
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) <= 1:
        return False
    parses = _parse(lowered)
    if any(g in p.tag for p in parses for g in NAME_GRAMMEMES):
        return False
    return bool(parses) and parses[0].tag.POS in NON_NAME_POS


def is_inanimate_common_noun(word: str) -> bool:
    """Говорит, что слово — словарное неодушевлённое существительное, не имя и не фамилия.

    Так отсекаются названия компаний и вещей («Металлопрокат», «Сибирь», «Прайс»),
    которые NER иногда принимает за ФИО. Одушевлённые слова («Мельник», «Заяц» — они же
    фамилии) и любые слова с разбором «фамилия/имя/отчество» под фильтр не попадают.
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) <= 1:
        return False
    parses = _parse(lowered)
    if not parses or not all(p.is_known and p.tag.POS == "NOUN" for p in parses):
        return False
    return not any(
        g in p.tag for p in parses for g in (*NAME_GRAMMEMES, "anim")
    )


TYPO_MIN_LEN = 5  # короче - слишком много словарных соседей, правило ловило бы фамилии
# Пары букв, которые распознавание речи путает на слух: звонкие/глухие, безударные гласные.
# Опечатка расшифровки почти всегда такая («Садачу» ← «задачу»), а случайная фамилия
# в одну такую замену от словарного слова - редкость: правило не раскрывает фамилии.
SOUND_ALIKE_PAIRS = (
    "зс", "дт", "бп", "вф", "гк", "жш", "ао", "еи", "иы", "эе", "ея", "юу", "цс", "щш", "чщ",
)
SOUND_ALIKE: dict[str, str] = {}
for _pair in SOUND_ALIKE_PAIRS:
    SOUND_ALIKE[_pair[0]] = SOUND_ALIKE.get(_pair[0], "") + _pair[1]
    SOUND_ALIKE[_pair[1]] = SOUND_ALIKE.get(_pair[1], "") + _pair[0]
# Окончания фамилий во всех падежах: «Крутоголов», «Свежинина», «Белоусову». У таких слов
# почти всегда найдётся словарный сосед в одну букву, и правило опечатки раскрывало бы фамилию.
SURNAME_SHAPE_RE = re.compile(
    r"(?:ов|ев|ёв|ин|ын|ск|цк|ых|их)(?:а|у|ой|ым|ыми|ом|е|ы|ых|им|ими|ого|ому|ая|ую|ий|ый)?$"
)


def typo_noun_parses(word: str) -> list[Parse]:
    """Разборы словарного существительного, опечаткой которого похоже слово вне словаря.

    Распознавание голосовых пишет «Садачу» вместо «задачу» (25.11.2026): слова нет в словаре,
    оно с заглавной, и NER принимал его за фамилию. Модель видела токен вместо слова, не могла
    заметить ошибку и вставила «Садачу» в слайд. Опечатка расшифровки - замена первой буквы на
    созвучную (SOUND_ALIKE). Словарные слова и слова с окончанием фамилии сюда не попадают.
    Одного этого признака мало: «Кадар», «Танака» тоже в одну созвучную замену от словарных
    слов. Поэтому детектор дополнительно требует согласованное определение перед словом.

    Args:
        word: Слово из находки ФИО.

    Returns:
        Разборы неодушевлённых существительных-кандидатов; пусто, если слово не опечатка.
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) < TYPO_MIN_LEN or not lowered.isalpha() or SURNAME_SHAPE_RE.search(lowered):
        return []
    if any(p.is_known for p in _parse(lowered)):
        return []
    found: list[Parse] = []
    # Только первая буква: на стыке слов распознавание чаще всего путает начало («вашу Садачу»
    # ← «вашу задачу»), а замена в середине давала соседей фамилиям («Кадар» ← «катар»).
    for letter in SOUND_ALIKE.get(lowered[0], ""):
        found += [
            parse
            for parse in _parse(letter + lowered[1:])
            if parse.is_known
            and parse.tag.POS == "NOUN"
            and "anim" not in parse.tag
            and not any(g in parse.tag for g in NAME_GRAMMEMES)
        ]
    return found


MODIFIER_POS = frozenset({"ADJF", "PRTF"})  # «вашу», «эту», «новую», «сделанную»


def agrees_as_modifier(modifier: str, nouns: list[Parse]) -> bool:
    """Слово - определение (прилагательное, местоимение, причастие), согласованное с одним из
    разборов существительного по падежу, числу и (в единственном числе) роду.

    Args:
        modifier: Слово перед существительным.
        nouns: Разборы существительного.

    Returns:
        True, если есть согласованная пара разборов.
    """
    lowered = modifier.lower().replace("ё", "е")
    for mod in _parse(lowered):
        if mod.tag.POS not in MODIFIER_POS:
            continue
        for noun in nouns:
            if mod.tag.case != noun.tag.case or mod.tag.number != noun.tag.number:
                continue
            if noun.tag.number == "plur" or mod.tag.gender == noun.tag.gender:
                return True
    return False


def is_surname_candidate(word: str) -> bool:
    """Говорит, что слово рядом с двумя инициалами можно считать фамилией.

    Мягче `is_person_word`: хватает любого разбора «фамилия» («Черных», «Шмидт», у которых
    главный разбор другой) или полного отсутствия слова в словаре (иностранная фамилия).
    Сами инициалы «О.И.» — сильный признак ФИО, поэтому строгий главный разбор не нужен;
    словарные слова без разбора «фамилия» («Согласовано», «Директор») не проходят.
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) < MIN_FILE_NAME_LEN:
        return False
    parses = _parse(lowered)
    if not parses:
        return False
    return any("Surn" in p.tag for p in parses) or not any(p.is_known for p in parses)


def is_person_word(word: str) -> bool:
    """Говорит, что слово — фамилия/имя/отчество по главному разбору pymorphy.

    Используется внутри имён файлов и путей, где нет контекста для NER: слово считается
    ФИО, только если лучший разбор одушевлённый «фамилия/имя/отчество». Словарные слова
    («Договор», «Счёт», «Прайс», «Август») и неоднозначные («Надежда», «Вера») не проходят.
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) < MIN_FILE_NAME_LEN:
        return False
    parses = _parse(lowered)
    if not parses:
        return False
    best = parses[0]
    return any(g in best.tag for g in NAME_GRAMMEMES) and "anim" in best.tag


@lru_cache(maxsize=LEMMA_CACHE_SIZE)
def name_gramme(word: str) -> str | None:
    """Возвращает грамему «Surn»/«Name»/«Patr» главного разбора одушевлённого слова.

    Для слов вне ФИО (и для коротких слов) возвращает None. Регистр слова не важен.
    """
    lowered = word.lower().replace("ё", "е")
    if len(lowered) < MIN_FILE_NAME_LEN:
        return None
    parses = _parse(lowered)
    if not parses or "anim" not in parses[0].tag:
        return None
    return next((g for g in NAME_GRAMMEMES if g in parses[0].tag), None)


# Падежи, допустимые в падежной метке «[PERSON_N|<падеж>]»; грамматика согласована с клиентом.
INFLECT_CASES = ("nomn", "gent", "datv", "accs", "ablt", "loct")
GENDER_MASC = "masc"
GENDER_FEMN = "femn"
_GENDER_EITHER = "ms-f"  # несклоняемые фамилии (Шевченко, Дюма): подходят любому роду
_WORD_PART_RE = re.compile(r"[А-Яа-яЁё]+")


def _name_parses(word: str, grammemes: tuple[str, ...]) -> list[Parse]:
    """Разборы слова в единственном числе с одной из грамем ФИО (в порядке убывания веса)."""
    lowered = word.lower()
    return [
        p for p in _parse(lowered)
        if "plur" not in p.tag and any(g in p.tag for g in grammemes)
    ]


def _word_gender(word: str, grammemes: tuple[str, ...]) -> str | None:
    """Род («masc»/«femn») главного разбора слова с нужной граммемой или None."""
    parses = _name_parses(word, grammemes)
    if not parses:
        return None
    return next((g for g in (GENDER_MASC, GENDER_FEMN) if g in parses[0].tag), None)


def _surname_gender(word: str) -> str | None:
    """Род по фамилии, только если ВСЕ её разборы-фамилии одного рода.

    «Иванова» — и женская фамилия, и мужская в родительном падеже; «Ким» — мужская и
    несклоняемая женская. Угадывать нельзя: ошибка рода хуже несклонённого ФИО.
    """
    genders = {
        g
        for parse in _name_parses(word, ("Surn",))
        for g in (GENDER_MASC, GENDER_FEMN)
        if g in parse.tag
    }
    return genders.pop() if len(genders) == 1 else None


def _person_gender(parts: list[str]) -> str | None:
    """Род человека по ФИО: сперва отчество и имя, при их отсутствии — однозначная фамилия."""
    for grammemes in (("Patr",), ("Name",)):
        genders = [g for g in (_word_gender(p, grammemes) for p in parts) if g]
        if genders:
            return max(set(genders), key=genders.count)
    surnames = {_surname_gender(p) for p in parts}
    return surnames.pop() if len(surnames) == 1 else None


def _match_case(source: str, result: str) -> str:
    """Переносит регистр исходного слова на результат (Заглавная, КАПС, строчная)."""
    if len(source) > 1 and source.isupper():
        return result.upper()
    if source[:1].isupper():
        return result[:1].upper() + result[1:]
    return result


def _inflect_part(part: str, case: str, gender: str | None) -> str:
    """Склоняет одно слово ФИО (без дефиса); без разбора или инициал — как есть."""
    if len(part) < 2:  # инициал
        return part
    for parse in _name_parses(part, NAME_GRAMMEMES):
        if gender and gender not in parse.tag and _GENDER_EITHER not in parse.tag:
            continue
        inflected = parse.inflect({case})
        if inflected is None:
            return part
        return _match_case(part, inflected.word)
    return part


def inflect_person(text: str, case: str) -> str:
    """Склоняет ФИО пословно в падеж `case` (одна из INFLECT_CASES).

    Пол берётся по отчеству/имени, иначе по фамилии, если она однозначна по роду; род не
    определён — ФИО возвращается как есть. Фамилия склоняется в том же роде.
    Инициалы, латиница и слова без разбора ФИО остаются в исходной форме; части слов через
    дефис склоняются каждая отдельно, регистр исходного слова сохраняется.

    Args:
        text: ФИО в любой форме («Петрова Ольга», «ИВАНОВ П.С.»).
        case: Граммема падежа pymorphy.

    Returns:
        ФИО в нужном падеже.
    """
    gender = _person_gender([p for p in _WORD_PART_RE.findall(text) if len(p) > 1])
    if gender is None:
        # Род не определён однозначно: склонение наугад дало бы «Петрову О.И.» женщине.
        return text
    return _WORD_PART_RE.sub(lambda m: _inflect_part(m.group(0), case, gender), text)


# Особые падежи pymorphy (второй родительный и т.п.) -> основной падеж метки
_SPECIAL_CASES = {"gen2": "gent", "acc2": "accs", "loc2": "loct", "gen1": "gent", "loc1": "loct"}


def _parse_cases(parse: Parse) -> frozenset[str]:
    """Падежи метки, которые допускает разбор; несклоняемое слово допускает любой."""
    raw = parse.tag.case
    if raw is None:
        return frozenset(INFLECT_CASES)
    case = _SPECIAL_CASES.get(raw, raw)
    return frozenset({case}) & frozenset(INFLECT_CASES)


def _word_cases(word: str, gender: str | None) -> frozenset[str] | None:
    """Падежи слова ФИО по всем его разборам (с учётом рода); None - слово не из ФИО."""
    parses = _name_parses(word, NAME_GRAMMEMES)
    if gender:
        parses = [p for p in parses if gender in p.tag or _GENDER_EITHER in p.tag]
    if not parses:
        return None
    cases: set[str] = set()
    for parse in parses:
        cases |= _parse_cases(parse)
    return frozenset(cases)


def person_case(text: str) -> str | None:
    """Косвенный падеж ФИО для падежной метки или None, если метку ставить нельзя.

    Падеж определяется по словам ФИО: берутся падежи всех разборов каждого слова (род - по
    имени/отчеству, как в `inflect_person`), и ищется пересечение по словам. Метка ставится,
    только если пересечение - ровно один косвенный падеж. Именительный (метки нет), несколько
    общих падежей («Иванову»: муж. дат. / жен. вин.; «Иванова»: жен. им. / муж. род.) и ни одного
    общего - без метки. Инициалы на падеж не влияют; слова без разбора ФИО не учитываются.

    Args:
        text: ФИО в том виде, как оно стоит в тексте.

    Returns:
        Код падежа из INFLECT_CASES, кроме «nomn», либо None.
    """
    parts = [p for p in _WORD_PART_RE.findall(text) if len(p) > 1]
    gender = _person_gender(parts)
    common: frozenset[str] | None = None
    for part in parts:
        cases = _word_cases(part, gender)
        if cases is None:
            continue
        common = cases if common is None else common & cases
    if common is None or len(common) != 1:
        return None
    (case,) = common
    return None if case == "nomn" else case
