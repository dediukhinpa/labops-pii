"""Латинские ФИО: словарь имён (транслит русских, международные, европейские) и поиск.

Модуль без морфологии (только `re` и `itertools`): его импортирует и сервис (через
`name_hints`), и guard, в образе которого pymorphy нет. Данные TS-детектора генерирует
tools/gen_ts_latin_names.py отсюда же.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator
from functools import lru_cache

# Сколько вариантов написания набирается на одно русское имя (транслит неоднозначен).
MAX_TRANSLIT_VARIANTS = 48
# Самая короткая латинская форма имени в словаре: короче («Al», «Li») слишком часто совпадает
# с обычными словами и аббревиатурами.
MIN_LATIN_NAME_LEN = 3
# Слов в латинском ФИО: «Имя Фамилия» и «Фамилия Имя Отчество».
LATIN_MAX_WORDS = 3

# --- словарь русских имён и их латинская запись -------------------------------------------

# Распространённые русские имена (именительный падеж). Многозначные слова («Вера», «Надежда»,
# «Любовь») оставлены: латинской записью они не пересекаются с английскими словами.
RU_FIRST_NAMES = (
    "Александр Александра Алексей Алёна Алина Алиса Алла Альбина Анастасия Анатолий Андрей Анжела "
    "Анна Антон Антонина Аркадий Арина Арсений Артём Артур Белла Богдан Борис Вадим Валентин "
    "Валентина Валерий Валерия Варвара Василий Василиса Вениамин Вера Вероника Виктор Виктория "
    "Виталий Влад Владимир Владислав Владислава Всеволод Вячеслав Галина Геннадий Георгий Герман "
    "Глеб Грigorий Григорий Дамир Данил Даниил Даниэль Дарья Денис Диана Дмитрий Евгений Евгения "
    "Евдокия Егор Екатерина Елена Елизавета Ерофей Зинаида Зоя Иван Игнат Игорь Илья Инга Инна "
    "Ирина Ислам Карина Каролина Кирилл Клавдия Константин Кристина Ксения Лариса Лев Леонид "
    "Лидия Лилия Любовь Людмила Магомед Максим Маргарита Марина Мария Матвей Михаил Надежда "
    "Наталья Никита Николай Нина Оксана Олег Олеся Ольга Павел Пётр Платон Полина Рамиль Расул "
    "Регина Ренат Римма Роберт Роман Ростислав Руслан Рустам Савелий Святослав Семён Сергей "
    "Снежана Софья София Станислав Степан Стефания Тамара Татьяна Тимофей Тимур Тихон Ульяна "
    "Фёдор Филипп Эдуард Эльвира Эльмира Эмилия Юлия Юрий Яков Ярослав Ярослава Ян Аделина Адель "
    "Азат Айдар Аида Айгуль Алсу Амир Анфиса Арсен Артемий Ася Бронислава Булат Вальдемар "
    "Василий Венера Виолетта Вильям Витольд Гала Гульнара Гульшат Давид Дина Дина Ева Эва "
    "Заур Ильдар Ильнур Ильяс Карим Кира Лейла Лиана Лика Лия Майя Малика Мила Милана Мирон "
    "Мирослав Назар Наиль Настасья Нелли Нигина Оля Радик Радмила Рашид Рената Рита Рузана Салават "
    "Самира Тагир Таисия Тая Фарид Фатима Флюра Харитон Хасан Эльдар Эмиль Юнус Юлиана Яна "
    "Ярик Аглая Агата Агния Алевтина Ангелина Валерьян Вадим Гордей Гриша Дарина Демид Добрыня "
    "Захар Злата Ираида Иосиф Кузьма Лада Лукьян Мамед Мартин Модест Нинель Оливер Остап Прохор "
    "Рогволод Савва Севастьян Серафима Устинья Феликс Фома Харлампий Элина Эрик Юлиан Яромир"
).split()

# Международные имена: только те, что не совпадают с обычными английскими словами.
INTERNATIONAL_FIRST_NAMES = frozenset(
    "john james michael david robert william richard thomas charles daniel matthew anthony "
    "andrew joshua christopher steven kevin brian edward ronald timothy jason jeffrey ryan "
    "jacob gary nicholas eric jonathan stephen larry justin scott brandon benjamin samuel "
    "gregory alexander patrick raymond dennis jerry tyler aaron adam nathan henry "
    "peter zachary douglas harold kyle carl arthur gerald roger keith jeremy terry lawrence "
    "sean christian albert joe ethan jesse willie billy bruce ralph roy "
    "louis philip bobby russell randy howard fred ernest oliver liam noah lucas "
    "mary patricia jennifer linda elizabeth barbara susan jessica sarah karen nancy lisa "
    "betty margaret sandra ashley kimberly emily donna michelle carol amanda melissa deborah "
    "stephanie rebecca sharon laura cynthia kathleen amy angela shirley anna brenda pamela "
    "emma nicole helen samantha katherine christine debra rachel carolyn janet maria heather "
    "diane julie joyce victoria kelly christina lauren joan evelyn judith megan cheryl andrea "
    "hannah jacqueline martha gloria teresa sara janice marie julia kathryn sophia frances "
    "jean abigail alice judy olivia sophie isabella charlotte amelia mia harper ella "
    "sebastian maximilian leonardo giovanni marco francesco antonio carlos jose juan miguel "
    "pablo pedro diego luis fernando rafael jorge javier ahmed mohammed muhammad ali omar "
    "hassan hussein ibrahim yusuf wei li zhang hiroshi takeshi kenji yuki akira "
    "hans klaus jurgen stefan wolfgang dieter heinz helmut jan pierre jean-pierre francois "
    "jacques michel laurent nicolas olivier giuseppe giorgio luca matteo alessandro "
    "elena olga natalia natalya tatiana irina svetlana ekaterina yekaterina".split()
)

# Окончания транслитерированных русских и украинских фамилий (строчными).
SURNAME_SUFFIXES = (
    "ov", "ova", "ev", "eva", "yov", "yova", "sky", "skiy", "skij", "ski", "skaya", "skaia",
    "tsky", "tskiy", "tskaya", "enko", "chenko", "yuk", "chuk", "shvili", "dze", "yan", "kin",
    "kina", "shin", "shina", "nov", "nova", "kov", "kova", "tsyn", "tsyna", "ykh", "ikh",
)
MIN_SURNAME_LEN = 5
# Отчества: «Petrovich», «Ivanovna».
PATRONYMIC_SUFFIXES = (
    "ovich", "evich", "yevich", "ovna", "evna", "yevna", "ichna", "inichna", "ich", "ych",
)
MIN_PATRONYMIC_LEN = 6

# Слова, которые рядом с именем не делают его ФИО: должности, технологии, организации,
# приветствия, слова резюме. Нужны только для «Имя Слово» без суффиксов фамилии.
NOT_A_NAME_WORDS = frozenset(
    "the and for with from dear hello hi hey thanks thank regards best kind sincerely yours "
    "please sir madam mr mrs ms miss dr prof team lead senior junior middle head chief "
    "manager director developer engineer analyst designer architect consultant specialist "
    "administrator assistant officer executive president vice owner founder partner "
    "recruiter researcher scientist tester programmer operator supervisor coordinator "
    "company group systems system solutions technologies technology tech labs lab studio "
    "software hardware services service consulting trading logistics bank holding limited "
    "corporation corp international global digital media market marketing sales support "
    "resume summary skills experience education profile contact contacts phone email "
    "address languages language objective references projects project portfolio "
    "male female born age years year month months week day days today tomorrow "
    "python java javascript typescript kotlin swift ruby rust golang php perl scala "
    "linux windows ubuntu debian android ios macos docker kubernetes git github gitlab "
    "react angular vue node express django flask spring laravel rails postgres mysql "
    "oracle redis kafka mongo elastic excel word office outlook teams slack zoom jira "
    "server client cloud code script studio platform framework library module plugin "
    "pro plus lite max mini premium standard basic free trial enterprise edition version "
    "open source public private default test demo sample example template draft final "
    "street avenue road city region country state university institute college school "
    "academy faculty department center centre office building room floor "
    "english russian german french spanish chinese italian japanese "
    "january february march april may june july august september october november "
    "december monday tuesday wednesday thursday friday saturday sunday "
    "new old big small first last next previous main general special global national "
    "yes not none null true false other others all any some more most "
    "name author reviewed signed attn attention cc bcc subject date sent to by of in on at "
    "candidate applicant employee client customer user person people staff member members "
    "contact interviewer recruiter reference referee spouse "
    # места и заведения: «Santa Barbara», «Lake Victoria», «Hotel Maria» - не люди
    "santa san saint sankt sainte fort port lake mount cape isla monte rio costa sierra "
    "puerto villa casa hotel cafe club park plaza grand royal palace castle bridge river "
    "valley beach bay island".split()
)

# --- транслитерация ------------------------------------------------------------------------

_VOWELS = "аеёиоуыэюяАЕЁИОУЫЭЮЯ"
_TRANSLIT: dict[str, tuple[str, ...]] = {
    "а": ("a",), "б": ("b",), "в": ("v",), "г": ("g",), "д": ("d",), "ж": ("zh", "j"),
    "з": ("z",), "и": ("i",), "к": ("k",), "л": ("l",), "м": ("m",), "н": ("n",), "о": ("o",),
    "п": ("p",), "р": ("r",), "с": ("s",), "т": ("t",), "у": ("u",), "ф": ("f",),
    "х": ("kh", "h"), "ц": ("ts", "c"), "ч": ("ch",), "ш": ("sh",), "щ": ("shch", "sch"),
    "ъ": ("",), "ы": ("y", "i"), "ь": ("",), "э": ("e",), "ю": ("yu", "iu", "ju"),
    "я": ("ya", "ia", "ja"), "й": ("y", "i"), "ё": ("yo", "e"),
}
# Сочетания с особой записью: «ий» -> «iy/y/i», «ия» -> «ia/iya», «ей» -> «ey/ei»
_TRANSLIT_PAIRS: dict[str, tuple[str, ...]] = {
    "ий": ("iy", "y", "i", "ii", "ij"),
    "ей": ("ey", "ei", "y", "ej"),
    "ай": ("ay", "ai", "aj"),
    "ой": ("oy", "oi", "oj"),
    "ия": ("ia", "iya", "ija"),
    "ье": ("ye", "e"),
    "ья": ("ya", "ia"),
}
# Европейские и турецкие имена, в том числе с диакритикой («Łukasz Dvořák», «Jürgen Müller»):
# раньше латинские имена были только ASCII, и такие ФИО уходили открытыми (матрица
# 25.11.2026). Как и выше - без совпадений с обычными английскими словами.
EUROPEAN_FIRST_NAMES = frozenset(
    "łukasz lukasz paweł pawel michał michal wojciech krzysztof tomasz piotr katarzyna "
    "małgorzata malgorzata agnieszka magdalena joanna zofia jakub mateusz kacper grzegorz "
    "andrzej jerzy zbigniew stanisław stanislaw władysław wladyslaw bożena grażyna dorota "
    "jiří jiri václav vaclav františek frantisek tomáš tomas lukáš lukas jaroslav miroslav "
    "zdeněk zdenek radek vojtěch ondřej ondrej jana hana lenka věra kateřina katerina tereza "
    "eliška eliska jürgen günter günther gunther jörg uwe rainer horst gerhard manfred werner "
    "ulrich matthias sabine ursula petra monika birgit heike renate karin brigitte björn "
    "bjorn sören søren jørgen jonas moritz niklas tobias florian andreas markus thorsten "
    "lars nils sven gunnar ingrid astrid sigrid kristina anders henrik åsa "
    "françois rené andré hélène émilie céline zoé chloé léa inès noémie jérôme sébastien "
    "stéphane frédéric cédric thierry benoît élodie "
    "josé jesús ramón raúl sofía lucía maría ángel álvaro joão sérgio gonçalo "
    "mehmet mustafa ahmet emre hüseyin özlem ayşe fatma zeynep elif burak gökhan serkan".split()
)
# Вручную: написания, которые транслитом не получаются
_EXTRA_LATIN_NAMES = (
    "alexander alexandr alexey alexei alexandra alex aleksey aleksei dmitri dmitriy dmitry "
    "evgeny evgeniy yevgeny yevgeniy eugene evgenia yulia yuliya julia iulia ksenia xenia "
    "yuri yury yuriy yuriy artem artyom peter pyotr petr fedor fyodor semen semyon "
    "sergei sergey serge igor ilya ilia elena yelena helen natalia nataliya nataly "
    "tatyana tatiana tanya anastasia anastasiya nastya olga olya maxim maksim "
    "vladimir vladislav viktor victor vasily vasiliy vasilii vassily mikhail michail mihail "
    "nikolay nikolai nicolai nikita ekaterina katerina yekaterina katya"
).split()


def _translit_options(word: str) -> Iterator[tuple[str, ...]]:
    """Варианты записи каждой «единицы» слова (буква или особое сочетание)."""
    index = 0
    while index < len(word):
        pair = word[index:index + 2].lower()
        if pair in _TRANSLIT_PAIRS and (index + 2 == len(word) or pair in ("ий", "ей", "ай", "ой")):
            yield _TRANSLIT_PAIRS[pair]
            index += 2
            continue
        char = word[index].lower()
        if char == "е":
            after_vowel = index == 0 or word[index - 1] in _VOWELS + "ьъ"
            yield ("ye", "e") if after_vowel else ("e",)
        else:
            yield _TRANSLIT.get(char, (char,))
        index += 1


def translit_variants(word: str) -> set[str]:
    """Возможные латинские написания русского слова (строчными), не больше MAX_TRANSLIT_VARIANTS."""
    options = list(_translit_options(word))
    return {
        "".join(parts)
        for parts in itertools.islice(itertools.product(*options), MAX_TRANSLIT_VARIANTS)
    }


def _build_latin_first_names() -> frozenset[str]:
    """Латинские написания имён: транслит русского словаря, ручные формы, международные."""
    names: set[str] = set(INTERNATIONAL_FIRST_NAMES) | set(_EXTRA_LATIN_NAMES)
    for name in RU_FIRST_NAMES:
        names |= translit_variants(name)
    ascii_names = {n for n in names if len(n) >= MIN_LATIN_NAME_LEN and n.isascii()}
    european = {n for n in EUROPEAN_FIRST_NAMES if len(n) >= MIN_LATIN_NAME_LEN}
    return frozenset(ascii_names | european)


LATIN_FIRST_NAMES = _build_latin_first_names()

# --- латинские ФИО -------------------------------------------------------------------------

# Латиница с диакритикой европейских и турецких фамилий («Müller», «Dvořák», «Yılmaz»): без неё
# «Hans Müller» уходил открытым целиком (матрица 25.11.2026)
LATIN_UPPER = "A-ZÀ-ÖØ-ÞĄĆČĎĘĚŁŃŇŐŘŚŠŤŮŰŹŻŽĞŞİ"
LATIN_LOWER = "a-zß-öø-ÿąćčďęěłńňőřśšťůűźżžğşı"
LATIN_LETTERS = LATIN_UPPER + LATIN_LOWER
# Слово: «Ivan», «IVAN», «Jean-Pierre»; слева и справа не буква/цифра/знак пути или адреса.
_LATIN_TITLE = rf"[{LATIN_UPPER}][{LATIN_LOWER}]{{2,19}}"
_LATIN_WORD = (
    rf"(?<![{LATIN_LETTERS}0-9_@./\\:+-])"
    rf"(?:{_LATIN_TITLE}(?:-{_LATIN_TITLE})?|[{LATIN_UPPER}]{{3,20}})"
    rf"(?![{LATIN_LETTERS}0-9_@/\\-])"
)
# Цепочка слов через пробелы любой длины: окна по 2-3 слова перебираются внутри неё, иначе
# «Senior Developer Maria Ivanova» резалась бы на «Senior Developer Maria» и «Ivanova».
_LATIN_RUN_RE = re.compile(rf"{_LATIN_WORD}(?:[ \t]{{1,3}}{_LATIN_WORD})+")
# После пары «Слово Имя» идёт строчное слово: это английская фраза («Yesterday Anna went»),
# а не запись «Фамилия Имя»
_LOWER_WORD_AHEAD_RE = re.compile(r"[ \t]+[a-z]{2,}")
MIN_UNKNOWN_SURNAME_LEN = 4
_LATIN_WORD_RE = re.compile(_LATIN_WORD)

KIND_FIRST = "first"
KIND_PATR = "patr"
KIND_SURN = "surn"
KIND_OTHER = "other"
KIND_STOP = "stop"
# Допустимые связки видов слов (в порядке написания): имя+что-то, фамилия+имя, имя+отчество...
_VALID_PAIRS = frozenset({
    (KIND_FIRST, KIND_FIRST), (KIND_FIRST, KIND_PATR), (KIND_FIRST, KIND_SURN),
    (KIND_FIRST, KIND_OTHER), (KIND_SURN, KIND_FIRST), (KIND_PATR, KIND_SURN),
    (KIND_SURN, KIND_PATR), (KIND_OTHER, KIND_FIRST),
})
_VALID_TRIPLES = frozenset({
    (KIND_SURN, KIND_FIRST, KIND_PATR), (KIND_FIRST, KIND_PATR, KIND_SURN),
    (KIND_FIRST, KIND_PATR, KIND_OTHER), (KIND_FIRST, KIND_FIRST, KIND_SURN),
    (KIND_SURN, KIND_FIRST, KIND_FIRST),
})


# Кэш вида слова: слова в тексте повторяются, вид зависит только от слова (ключ - слово до 41
# знака по шаблону _LATIN_WORD)
LATIN_KIND_CACHE_SIZE = 8192


@lru_cache(maxsize=LATIN_KIND_CACHE_SIZE)
def latin_word_kind(word: str) -> str:
    """Вид латинского слова: имя, отчество, фамилия по суффиксу, «чужое» слово или не-имя."""
    low = word.lower()
    if low in NOT_A_NAME_WORDS:
        return KIND_STOP
    parts = low.split("-")
    if any(p in LATIN_FIRST_NAMES for p in parts):
        return KIND_FIRST
    if len(low) >= MIN_PATRONYMIC_LEN and low.endswith(PATRONYMIC_SUFFIXES):
        return KIND_PATR
    if len(low) >= MIN_SURNAME_LEN and low.endswith(SURNAME_SUFFIXES):
        return KIND_SURN
    return KIND_OTHER


def _valid_window(kinds: tuple[str, ...], text: str, words: list[str], end: int) -> bool:
    """Подходит ли набор видов подряд идущих слов под латинское ФИО.

    Пара «неизвестное слово + имя» принимается строже: слово не короче MIN_UNKNOWN_SURNAME_LEN
    и дальше не идёт строчное слово (иначе «Yesterday Anna went home» стало бы ФИО).
    """
    if len(kinds) == 3:
        return kinds in _VALID_TRIPLES
    if kinds not in _VALID_PAIRS:
        return False
    if kinds == (KIND_OTHER, KIND_FIRST):
        return len(words[0]) >= MIN_UNKNOWN_SURNAME_LEN and not _LOWER_WORD_AHEAD_RE.match(
            text, end
        )
    return True


def find_latin_name_spans(text: str) -> list[tuple[int, int]]:
    """Латинские ФИО: «Ivan Petrov», «Sidorova Elena», «Ivan Petrovich Sidorov».

    Нужно имя из словаря (русские имена в транслите и международные без совпадений с обычными
    словами) рядом со словом, похожим на фамилию, отчество или имя. Слова из списка
    NOT_A_NAME_WORDS (должности, технологии, приветствия) имя не продолжают: «Product Manager
    Anna» даёт только «Anna» без пары, а «Visual Studio» не ловится вовсе.

    Returns:
        Пары (начало, конец) непересекающихся находок по порядку.
    """
    return list(iter_latin_name_spans(text))


def has_latin_name(text: str) -> bool:
    """Есть ли в тексте латинское ФИО (останавливается на первой находке; для guard)."""
    return next(iter_latin_name_spans(text), None) is not None


def iter_latin_name_spans(text: str) -> Iterator[tuple[int, int]]:
    """Находки `find_latin_name_spans` по одной, по порядку."""
    for run in _LATIN_RUN_RE.finditer(text):
        words = [(m.start() + run.start(), m.end() + run.start(), m.group())
                 for m in _LATIN_WORD_RE.finditer(run.group())]
        # Регистр одной записи един: «IVAN PETROV» или «Ivan Petrov», но не смесь
        if len({w.isupper() for _, _, w in words}) > 1:
            continue
        kinds = [latin_word_kind(w) for _, _, w in words]
        # Любая связка содержит имя или отчество: без них цепочку («Visual Studio Code») не
        # перебираем
        if KIND_FIRST not in kinds and KIND_PATR not in kinds:
            continue
        index = 0
        while index < len(words):
            matched = 0
            for size in range(min(LATIN_MAX_WORDS, len(words) - index), 1, -1):
                window = words[index:index + size]
                # «Слово Имя Фамилия»: пара «Слово Имя» уступает «Имя Фамилия» со следующего слова
                if kinds[index:index + size] == [KIND_OTHER, KIND_FIRST] and (
                    index + size < len(words) and kinds[index + size] != KIND_STOP
                ):
                    continue
                if _valid_window(
                    tuple(kinds[index:index + size]), text, [w for _, _, w in window],
                    window[-1][1],
                ):
                    matched = size
                    break
            if matched:
                yield words[index][0], words[index + matched - 1][1]
                index += matched
            else:
                index += 1
