"""Дополнительные правила поиска ФИО: латиница и значения JSON-полей по ключу.

Natasha NER разбирает только русский текст и не знает контекста полей, поэтому два вида ФИО
уходили в модель открытыми (тесты на HR-данных, 13.11.2026): имя латиницей («Ivanov Ivan»,
«Elena Sidorova») и значение поля карточки `"name": "Иванов Иван"` без остатка закрывалось
лишь у каждого пятого. Модуль даёт чистые функции: позиции находок, без доступа к сервису.
Все регулярные выражения ограничены по длине и идут по тексту один раз (проверено на
враждебных телах: длинные повторы, большой JSON).
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator
from dataclasses import dataclass

from labops_pii.morph import is_surname_candidate, name_gramme

# Сколько вариантов написания набирается на одно русское имя (транслит неоднозначен).
MAX_TRANSLIT_VARIANTS = 48
# Самая короткая латинская форма имени в словаре: короче («Al», «Li») слишком часто совпадает
# с обычными словами и аббревиатурами.
MIN_LATIN_NAME_LEN = 3
# Слов в латинском ФИО: «Имя Фамилия» и «Фамилия Имя Отчество».
LATIN_MAX_WORDS = 3
# Длина значения поля, дольше которой это не имя.
MAX_FIELD_VALUE_CHARS = 100
MAX_FIELD_VALUE_WORDS = 5
# Ключ поля: имя до 40 знаков; ограничение держит разбор линейным на любом тексте.
MAX_FIELD_KEY_CHARS = 40

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
    "contact interviewer recruiter reference referee spouse".split()
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
    return frozenset(n for n in names if len(n) >= MIN_LATIN_NAME_LEN and n.isascii())


LATIN_FIRST_NAMES = _build_latin_first_names()

# --- латинские ФИО -------------------------------------------------------------------------

# Слово: «Ivan», «IVAN», «Jean-Pierre»; слева и справа не буква/цифра/знак пути или адреса.
_LATIN_WORD = (
    r"(?<![A-Za-z0-9_@./\\:+-])"
    r"(?:[A-Z][a-z]{2,19}(?:-[A-Z][a-z]{2,19})?|[A-Z]{3,20})"
    r"(?![A-Za-z0-9_@/\\-])"
)
# Цепочка слов через пробелы любой длины: окна по 2-3 слова перебираются внутри неё, иначе
# «Senior Developer Maria Ivanova» резалась бы на «Senior Developer Maria» и «Ivanova».
_LATIN_RUN_RE = re.compile(rf"{_LATIN_WORD}(?:[ \t]{{1,3}}{_LATIN_WORD})+")
# После пары «Слово Имя» идёт строчное слово: это английская фраза («Yesterday Anna went»),
# а не запись «Фамилия Имя»
_LOWER_WORD_AHEAD_RE = re.compile(r"[ \t]+[a-z]{2,}")
MIN_UNKNOWN_SURNAME_LEN = 4
_LATIN_WORD_RE = re.compile(_LATIN_WORD)

_KIND_FIRST = "first"
_KIND_PATR = "patr"
_KIND_SURN = "surn"
_KIND_OTHER = "other"
_KIND_STOP = "stop"
# Допустимые связки видов слов (в порядке написания): имя+что-то, фамилия+имя, имя+отчество...
_VALID_PAIRS = frozenset({
    (_KIND_FIRST, _KIND_FIRST), (_KIND_FIRST, _KIND_PATR), (_KIND_FIRST, _KIND_SURN),
    (_KIND_FIRST, _KIND_OTHER), (_KIND_SURN, _KIND_FIRST), (_KIND_PATR, _KIND_SURN),
    (_KIND_SURN, _KIND_PATR), (_KIND_OTHER, _KIND_FIRST),
})
_VALID_TRIPLES = frozenset({
    (_KIND_SURN, _KIND_FIRST, _KIND_PATR), (_KIND_FIRST, _KIND_PATR, _KIND_SURN),
    (_KIND_FIRST, _KIND_PATR, _KIND_OTHER), (_KIND_FIRST, _KIND_FIRST, _KIND_SURN),
    (_KIND_SURN, _KIND_FIRST, _KIND_FIRST),
})


def latin_word_kind(word: str) -> str:
    """Вид латинского слова: имя, отчество, фамилия по суффиксу, «чужое» слово или не-имя."""
    low = word.lower()
    if low in NOT_A_NAME_WORDS:
        return _KIND_STOP
    parts = low.split("-")
    if any(p in LATIN_FIRST_NAMES for p in parts):
        return _KIND_FIRST
    if len(low) >= MIN_PATRONYMIC_LEN and low.endswith(PATRONYMIC_SUFFIXES):
        return _KIND_PATR
    if len(low) >= MIN_SURNAME_LEN and low.endswith(SURNAME_SUFFIXES):
        return _KIND_SURN
    return _KIND_OTHER


def _valid_window(kinds: tuple[str, ...], text: str, words: list[str], end: int) -> bool:
    """Подходит ли набор видов подряд идущих слов под латинское ФИО.

    Пара «неизвестное слово + имя» принимается строже: слово не короче MIN_UNKNOWN_SURNAME_LEN
    и дальше не идёт строчное слово (иначе «Yesterday Anna went home» стало бы ФИО).
    """
    if len(kinds) == 3:
        return kinds in _VALID_TRIPLES
    if kinds not in _VALID_PAIRS:
        return False
    if kinds == (_KIND_OTHER, _KIND_FIRST):
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
    spans: list[tuple[int, int]] = []
    for run in _LATIN_RUN_RE.finditer(text):
        words = [(m.start() + run.start(), m.end() + run.start(), m.group())
                 for m in _LATIN_WORD_RE.finditer(run.group())]
        # Регистр одной записи един: «IVAN PETROV» или «Ivan Petrov», но не смесь
        if len({w.isupper() for _, _, w in words}) > 1:
            continue
        kinds = [latin_word_kind(w) for _, _, w in words]
        index = 0
        while index < len(words):
            matched = 0
            for size in range(min(LATIN_MAX_WORDS, len(words) - index), 1, -1):
                window = words[index:index + size]
                # «Слово Имя Фамилия»: пара «Слово Имя» уступает «Имя Фамилия» со следующего слова
                if kinds[index:index + size] == [_KIND_OTHER, _KIND_FIRST] and (
                    index + size < len(words) and kinds[index + size] != _KIND_STOP
                ):
                    continue
                if _valid_window(
                    tuple(kinds[index:index + size]), text, [w for _, _, w in window],
                    window[-1][1],
                ):
                    matched = size
                    break
            if matched:
                spans.append((words[index][0], words[index + matched - 1][1]))
                index += matched
            else:
                index += 1
    return spans


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
            if latin_word_kind(bare) in (_KIND_FIRST, _KIND_PATR, _KIND_SURN):
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
