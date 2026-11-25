"""Детектор персональных данных в русском тексте."""

from __future__ import annotations

import bisect
import logging
import re
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from natasha import Doc, NewsEmbedding, NewsNERTagger, Segmenter

from labops_pii import checksums
from labops_pii.allowlist import is_allowed_fragment
from labops_pii.config import env_mask_addresses
from labops_pii.morph import (
    WORD_RE,
    common_lemma,
    is_inanimate_common_noun,
    agrees_as_modifier,
    typo_noun_parses,
    is_non_name_word,
    is_person_word,
    is_surname_candidate,
    lemma,
    name_gramme,
    person_key,
    request_cache,
    with_female_subject,
    with_preposition_gender,
)
from labops_pii.latin_names import (
    LATIN_LETTERS,
    LATIN_LOWER,
    LATIN_UPPER,
    NOT_A_NAME_WORDS,
    find_latin_name_spans,
)
from labops_pii.name_hints import (
    find_json_field_names,
    find_quoted_name_spans,
    find_table_cell_names,
)
from labops_pii.patronymic import (
    find_name_patronymic_spans,
    find_surname_name_spans,
    is_dictionary_surname,
    is_surname_near_patronymic,
)
from labops_pii.pii_patterns import (
    ACCOUNT_RE,
    BARE_PHONE_RE,
    INN_GROUPED_LENGTHS,
    INN_GROUPED_RE,
    NICK_RE,
    PHONE_LOOSE_RE,
    PHONE_RE,
    SKYPE_RE,
    SNILS_KEYWORD_WINDOW,
    SNILS_RE,
    TME_RE,
    find_address_spans,
    find_card_spans,
    find_obfuscated_emails,
    find_snils_spans,
    fold_for_names,
    has_inn_word_before,
    normalize_text,
)
from labops_pii.tech_tokens import find_tech_spans

logger = logging.getLogger(__name__)

# Типы находок, к которым применяется белый список слов
ALLOWLIST_TYPES = frozenset({"PERSON", "ORG", "CONTACT"})

INITIAL_TAIL_RE = re.compile(r"[ \t]*[А-ЯЁ]\.[ \t]?(?:[А-ЯЁ]\.)?")
INITIAL_HEAD_RE = re.compile(r"[А-ЯЁ]\.[ \t]?(?:[А-ЯЁ]\.)?[ \t]*$")
# Кавычки всех видов («ёлочки», „лапки“, “английские”, ‹одинарные›) обрезаются с краёв ФИО:
# NER берёт закрывающую кавычку в находку, и она уходила под токен
QUOTE_CHARS = "«»‹›„“”‟\"'"
TRIM_CHARS = " \t\n\r,.;:!?()" + QUOTE_CHARS
HEAD_WINDOW = 64  # окно слева от ФИО для поиска инициалов
# Слово-фамилия вплотную слева от «Имя Отчество» (в той же строке): NER его теряет, когда
# перед ним должность («директор Дудорова Марина Евгеньевна» - «Дудорова» читается как
# родительный падеж «директора Дудорова»), и фамилия уходила наружу открытым текстом.
SURNAME_BEFORE_RE = re.compile(r"([А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?)[ \t]+$")
# Самое короткое слово в смешанной по регистру группе ФИО: короче («Ян», «Ли») слишком часто
# совпадает с обычными словами
MIN_MIXED_NAME_LEN = 4
KEYWORD_WINDOW = 16  # сколько символов слева от числа смотрим на ключевое слово
PHONE_DIGITS_WITH_PREFIX = 11
PHONE_NATIONAL_DIGITS = 10
DIGITS_RE = re.compile(r"\D")
CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")
CYRILLIC_WORD_RE = re.compile(r"[А-Яа-яЁё]+")
# Слово целиком заглавными / строчными (с возможной второй частью через дефис) и инициалы
# в том же регистре: NER такие ФИО не видит, поэтому есть отдельное правило по морфологии.
CAPS_WORD_RE = re.compile(r"[А-ЯЁ]{2,}(?:-[А-ЯЁ]{2,})?|[а-яё]{2,}(?:-[а-яё]{2,})?")
CAPS_INITIALS_RE = re.compile(
    r"[ \t]*(?:[А-ЯЁ]\.[ \t]?(?:[А-ЯЁ]\.)?|[а-яё]\.[ \t]?(?:[а-яё]\.)?)"
)
CAPS_GAP_RE = re.compile(r"[ \t]+")
# Фамилия с двумя инициалами справа или слева без NER (R9-A4-12): Natasha пропускает
# «Заказ у Петрова О.И. оформлен.» целиком, и фамилия с инициалами уходила в модель.
# Требуются именно два инициала: одна буква с точкой бывает сокращением («г.», «П. 3»).
# Фамилия капсом рядом с инициалами: короче - аббревиатура («АЗС», «ТЭЦ»)
MIN_CAPS_SURNAME_LEN = 4
INITIALED_WORD = r"[А-ЯЁ][а-яё]{2,}(?:-[А-ЯЁ][а-яё]{2,})?"
TWO_INITIALS = r"[А-ЯЁ]\.[ \t]?[А-ЯЁ]\."
# Точка после второго инициала бывает опущена: «Петров А.Б: на связи», «Петров А.Б,»
TWO_INITIALS_LAST_DOT_OPTIONAL = r"[А-ЯЁ]\.[ \t]?[А-ЯЁ]\.?"
SURNAME_INITIALS_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z0-9_.-])({INITIALED_WORD})[ \t]+({TWO_INITIALS_LAST_DOT_OPTIONAL})"
    r"(?![А-Яа-яЁёA-Za-z0-9])"
)
INITIALS_SURNAME_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z0-9_.-])({TWO_INITIALS})[ \t]?({INITIALED_WORD})"
    r"(?![А-Яа-яЁёA-Za-z0-9_-])"
)
# Фамилия с ОДНИМ инициалом («Иванов С.», «А. Кузнецов»): NER такие пары почти не размечал, и
# фамилия уходила в модель. Одна буква с точкой бывает сокращением, поэтому фамилия здесь
# только словарная (`is_dictionary_surname`), а второй инициал рядом отдан шаблонам выше.
SURNAME_ONE_INITIAL_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z0-9_.-])({INITIALED_WORD})[ \t]+([А-ЯЁ])\."
    r"(?![ \t]?[А-ЯЁ]\.)(?![А-Яа-яЁё])"
)
# Фамилия капсом и два инициала («ПЕХТЫШЕВА Ю.А.», «ГОЛОВАЧ Д.И.»): детектор капса берёт
# только слова с главным разбором «фамилия», и фамилия вне словаря уходила в модель
CAPS_SURNAME_INITIALS_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z0-9_.-])([А-ЯЁ]{{{MIN_CAPS_SURNAME_LEN},}}(?:-[А-ЯЁ]{{2,}})?)"
    rf"[ \t]+({TWO_INITIALS})(?![А-Яа-яЁё])"
)
ONE_INITIAL_SURNAME_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z0-9_.-])([А-ЯЁ])\.[ \t]?({INITIALED_WORD})"
    r"(?![А-Яа-яЁёA-Za-z0-9_.-])"
)
# Предлоги перед ФИО (R9-A4-07). После предлога ФИО стоит в косвенном падеже, а женская
# фамилия на «-а» бывает только в именительном: «от Петрова», «у Петрова И.И.» — мужчина.
PREPOSITIONS = frozenset({
    "без", "в", "во", "вместо", "возле", "для", "до", "за", "из", "к", "ко", "кроме", "мимо",
    "на", "над", "о", "об", "обо", "около", "от", "перед", "по", "под", "после", "при",
    "про", "против", "ради", "с", "со", "среди", "у", "через",
})
PREPOSITION_WINDOW = 16  # сколько символов слева от ФИО смотрим на предлог
PREPOSITION_BEFORE_RE = re.compile(r"(?<![А-Яа-яЁёA-Za-z])([А-Яа-яЁё]+)[ \t]+\Z")
# ФИО в начале фразы и сразу глагол прошедшего времени женского рода или «она»: подлежащее,
# женщина («Петрова Александра подписала договор»), а не мужской родительный падеж
FEMININE_SUBJECT_AFTER_RE = re.compile(
    r"(?:[ \t]{0,3},[ \t]{1,3}|[ \t]{1,3})([а-яё]{2,}ла(?:сь)?|она)(?![а-яё])"
)
# Слова на «-ла», которые не глаголы: «дела Петрова Александра» - его дела, родительный падеж
NOT_FEMININE_VERBS = frozenset({"дела", "тела", "села", "стола", "числа", "зала", "крыла", "она"})
PHRASE_START_CHARS = "\n.!?:;—–«\"("
# Группа слов одного регистра не режется по числу слов: «ФАМИЛИЯ ИМЯ ОТЧЕСТВО ДОПОЛНЕНИЕ»
# (двойное имя, «оглы», «кызы») целиком скрывается, а не оставляет четвёртое слово открытым.


class PiiType(StrEnum):
    """Типы персональных данных и реквизитов."""

    PERSON = "PERSON"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    INN = "INN"
    OGRN = "OGRN"
    OGRNIP = "OGRNIP"
    SNILS = "SNILS"
    CARD = "CARD"
    ACCOUNT = "ACCOUNT"
    PASSPORT = "PASSPORT"
    CONTACT = "CONTACT"
    ORG = "ORG"
    ADDRESS = "ADDRESS"


@dataclass(frozen=True, slots=True)
class Detection:
    """Найденный фрагмент ПДн.

    Attributes:
        start: Начало в тексте (символы).
        end: Конец (не включительно).
        pii_type: Тип.
        key: Нормализованное значение для сопоставления между падежами и форматами.
        priority: Меньше — важнее при пересечении фрагментов.
        exact: Фрагмент — часть имени файла/пути: токен переиспользуется только при полном
            совпадении написания (иначе `/restore` вставил бы в имя файла «Иванов И.И.»).
    """

    start: int
    end: int
    pii_type: PiiType
    key: str
    priority: int
    exact: bool = False


# Приоритеты при пересечениях (меньше — важнее).
PRIO_IP = 0
PRIO_EMAIL = 1
PRIO_SNILS = 2
PRIO_PASSPORT = 3
PRIO_CARD = 3
PRIO_ACCOUNT = 4
PRIO_OGRN = 4
PRIO_INN = 5
PRIO_PHONE = 6
PRIO_CONTACT = 7
# СНИЛС только по контрольной сумме (без слова «СНИЛС»): тот же номер, найденный как телефон,
# остаётся телефоном (диапазон тот же, маска та же), а не СНИЛС
PRIO_SNILS_CHECKSUM = 7
# Адрес сильнее ФИО: название улицы по фамилии («ул. Ленина», «пр-т Иванова») Natasha читает как
# PERSON, и без этого приоритета в адресе остался бы токен ФИО вместо одного токена адреса.
PRIO_ADDRESS = 7
PRIO_PERSON = 8
PRIO_ORG = 9

_CAP = r"[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?"
IP_RE = re.compile(
    r"(?:\bИП|(?i:\bиндивидуальн\w+\s+предпринимател\w+))[ \t]+"
    rf"{_CAP}"
    rf"(?:[ \t]+(?:[А-ЯЁ]\.[ \t]?[А-ЯЁ]\.|[А-ЯЁ]\.|[А-ЯЁ][а-яё]+(?:[ \t]+[А-ЯЁ][а-яё]+)?))?"
    r"(?:[,;]?[ \t]*(?:ИНН|ОГРНИП)[ \t]*[:№]?[ \t]*(?:\d{12}|\d{15}))*"
)
# ИП с ФИО заглавными (R4-SEC-10): «ИП ПЕТРОВ», «ИП ПЕТРОВ ИВАН ИВАНОВИЧ», «ИП ПЕТРОВ И.И.»,
# «Индивидуальный предприниматель ПЕТРОВ». Регулярное выражение берёт только слова и
# инициалы; служебные слова и словарные существительные («ИП ООО РОМАШКА», «ИП ЗАКАЗЧИК»)
# отсекает _caps_ip_spans по стоп-списку и морфологии.
_CAPS = r"[А-ЯЁ]{2,}(?:-[А-ЯЁ]{2,})?"
IP_CAPS_RE = re.compile(
    r"(?:\bИП|(?i:\bиндивидуальн\w+\s+предпринимател\w+))[ \t]+"
    rf"(?P<first>{_CAPS})"
    r"(?P<rest>[ \t]+[А-ЯЁ]\.[ \t]?(?:[А-ЯЁ]\.)?"
    rf"|(?:[ \t]+(?!(?:ИНН|ОГРНИП|ОГРН|КПП)\b){_CAPS}){{0,2}})"
    r"(?:[,;]?[ \t]*(?:ИНН|ОГРНИП)[ \t]*[:№]?[ \t]*(?:\d{12}|\d{15}))*"
)
# Слова капсом, которые не бывают частью ФИО предпринимателя (реквизиты, формы юрлиц)
CAPS_IP_STOPWORDS = frozenset({
    "ИНН", "ОГРНИП", "ОГРН", "КПП", "ОКПО", "БИК", "ТЕЛ", "ООО", "АО", "ПАО", "ЗАО", "ОАО",
    "НАО", "ИП", "ГОСТ", "ТУ", "DIN", "ISO", "АДРЕС", "ПОЧТА", "ТЕЛЕФОН", "СЧЁТ", "СЧЕТ",
    # роли и должности из шапок документов: pymorphy видит в них «фамилию»
    "ЗАКАЗЧИК", "ПОСТАВЩИК", "ПОКУПАТЕЛЬ", "ПРОДАВЕЦ", "ИСПОЛНИТЕЛЬ", "ПОДРЯДЧИК", "КЛИЕНТ",
    "КОНТРАГЕНТ", "ПЛАТЕЛЬЩИК", "ПОЛУЧАТЕЛЬ", "ОТПРАВИТЕЛЬ", "ДИРЕКТОР", "РУКОВОДИТЕЛЬ",
    "БУХГАЛТЕР", "МЕНЕДЖЕР", "ПРЕДПРИНИМАТЕЛЬ", "ПРЕДСТАВИТЕЛЬ", "ПОДПИСАНТ", "ОТВЕТСТВЕННЫЙ",
})
CAPS_WORD_IN_REST_RE = re.compile(rf"[ \t]+({_CAPS})")
# Ключевое слово ИП слева от слова (для одиночной фамилии капсом без инициалов)
IP_HEAD_RE = re.compile(
    r"(?:\b(?i:ип)|(?i:\bиндивидуальн\w+\s+предпринимател\w+))[ \t]*:?[ \t]+$"
)
# Служебные слова ИП-конструкции, которые не входят в ключ ФИО.
IP_NOISE_RE = re.compile(
    r"\bИП\b|ИНН|ОГРНИП|\d+|[№:]|(?i:индивидуальн\w+|предпринимател\w+)"
)
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Телефоны, карты, счета и СНИЛС ищутся общими с pii-guard шаблонами (pii_patterns).
# Левая граница как у pii-guard: «арт.7707083893» и «1,7707083893» шлюз отклонил бы, поэтому
# число должно маскироваться (токен потом восстанавливается, потери для смысла нет).
NUM10_12_RE = re.compile(r"(?<!\d)(?:\d{12}|\d{10})(?!\d)")
OGRN_RE = re.compile(r"(?<![\d.,])(?:\d{15}|\d{13})(?!\d)")
# Промежутки ограничены: «[ \t]+…[ \t]*» на длинном ряду пробелов давал квадратичный перебор
# (70 000 знаков - 46 с, ревью 25.11.2026)
PASSPORT_SEP_RE = re.compile(
    r"(?<![\d.,])\d{2}[ \t]?\d{2}"
    r"(?:[ \t]{1,3}(?:№|N|номер)?[ \t]{0,3}|[ \t]{0,3}(?:№|N|номер)[ \t]{0,3})\d{6}(?!\d)"
)
# Серия и номер со знаками между ними («серия 4510, номер 123456», «4510-123456», «Серия:
# 45 10, № 123456») - паспорт только при слове «паспорт»/«серия» рядом
PASSPORT_LOOSE_RE = re.compile(
    r"(?<![\d.,])\d{2}[ \t]?\d{2}[ \t]{0,3}[,;:\-]?[ \t]{0,3}"
    r"(?:(?:№|N|номер|ном\.)[ \t]{0,3}:?[ \t]{0,3})?\d{6}(?!\d)"
)
PASSPORT_KEYWORD_WINDOW = 24
# Паспорт без слова «паспорт» (матрица 25.11.2026): за серией и номером идёт «выдан», «код
# подразделения», «дата выдачи» («Документ: 4510123456, выдан 01.02.2010») или слева
# «удостоверение личности». Слово «документ» само по себе не признак: номера актов и счетов
# тоже «документы». Между номером и словом нет цифр и перевода строки.
PASSPORT_AFTER_WINDOW = 40
PASSPORT_AFTER_RE = re.compile(
    rf"[^\d\n]{{0,{PASSPORT_AFTER_WINDOW}}}?(?<![а-яё])(?i:выдан|код[ \t]+подразделения|"
    r"дата[ \t]+выдачи)"
)
KW_PASSPORT_IDENTITY = ("удостоверени", "удостоверяющ")
# «Удостоверение личности 4510-123456»: до начала слова два слова и пробелы
PASSPORT_IDENTITY_WINDOW = 32
# Другие документы тоже «выданы»: номер после них - не паспорт («Накладная 4510123456 выдана»)
KW_OTHER_DOCUMENTS = (
    "наклад", "счет", "счёт", "акт", "договор", "заказ", "доверен", "справк", "квитанц", "чек",
    "упд", "ттн", "лиценз", "сертификат", "полис", "пропуск", "диплом", "аттестат",
)
PASSPORT_KW_RE = re.compile(r"(?<![\d.,])\d{10}(?!\d)")
ORG_RE = re.compile(
    r"\b(?:ООО|АО|ПАО|ЗАО|ОАО|НАО|ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ)[ \t]+"
    r"(?:«[^»\n]{1,80}»|\"[^\"\n]{1,80}\"|[А-ЯЁA-Z][\w-]*)"
)

# Латинское ФИО («Li Wei», «John Smith») - только сразу после метки контакта: Natasha
# латиницу не разбирает, а имя без метки не отличить от названия товара или компании.
LATIN_NAME_LABEL_RE = re.compile(
    r"(?<![A-Za-z])(?i:contact(?:[ \t]+person)?|attn|attention|sales[ \t]+manager|manager|"
    r"representative|best[ \t]+regards|kind[ \t]+regards|regards|sincerely|signed)"
    r"[ \t]*[:,\-]?[ \t\r\n]{0,3}"
    rf"(?P<name>[{LATIN_UPPER}][{LATIN_LOWER}]{{1,19}}"
    rf"(?:[ \t]+[{LATIN_UPPER}][{LATIN_LOWER}]{{1,19}}){{1,2}})(?![{LATIN_LETTERS}])"
)
LATIN_NAME_WORD_RE = re.compile(rf"[{LATIN_UPPER}][{LATIN_LOWER}]+")
LATIN_MIN_NAME_WORDS = 2
# Короче слово в повторе не ищется отдельно: «Li», «Mo» слишком часто встречаются сами
LATIN_MIN_REPEAT_WORD_LEN = 3
# Международный префикс вместо «+»
INTL_ZERO_PREFIX = "00"
# Слова, которые после метки означают отдел/компанию, а не человека
LATIN_NOT_NAME_WORDS = frozenset(
    "accounts accounting payable receivable department dept office team support sales service "
    "services customer customers head general company co ltd llc inc limited group trading "
    "logistics procurement purchasing purchase export import management finance legal hr "
    "technical engineering production quality warehouse shipping supply department "
    "regards thanks thank dear hello hi best kind "
    "please us today information details sheet".split()
)

# допустимые первые цифры ОГРН (признак сведений о юрлице: 1 или 5); у EAN-13 их больше
OGRN_FIRST_DIGITS = ("1", "5")

# Слова адреса, не входящие в ключ: ключевые слова улицы во всех падежах и пометки дома.
# Ключ строится без них, чтобы «ул. Ленина, д. 5» и «на улице Ленина, дом 5» были одним
# адресом и получали один токен.
# Тип улицы в ключе адреса - одним кодом: «ул. Мира, д. 5» и «пр-т Мира, д. 5» - разные адреса
# (раньше тип выбрасывался, и restore второго возвращал первый, ревью 25.11.2026), а падеж и
# сокращение типа ключ не меняют
ADDRESS_STREET_TYPES: dict[str, tuple[str, ...]] = {
    "ул": ("улица", "улице", "улицу", "улицы", "улицей", "ул", "ul", "ulitsa", "ulica", "street",
           "str", "st"),
    "пр": ("проспект", "проспекта", "проспекте", "проспекту", "проспектом", "просп", "пр",
           "пр-т", "пр-кт", "pr", "prosp", "prospekt", "prospect", "avenue", "ave"),
    "пер": ("переулок", "переулка", "переулке", "переулку", "переулком", "пер", "per",
            "pereulok", "lane", "ln"),
    "бр": ("бульвар", "бульвара", "бульваре", "бульвару", "бульваром", "б-р", "бул", "bul",
           "bulvar", "boulevard", "blvd"),
    "наб": ("набережная", "набережной", "набережную", "наб", "nab", "naberezhnaya",
            "embankment", "emb"),
    "ш": ("шоссе", "ш", "sh", "shosse", "highway"),
    "дор": ("road", "rd"),
    "пл": ("площадь", "площади", "площадью", "пл", "pl", "ploshchad", "square", "sq"),
    "прд": ("проезд", "проезда", "проезде", "проезду", "проездом", "пр-д"),
    "туп": ("тупик", "тупика", "тупике", "тупику", "тупиком"),
    "ал": ("аллея", "аллеи", "аллее", "аллею", "аллеей"),
    "мкр": ("микрорайон", "микрорайона", "микрорайоне", "микрорайону", "мкр", "мкрн"),
}
ADDRESS_STREET_TYPE_CODES = {
    word: code for code, words in ADDRESS_STREET_TYPES.items() for word in words
}
# Префикс кода типа улицы в ключе: не буква, с названием улицы не совпадёт
ADDRESS_STREET_TYPE_PREFIX = "#"
ADDRESS_NOISE_WORDS = frozenset({"д", "дом", "влд", "владение", "по", "на", "реки", "канала",
                                 "озера", "d", "dom", "bld", "building", "house", "h", "no"})
# Квартира, корпус и т.п. в ключе записываются одной буквенной меткой перед номером
ADDRESS_SUFFIX_CODES = {
    "корп": "к", "корпус": "к", "к": "к", "стр": "с", "строение": "с", "с": "с",
    "лит": "л", "литера": "л", "кв": "кв", "квартира": "кв", "оф": "оф", "офис": "оф",
    "пом": "пом", "помещение": "пом", "комн": "комн", "комната": "комн", "эт": "эт",
    "этаж": "эт", "apt": "кв", "ap": "кв", "apartment": "кв", "kv": "кв", "office": "оф",
    "of": "оф", "suite": "оф", "ste": "оф",
}
# Латинские слова тоже в ключе: иначе «Tverskaya st. 7» и «Lenina st. 7» дали бы один ключ «7»
ADDRESS_TOKEN_RE = re.compile(
    r"[А-Яа-яЁё]+(?:-[А-Яа-яЁё]+)*|[A-Za-z]+(?:-[A-Za-z]+)*|\d+(?:-\d+)?[А-Яа-яA-Za-z]?"
)

KW_INN = ("инн",)
KW_OGRN = ("огрн",)
KW_SNILS = ("снилс",)
KW_PASSPORT = ("паспорт", "серия", "серии")


def _keyword_before(
    text: str,
    pos: int,
    words: Iterable[str],
    window_size: int = KEYWORD_WINDOW,
    word_start: bool = False,
) -> bool:
    """Проверяет, есть ли одно из слов в коротком окне слева от позиции.

    Args:
        text: Текст.
        pos: Позиция числа.
        words: Ключевые слова (строчные).
        window_size: Размер окна слева, символов.
        word_start: Требовать левую границу слова. Нужна только там, где слово коротко и
            встречается внутри обычных слов: «инн» в «длинная». Для остальных слов границы
            нет намеренно: «загранпаспорт 4512345678» должен находиться (как до этапа).
            Правой границы нет нигде: «ИНН1234567890» и «ИНН:1234567890» находятся.
    """
    window = text[max(0, pos - window_size):pos].lower()
    if not word_start:
        return any(w in window for w in words)
    return any(re.search(rf"(?<![а-яёa-z]){re.escape(w)}", window) for w in words)


def _passport_context(text: str, start: int, end: int, window_size: int) -> bool:
    """Серия и номер в контексте паспорта: слово «паспорт»/«серия» или «удостоверение
    личности» слева либо «выдан»/«код подразделения»/«дата выдачи» справа.

    Args:
        text: Текст.
        start: Начало номера.
        end: Конец номера.
        window_size: Окно слева для слова «паспорт»/«серия».
    """
    if _keyword_before(text, start, KW_PASSPORT, window_size) or _keyword_before(
        text, start, KW_PASSPORT_IDENTITY, PASSPORT_IDENTITY_WINDOW
    ):
        return True
    return PASSPORT_AFTER_RE.match(text, end) is not None and not _keyword_before(
        text, start, KW_OTHER_DOCUMENTS, PASSPORT_IDENTITY_WINDOW, word_start=True
    )


class PiiDetector:
    """Находит ПДн: ФИО (Natasha NER), телефоны, email, ИНН, ОГРН, СНИЛС, паспорт, контакты."""

    def __init__(
        self,
        mask_legal_entity_requisites: bool = False,
        contacts: Sequence[str] = (),
        mask_addresses: bool | None = None,
    ) -> None:
        """Создаёт детектор и загружает модель Natasha.

        Args:
            mask_legal_entity_requisites: Маскировать ли НАЗВАНИЯ организаций (ORG).
                Числовые реквизиты (ИНН, ОГРН/ОГРНИП, счета) маскируются всегда,
                независимо от значения: иначе вторая линия защиты (pii-guard) отклоняет запрос.
            contacts: Словарь контактов (точное совпадение без учёта регистра).
            mask_addresses: Маскировать ли адрес (улица + дом, индекс). Выключатель отката
                PSEUDONYMIZER_ADDRESS_MASK=off: поведение до этапа Г. None - из окружения
                (PSEUDONYMIZER_ADDRESS_MASK, по умолчанию включено).
        """
        self._mask_legal = mask_legal_entity_requisites
        # None - значение PSEUDONYMIZER_ADDRESS_MASK (по умолчанию вкл.)
        self._mask_addresses = env_mask_addresses() if mask_addresses is None else (
            mask_addresses
        )
        self._segmenter = Segmenter()
        self._ner = NewsNERTagger(NewsEmbedding())
        cleaned = sorted({c.strip() for c in contacts if c.strip()}, key=len, reverse=True)
        self._contacts_re: re.Pattern[str] | None = None
        self._contact_keys = {c.casefold() for c in cleaned}
        if cleaned:
            alt = "|".join(re.escape(c) for c in cleaned)
            self._contacts_re = re.compile(rf"(?<!\w)(?:{alt})(?!\w)", re.IGNORECASE)

    def detect(self, text: str, known_lemmas: Collection[str] = ()) -> list[Detection]:
        """Возвращает непересекающиеся находки, отсортированные по позиции.

        Args:
            text: Исходный текст.
            known_lemmas: Леммы слов ФИО, уже известных в треде. Такие слова маскируются,
                даже если NER их пропустил (например, одинокая фамилия в начале фразы).
        """
        # Разборы pymorphy и ключи ФИО запоминаются на весь запрос: детекторы ниже проходят
        # по одним и тем же словам, а общий LRU на длинном тексте их вытесняет (R9-A4-08).
        with request_cache():
            return self._detect(text, known_lemmas)

    def _detect(self, text: str, known_lemmas: Collection[str]) -> list[Detection]:
        """Тело `detect` внутри памяти разборов запроса."""
        found: list[Detection] = []
        # Цифровые ПДн ищутся в нормализованной копии той же длины (NFKC, тире и «/» -> «-»,
        # NBSP -> пробел): позиции совпадают с исходным текстом, замена идёт по оригиналу.
        norm = normalize_text(text)
        found += self._detect_ip(text, norm)
        found += self._detect_email(norm)
        found += self._detect_phone(norm)
        found += self._detect_numbers(norm)
        found += self._detect_contacts(text, norm)
        if self._mask_addresses:
            found += self._detect_addresses(text)
        # Технические токены считаются один раз на запрос: функция чистая, а пять детекторов
        # раньше пересчитывали её каждый сам (~130 мс на тексте в 70 тыс. символов).
        tech = find_tech_spans(text)
        # Кириллические детекторы ФИО идут по свёрнутой копии той же длины: без невидимых знаков,
        # меток направления письма и латинских гомоглифов, иначе разорванное или подменённое имя
        # проходит мимо NER и морфологии. На чистом тексте копия побайтно равна оригиналу.
        folded = fold_for_names(text)
        found += self._detect_persons(folded, tech)
        found += self._detect_latin_names(text, tech)
        found += self._detect_field_names(text)
        found += self._detect_mixed_case_persons(folded, tech)
        found += self._detect_case_shifted_persons(folded, tech)
        atoms = self._detect_initialed_surnames(folded, tech)
        atoms += self._detect_name_patronymic(folded, tech)
        # Находка ФИО, целиком составленная из двух и более людей («Петров А.Б. Сидоров
        # В.Г.», «Иван Петров Анна Сидорова»), делится на них: иначе оба получали один токен,
        # и restore любого из них по отдельности возвращал обоих (ревью 25.11.2026)
        found = _drop_multi_person_spans(found, atoms, folded) + atoms
        found += self._detect_known_names(folded, known_lemmas, tech)
        found += self._detect_tech_names(folded, tech, known_lemmas)
        # Слова ФИО, найденные в этом же тексте, ловятся и в других местах: подвал карточки
        # «Фамилия Имя • Резюме обновлено» после поля "name" иначе оставался открытым (NER не
        # видит фамилию без контекста, а леммы треда пополняются только после ответа)
        found += self._detect_repeated_names(folded, found, known_lemmas, tech)
        if self._mask_legal:
            found += self._detect_orgs(text)
        # Слова белого списка (PII_ALLOWED_WORDS) не ПДн: ни ФИО, ни организация
        found = [
            d for d in found
            if not (
                d.pii_type in ALLOWLIST_TYPES and is_allowed_fragment(text[d.start:d.end])
            )
        ]
        resolved = [_with_initial_dot(d, text) for d in _resolve_overlaps(found, text)]
        return _with_preposition_genders(text, resolved)

    # --- регулярные детекторы -------------------------------------------------

    def _detect_ip(self, text: str, norm: str) -> list[Detection]:
        """ИП целиком (ФИО + ИНН/ОГРНИП) — это ФИО физлица."""
        result: list[Detection] = []
        for m in IP_RE.finditer(text):
            key = person_key(IP_NOISE_RE.sub("", m.group()))
            result.append(Detection(m.start(), m.end(), PiiType.PERSON, key, PRIO_IP))
        # Цифры ИНН/ОГРНИП ищутся в нормализованной копии (цифры любых систем счисления),
        # позиции совпадают; ключ строится по оригиналу.
        for m in IP_CAPS_RE.finditer(norm):
            end = _caps_ip_end(m)
            if end is None:
                continue
            key = person_key(IP_NOISE_RE.sub("", text[m.start():end]))
            result.append(Detection(m.start(), end, PiiType.PERSON, key, PRIO_IP))
        return result

    def _detect_email(self, text: str) -> list[Detection]:
        found = [
            Detection(m.start(), m.end(), PiiType.EMAIL, m.group().lower(), PRIO_EMAIL)
            for m in EMAIL_RE.finditer(text)
        ]
        # Запись в обход «@» - тот же адрес: ключ как у «local@domain», токен общий
        found += [
            Detection(start, end, PiiType.EMAIL, f"{local}@{domain}".lower(), PRIO_EMAIL)
            for start, end, local, domain in find_obfuscated_emails(text)
        ]
        return found

    def _detect_phone(self, text: str) -> list[Detection]:
        result: list[Detection] = []
        for m in PHONE_RE.finditer(text):
            digits = DIGITS_RE.sub("", m.group())
            # 8/7 + 10 цифр; у международного «+код» первая цифра - часть кода страны
            is_ru_form = not m.group().startswith("+") or m.group().startswith("+7")
            if len(digits) == PHONE_DIGITS_WITH_PREFIX and is_ru_form:
                digits = digits[1:]
            elif m.group().startswith(INTL_ZERO_PREFIX):
                # «0086 …» и «+86 …» - один номер: ключ без префикса «00»
                digits = digits[len(INTL_ZERO_PREFIX):]
            result.append(Detection(m.start(), m.end(), PiiType.PHONE, digits, PRIO_PHONE))
        # Необычная разбивка после «+7» или слова «тел» («+7 916 12 345 67»)
        for m in PHONE_LOOSE_RE.finditer(text):
            start, end = m.span(1) if m.group(1) is not None else m.span()
            digits = DIGITS_RE.sub("", text[start:end])[-PHONE_NATIONAL_DIGITS:]
            result.append(Detection(start, end, PiiType.PHONE, digits, PRIO_PHONE))
        # Десять цифр подряд — телефон только после слова «тел» (ключевое слово внутри шаблона)
        for m in BARE_PHONE_RE.finditer(text):
            number = m.group(1)
            if checksums.is_valid_inn(number):
                continue
            if _keyword_before(text, m.start(1), KW_INN, word_start=True):
                continue
            result.append(Detection(m.start(1), m.end(1), PiiType.PHONE, number, PRIO_PHONE))
        return result

    def _detect_latin_names(self, text: str, tech: list[tuple[int, int]]) -> list[Detection]:
        """Латинские ФИО: после метки контакта («Contact: Li Wei») и по словарю имён.

        Найденное после метки или по словарю имя ищется по всему тексту: целиком (в той же
        записи слов) и каждое слово отдельно (фамилия «Smith»), с точным совпадением регистра
        и границами слова. Без метки и без пары «имя из словаря + слово» одиночное латинское
        слово не маскируется (правила словаря - в `latin_names.find_latin_name_spans`).
        """
        result: list[Detection] = []
        names: list[list[str]] = []
        for m in LATIN_NAME_LABEL_RE.finditer(text):
            start = m.start("name")
            end = start
            words: list[str] = []
            for word in LATIN_NAME_WORD_RE.finditer(m.group("name")):
                low = word.group().lower()
                if low in LATIN_NOT_NAME_WORDS or low in NOT_A_NAME_WORDS:
                    break
                end = start + word.end()
                words.append(word.group())
            if len(words) >= LATIN_MIN_NAME_WORDS:
                result.append(Detection(
                    start, end, PiiType.PERSON, person_key(text[start:end]), PRIO_PERSON
                ))
                names.append(words)
        for start, end in find_latin_name_spans(text):
            if _overlaps(tech, start, end):
                continue  # имя внутри пути или адреса
            result.append(Detection(
                start, end, PiiType.PERSON, person_key(text[start:end]), PRIO_PERSON
            ))
            names.append(text[start:end].split())
        if names:
            result += self._latin_name_repeats(text, names)
        return result

    def _detect_field_names(self, text: str) -> list[Detection]:
        """Значения полей `"full_name": "..."`, ячейки таблиц `| Иванов Иван |` и ФИО в кавычках.

        NER в JSON и в строках таблиц теряет имя без контекста (в карточках закрывалась лишь
        пятая часть имён, в ячейках - треть): здесь контекстом служит ключ поля или сама
        ячейка. Правила - в `name_hints.find_json_field_names` и `find_table_cell_names`.
        """
        spans = [(f.start, f.end) for f in find_json_field_names(text)]
        spans += find_table_cell_names(text)
        spans += find_quoted_name_spans(text)
        return [
            Detection(start, end, PiiType.PERSON, person_key(text[start:end]), PRIO_PERSON)
            for start, end in spans
        ]

    @staticmethod
    def _latin_name_repeats(text: str, names: list[list[str]]) -> list[Detection]:
        """Повторы уже найденных латинских ФИО: полная форма и отдельные слова имени.

        Совпадения пересекаются с находками по метке; лишнее отбрасывает _resolve_overlaps.
        """
        forms: dict[str, str] = {}
        for words in names:
            full = r"[ \t]+".join(re.escape(w) for w in words)
            forms[full] = " ".join(words)
            for word in words:
                if len(word) >= LATIN_MIN_REPEAT_WORD_LEN:
                    forms[re.escape(word)] = word
        # Длинные формы первыми: «John Smith» не должен распасться на «John» и «Smith»
        alt = "|".join(sorted(forms, key=len, reverse=True))
        repeat_re = re.compile(rf"(?<![A-Za-z0-9_])(?:{alt})(?![A-Za-z0-9_])")
        return [
            Detection(m.start(), m.end(), PiiType.PERSON, person_key(m.group()), PRIO_PERSON)
            for m in repeat_re.finditer(text)
        ]

    def _detect_numbers(self, text: str) -> list[Detection]:
        """ИНН, ОГРН/ОГРНИП, СНИЛС, паспорт — по формату, контрольной сумме и ключевым словам."""
        result: list[Detection] = []
        # «тел 9161234567»: номер после слова «тел» - телефон, даже если сошлась сумма ИНН
        # (иначе модель видела бы «[INN_1]» вместо телефона, матрица 25.11.2026)
        phone_spans = {m.span(1) for m in PHONE_LOOSE_RE.finditer(text) if m.group(1)}
        for m in NUM10_12_RE.finditer(text):
            digits = m.group()
            kw = _keyword_before(text, m.start(), KW_INN, word_start=True)
            if not (checksums.is_valid_inn(digits) or kw) or (not kw and m.span() in phone_spans):
                continue
            result.append(Detection(m.start(), m.end(), PiiType.INN, digits, PRIO_INN))
        for m in OGRN_RE.finditer(text):
            digits = m.group()
            kw = _keyword_before(text, m.start(), KW_OGRN)
            if len(digits) == checksums.OGRNIP_LEN:
                if checksums.is_valid_ogrnip(digits) or kw:
                    result.append(Detection(m.start(), m.end(), PiiType.OGRNIP, digits, PRIO_OGRN))
            elif kw or (
                checksums.is_valid_ogrn(digits) and digits.startswith(OGRN_FIRST_DIGITS)
            ):
                # без слова «огрн» ОГРН начинается с 1 или 5; иначе это штрихкод EAN-13
                result.append(Detection(m.start(), m.end(), PiiType.OGRN, digits, PRIO_OGRN))
        for m in SNILS_RE.finditer(text):
            digits = DIGITS_RE.sub("", m.group())
            kw = _keyword_before(text, m.start(), KW_SNILS, SNILS_KEYWORD_WINDOW)
            dashed = "-" in m.group() or " " in m.group()
            if kw or (dashed and checksums.is_valid_snils(digits)):
                result.append(Detection(m.start(), m.end(), PiiType.SNILS, digits, PRIO_SNILS))
        # Всё, что шлюз (pii-guard) счёл бы СНИЛС, маскируется и без ключевого слова: правило
        # общее (find_snils_spans), иначе запрос с артикулом «31234567846» шлюз отклоняет
        # (R9-A4-04). Токен обратимый, смысл артикула /restore возвращает.
        for start, end in find_snils_spans(text):
            digits = DIGITS_RE.sub("", text[start:end])
            result.append(Detection(start, end, PiiType.SNILS, digits, PRIO_SNILS_CHECKSUM))
        # ряд цен по тиражам не карта, даже если 16 цифр случайно проходят Luhn
        for span in find_card_spans(text):
            digits = DIGITS_RE.sub("", text[span[0] : span[1]])
            result.append(Detection(span[0], span[1], PiiType.CARD, digits, PRIO_CARD))
        for m in ACCOUNT_RE.finditer(text):
            digits = DIGITS_RE.sub("", m.group())
            # счета (в том числе организаций) маскируются всегда
            result.append(Detection(m.start(), m.end(), PiiType.ACCOUNT, digits, PRIO_ACCOUNT))
        for m in PASSPORT_SEP_RE.finditer(text):
            digits = DIGITS_RE.sub("", m.group())
            result.append(Detection(m.start(), m.end(), PiiType.PASSPORT, digits, PRIO_PASSPORT))
        for m in PASSPORT_LOOSE_RE.finditer(text):
            if _passport_context(text, m.start(), m.end(), PASSPORT_KEYWORD_WINDOW):
                digits = DIGITS_RE.sub("", m.group())
                result.append(
                    Detection(m.start(), m.end(), PiiType.PASSPORT, digits, PRIO_PASSPORT)
                )
        # ИНН группами после слова «ИНН» (правило общее с guard, pii_patterns)
        for m in INN_GROUPED_RE.finditer(text):
            digits = DIGITS_RE.sub("", m.group())
            if (
                len(digits) in INN_GROUPED_LENGTHS
                and checksums.is_valid_inn(digits)
                and has_inn_word_before(text, m.start())
            ):
                result.append(Detection(m.start(), m.end(), PiiType.INN, digits, PRIO_INN))
        for m in PASSPORT_KW_RE.finditer(text):
            if _passport_context(text, m.start(), m.end(), KEYWORD_WINDOW):
                result.append(
                    Detection(m.start(), m.end(), PiiType.PASSPORT, m.group(), PRIO_PASSPORT)
                )
        return result

    def _detect_contacts(self, text: str, norm: str) -> list[Detection]:
        # Ники и ссылки Telegram (R4-SEC-9): ключ по написанию без учёта регистра, как у email
        sources = [(NICK_RE, norm), (TME_RE, text)]
        if self._contacts_re is not None:
            sources.append((self._contacts_re, text))
        found = [
            Detection(m.start(), m.end(), PiiType.CONTACT, m.group().casefold(), PRIO_CONTACT)
            for pattern, source in sources
            for m in pattern.finditer(source)
        ]
        found += [
            Detection(
                m.start("login"), m.end("login"), PiiType.CONTACT,
                m.group("login").casefold(), PRIO_CONTACT,
            )
            for m in SKYPE_RE.finditer(text)
        ]
        return found

    def _detect_addresses(self, text: str) -> list[Detection]:
        """Адрес на уровне дома: улица + номер дома (+ квартира, индекс). Город не трогается."""
        norm = normalize_text(text)
        return [
            Detection(start, end, PiiType.ADDRESS, _address_key(norm[start:end]), PRIO_ADDRESS)
            for start, end in find_address_spans(text)
        ]

    def _detect_orgs(self, text: str) -> list[Detection]:
        return [
            Detection(m.start(), m.end(), PiiType.ORG, " ".join(m.group().casefold().split()),
                      PRIO_ORG)
            for m in ORG_RE.finditer(text)
        ]

    def _detect_known_names(
        self, text: str, known_lemmas: Collection[str], tech: list[tuple[int, int]]
    ) -> list[Detection]:
        """Ловит слова ФИО, уже встречавшиеся в треде, по лемме (страховка от пропусков NER).

        Слово должно быть отдельным токеном: соседство с «_», цифрой или буквой и попадание
        внутрь имени файла/пути отменяют находку, иначе замена режет токен текста по лемме.
        """
        if not known_lemmas:
            return []
        result: list[Detection] = []
        for m in WORD_RE.finditer(text):
            word = m.group()
            if _glued_to_word(text, m.start(), m.end()) or _overlaps(tech, m.start(), m.end()):
                continue
            if len(word) > 1 and lemma(word) in known_lemmas and _known_name_shape(word):
                result.append(
                    Detection(m.start(), m.end(), PiiType.PERSON, person_key(word), PRIO_PERSON)
                )
        return result

    def _detect_repeated_names(
        self,
        text: str,
        found: list[Detection],
        known_lemmas: Collection[str],
        tech: list[tuple[int, int]],
    ) -> list[Detection]:
        """Повторы слов ФИО, уже найденных в этом тексте (по лемме, как слова известные в треде)."""
        lemmas = {
            lemma(word)
            for det in found
            if det.pii_type is PiiType.PERSON and not det.exact
            for word in WORD_RE.findall(text[det.start:det.end])
            if _name_like_word(word)
        } - set(known_lemmas)
        return self._detect_known_names(text, lemmas, tech) if lemmas else []

    def _detect_mixed_case_persons(
        self, text: str, tech: list[tuple[int, int]]
    ) -> list[Detection]:
        """ФИО, где часть слов с заглавной, а часть строчными («петров Пётр», «Иван иванов»).

        Группа подряд идущих (через пробелы) кириллических слов, у каждого из которых главный
        разбор pymorphy - одушевлённая фамилия/имя/отчество, и где есть и заглавное, и
        строчное слово. Полнота та же, что у ФИО одного регистра: «фамилия + имя/отчество»
        или «имя + отчество». Группы одного регистра ловит `_detect_case_shifted_persons`
        (все строчные) и NER (все с заглавной), здесь только смесь.
        """
        result: list[Detection] = []
        group: list[tuple[int, int, str]] = []  # (начало, конец, грамема)

        def flush() -> None:
            """Группа со смесью регистров и полным набором частей ФИО становится находкой."""
            if len(group) > 1:
                words = [text[a:b] for a, b, _ in group]
                grams = {g for _, _, g in group}
                mixed = any(w[0].isupper() for w in words) and any(w[0].islower() for w in words)
                full = ("Surn" in grams and grams & {"Name", "Patr"}) or (
                    "Name" in grams and "Patr" in grams
                )
                if mixed and full and all(w.isalpha() or "-" in w for w in words):
                    start, end = group[0][0], group[-1][1]
                    result.append(
                        Detection(start, end, PiiType.PERSON, person_key(text[start:end]),
                                  PRIO_PERSON)
                    )
            group.clear()

        for m in CYRILLIC_WORD_RE.finditer(text):
            word = m.group()
            grams = name_gramme(word) if len(word) >= MIN_MIXED_NAME_LEN else None
            extends = bool(group) and CAPS_GAP_RE.fullmatch(text[group[-1][1]:m.start()])
            if not extends:
                flush()
            if (
                grams is None
                or _case_kind(word) == "upper"
                or _glued_to_word(text, m.start(), m.end())
                or _overlaps(tech, m.start(), m.end())
            ):
                flush()
                continue
            group.append((m.start(), m.end(), grams))
        flush()
        return result

    def _detect_tech_names(
        self, text: str, tech: list[tuple[int, int]], known_lemmas: Collection[str]
    ) -> list[Detection]:
        """ФИО внутри имён файлов и путей: каждая кириллическая часть проверяется отдельно.

        Разделители («_», «-», «.», «/», «\\») и остальные части не затрагиваются: заменяется
        только само слово, поэтому оригинал токена совпадает с заменённым фрагментом.
        """
        result: list[Detection] = []
        for t_start, t_end in tech:
            for m in CYRILLIC_WORD_RE.finditer(text, t_start, t_end):
                word = m.group()
                if is_inanimate_common_noun(word):
                    continue
                if is_person_word(word) or lemma(word) in known_lemmas and len(word) > 1:
                    result.append(
                        Detection(m.start(), m.end(), PiiType.PERSON, person_key(word),
                                  PRIO_PERSON, exact=True)
                    )
        return result

    def _detect_case_shifted_persons(
        self, text: str, tech: list[tuple[int, int]]
    ) -> list[Detection]:
        """ФИО целиком заглавными или строчными («ИВАНОВ ИВАН ИВАНОВИЧ», «иванов и.и.»).

        Берутся подряд идущие (через пробелы) слова одного регистра, у каждого из которых
        главный разбор pymorphy — одушевлённая фамилия/имя/отчество. Находка засчитывается
        только при сочетании «фамилия + имя/отчество/инициалы» или «имя + отчество»:
        одиночное слово и пары вроде «РОМАШКА ТРЕЙД» не маскируются.
        """
        result: list[Detection] = []
        group: list[tuple[int, int, str]] = []  # (начало, конец, грамема)
        for m in CAPS_WORD_RE.finditer(text):
            kind = _case_kind(m.group())
            grams = _caps_gramme(m.group()) if kind else None
            skip = (
                grams is None
                or _glued_to_word(text, m.start(), m.end())
                or _overlaps(tech, m.start(), m.end())
            )
            if skip or (group and not _can_extend(text, group, m, kind)):
                result += self._flush_caps_group(text, group)
                group = []
                if skip:
                    continue
            group.append((m.start(), m.end(), grams))
        result += self._flush_caps_group(text, group)
        return result

    def _detect_initialed_surnames(
        self, text: str, tech: list[tuple[int, int]]
    ) -> list[Detection]:
        """«Петрова О.И.» и «О.И. Петрова» по морфологии — страховка от пропусков NER.

        Инициалы, уже взятые фамилией слева («Петров А.Б. Сидоров»), не склеивают его со
        следующей фамилией: та маскируется отдельно, иначе два человека стали бы одним токеном.
        """
        result: list[Detection] = []
        taken: set[int] = set()  # начала инициалов, уже отданных фамилии слева
        for m in SURNAME_INITIALS_RE.finditer(text):
            if _overlaps(tech, m.start(), m.end()) or not _initialed_surname(m.group(1)):
                continue
            taken.add(m.start(2))
            result.append(self._initialed_person(text, m.start(), m.end()))
        for m in INITIALS_SURNAME_RE.finditer(text):
            if _overlaps(tech, m.start(), m.end()) or not _initialed_surname(m.group(2)):
                continue
            start = m.start(2) if m.start(1) in taken else m.start()
            result.append(self._initialed_person(text, start, m.end()))
        for m in CAPS_SURNAME_INITIALS_RE.finditer(text):
            if _overlaps(tech, m.start(), m.end()) or _is_caps_stop(m.group(1)):
                continue
            if _initialed_surname(m.group(1)):
                result.append(self._initialed_person(text, m.start(), m.end()))
        for regex, group in ((SURNAME_ONE_INITIAL_RE, 1), (ONE_INITIAL_SURNAME_RE, 2)):
            for m in regex.finditer(text):
                if _overlaps(tech, m.start(), m.end()) or not _initialed_surname(
                    m.group(group)
                ):
                    continue
                result.append(self._initialed_person(text, m.start(), m.end()))
        return result

    @staticmethod
    def _detect_name_patronymic(text: str, tech: list[tuple[int, int]]) -> list[Detection]:
        """ФИО по якорю «имя + отчество» без NER (см. `labops_pii.patronymic`).

        NER пропускал полное ФИО в обычных фразах («Позвоните Иванов Сергей Петрович
        завтра.») и не брал в находку фамилию вне словаря, через дефис или капсом.
        """
        return [
            Detection(start, end, PiiType.PERSON, person_key(text[start:end]), PRIO_PERSON)
            for start, end in _patronymic_and_pair_spans(text)
            if not _overlaps(tech, start, end) and not _glued_to_word(text, start, end)
        ]

    @staticmethod
    def _initialed_person(text: str, start: int, end: int) -> Detection:
        """Находка ФИО на фрагмент «фамилия + инициалы».

        Последняя точка инициалов остаётся снаружи, как в находках NER: она же бывает точкой
        предложения, а границы находки одного человека не должны зависеть от детектора.
        """
        if text[end - 1] == ".":
            end -= 1
        return Detection(start, end, PiiType.PERSON, person_key(text[start:end]), PRIO_PERSON)

    def _flush_caps_group(
        self, text: str, group: list[tuple[int, int, str]]
    ) -> list[Detection]:
        """Превращает набранную группу слов одного регистра в находку, если это ФИО."""
        if not group:
            return []
        start, end = group[0][0], group[-1][1]
        grams = {g for _, _, g in group}
        tail = CAPS_INITIALS_RE.match(text, end) if "Surn" in grams else None
        if tail and _case_kind(text[end - 1]) == _case_kind(tail.group().lstrip()[0]):
            end = tail.end()
            while end > start and text[end - 1] in " \t":
                end -= 1
        head = None
        if "Surn" in grams:
            window_start = max(0, start - HEAD_WINDOW)
            head = CAPS_HEAD_RE.search(text[window_start:start])
        if head:
            start = window_start + head.start()
        has_initials = tail is not None or head is not None
        # «ИП ПЕТРОВ»: одиночное слово после «ИП» — ФИО, даже без имени и инициалов
        after_ip = bool(IP_HEAD_RE.search(text[max(0, start - HEAD_WINDOW):start]))
        if after_ip and len(group) == 1 and not _is_caps_stop(text[start:end]):
            return [Detection(start, end, PiiType.PERSON, person_key(text[start:end]), PRIO_PERSON)]
        is_full = (
            ("Surn" in grams and (len(group) > 1 or has_initials) and (
                grams & {"Name", "Patr"} or has_initials))
            or ("Name" in grams and "Patr" in grams)
        )
        if len(group) == 1 and not has_initials or not is_full:
            return []
        chunk = text[start:end]
        return [Detection(start, end, PiiType.PERSON, person_key(chunk), PRIO_PERSON)]

    # --- NER ------------------------------------------------------------------

    def _detect_persons(self, folded: str, tech: list[tuple[int, int]]) -> list[Detection]:
        """ФИО через Natasha NER (Slovnet), с захватом соседних инициалов.

        Работает по свёрнутой копии (`fold_for_names`): без невидимых знаков, меток направления
        письма и латинских гомоглифов. Длина копии равна исходной, поэтому позиции находок
        указывают на оригинал, а псевдонимизатор заменяет исходный фрагмент (round-trip побайтный).
        """
        doc = Doc(folded)
        doc.segment(self._segmenter)
        doc.tag_ner(self._ner)
        result: list[Detection] = []
        for span in doc.spans:
            if span.type != "PER":
                continue
            for piece_start, piece_end in _subtract(span.start, span.stop, tech):
                # Находка NER через несколько строк (список людей) - по ФИО на строку
                lines = _split_name_lines(folded, piece_start, piece_end)
                for k, (line_start, line_end) in enumerate(lines):
                    # Отделённая строка - находка, только если в ней есть словарное имя или
                    # фамилия: «Буллеты:» под ФИО спикера - заголовок, а не второй человек
                    if k and not _line_has_name_word(folded, line_start, line_end):
                        continue
                    found = self._person_from_piece(folded, line_start, line_end, tech)
                    if found is not None:
                        result.append(found)
        return result

    def _person_from_piece(
        self, text: str, start: int, end: int, tech: list[tuple[int, int]]
    ) -> Detection | None:
        """Уточняет границы одного фрагмента NER и превращает его в находку (или отбрасывает)."""
        tail = INITIAL_TAIL_RE.match(text, end)
        if tail:
            end = tail.end()
        # Окно вместо text[:start]: копия всего префикса на каждую находку давала O(n^2)
        window_start = max(0, start - HEAD_WINDOW)
        head = INITIAL_HEAD_RE.search(text[window_start:start])
        if head:
            start = window_start + head.start()
        while start < end and text[start] in TRIM_CHARS:
            start += 1
        while end > start and text[end - 1] in " \t\n\r,;:!?()" + QUOTE_CHARS:
            end -= 1
        start, end = _trim_non_name_words(text, start, end)
        end = _cut_foreign_next_lines(text, start, end)
        start = _with_surname_before(text, start, end)
        chunk = text[start:end]
        if end <= start or not CYRILLIC_RE.search(chunk):
            return None
        if _overlaps(tech, start, end) or _glued_to_word(text, start, end):
            return None  # захват вылез на имя файла/слово через «_»
        words = WORD_RE.findall(chunk)
        if _typo_after_modifier(text, start, words):
            return None  # «разбираем вашу Садачу»: опечатка расшифровки голоса, не фамилия
        if words and all(is_inanimate_common_noun(w) for w in words):
            return None  # «Металлопрокат», «Сибирь» — названия, не ФИО
        if words and all(w.upper() in CAPS_IP_STOPWORDS for w in words):
            # Подпись поля, а не ФИО: в маскированном «Подписант: [PERSON_1]» NER принимал
            # «Подписант» за имя, и вторая проверка отклоняла сообщение (28.10.2026).
            return None
        return Detection(start, end, PiiType.PERSON, person_key(chunk), PRIO_PERSON)


# ФИО, кончающееся инициалом: «Петров А.Б», «Kuznetsov A» (точка после него - часть ФИО)
_INITIAL_END_RE = re.compile(r"(?:^|[\s.])[А-ЯЁA-Z]\Z")


def _with_initial_dot(det: Detection, text: str) -> Detection:
    """Точка после последнего инициала входит в находку ФИО, кто бы её ни нашёл.

    NER и капс брали точку в находку («Петров А.Б.»), шаблон инициалов - нет («Петров
    А.Б»). Ключ у обоих один, токен общий, а оригинал - первого упоминания: restore второго
    терял или добавлял точку («Петров А.Б в отпуске.»). Граница теперь одна для всех.
    """
    if det.pii_type is not PiiType.PERSON or det.exact:
        return det
    if det.end >= len(text) or text[det.end] != ".":
        return det
    if not _INITIAL_END_RE.search(text, det.start, det.end):
        return det
    return replace(det, end=det.end + 1)


def _patronymic_and_pair_spans(text: str) -> list[tuple[int, int]]:
    """ФИО с отчеством и пары «фамилия + имя», не задевающие ни одного ФИО с отчеством.

    Пара на стыке двух ФИО («…Сергеевна Иванова Ольга Петровна…» -> «Иванова Ольга») иначе
    связала бы двух людей в одну находку.
    """
    with_patronymic = find_name_patronymic_spans(text)
    pairs = [
        (start, end) for start, end in find_surname_name_spans(text)
        if not any(start < p_end and p_start < end for p_start, p_end in with_patronymic)
    ]
    return with_patronymic + pairs


def _atom_clusters(atoms: list[Detection], start: int, end: int) -> list[tuple[int, int]]:
    """Диапазоны людей внутри [start, end): пересекающиеся «атомы» ФИО сливаются в одного."""
    clusters: list[tuple[int, int]] = []
    inside = sorted((a.start, a.end) for a in atoms if start <= a.start and a.end <= end)
    for a_start, a_end in inside:
        if clusters and a_start < clusters[-1][1]:
            clusters[-1] = (clusters[-1][0], max(clusters[-1][1], a_end))
        else:
            clusters.append((a_start, a_end))
    return clusters


def _covers_only_people(text: str, start: int, end: int, clusters: list[tuple[int, int]]) -> bool:
    """Каждое слово фрагмента лежит внутри одного из людей (между ними - только знаки)."""
    return all(
        any(c_start <= w.start() and w.end() <= c_end for c_start, c_end in clusters)
        for w in WORD_RE.finditer(text, start, end)
    )


def _drop_multi_person_spans(
    found: list[Detection], atoms: list[Detection], text: str
) -> list[Detection]:
    """Убирает находки ФИО, которые целиком состоят из двух и более людей-«атомов».

    Атомы - находки детерминированных шаблонов (фамилия с инициалами, «имя + отчество», пара
    «фамилия + имя»), каждая про одного человека. Широкая находка NER или другого детектора
    поверх нескольких атомов без лишних слов - это перечисление людей: она удаляется, атомы
    остаются и маскируются по отдельности. Находка с любым словом вне атомов не трогается.
    """
    if len(atoms) < 2:
        return found
    result: list[Detection] = []
    for det in found:
        if det.pii_type is PiiType.PERSON and not det.exact:
            clusters = _atom_clusters(atoms, det.start, det.end)
            if len(clusters) > 1 and _covers_only_people(text, det.start, det.end, clusters):
                continue
        result.append(det)
    return result


def _initialed_surname(word: str) -> bool:
    """Слово рядом с инициалами - фамилия: по словарю или по признакам рядом с отчеством.

    `is_surname_candidate` не узнаёт словарные нарицательные и прилагательные-фамилии
    («Д.И. Головач», «Белых И.П.»), и фамилия уходила в модель; роли и должности («И.О.
    Директора») отсекает `is_surname_near_patronymic`.
    """
    return is_surname_candidate(word) or is_surname_near_patronymic(word)


def _caps_gramme(word: str) -> str | None:
    """Грамема слова капсом/строчными; фамилия через дефис («САЛТЫКОВ-ЩЕДРИН») - «Surn»."""
    if "-" in word and is_dictionary_surname(word):
        return "Surn"
    return name_gramme(word)


def _name_like_word(word: str) -> bool:
    """Слово из находки ФИО, чьи повторы в тексте тоже ФИО: с заглавной, не капсом, имя/фамилия.

    «ИП», «ИНН», должности и слова-шум, захваченные в находку вместе с ФИО, сюда не попадают:
    иначе их повторы по тексту стали бы «ФИО». Слово с дефисом («Петрова-Водкина») годится,
    если так же устроена каждая часть: «Fullstack-разработчик» и «инженер-программист»
    не словарные, и без этой проверки профессия, принятая NER за ФИО, закрывалась бы везде.
    """
    return (
        len(word) >= MIN_MIXED_NAME_LEN - 1
        and word[0].isupper()
        and not word.isupper()
        and all(
            CYRILLIC_WORD_RE.fullmatch(part)
            and (name_gramme(part) is not None or is_surname_candidate(part))
            for part in word.split("-")
        )
    )


def _known_name_shape(word: str) -> bool:
    """Годится ли слово, чья лемма уже известна в треде, для маски по лемме.

    С заглавной буквы - любое слово. Строчное («найди сидоров») - только если главный разбор
    pymorphy одушевлённая фамилия/имя/отчество: «надежда», «вера», «любовь», как и любое
    словарное слово, остаются текстом, даже когда в треде есть человек с таким именем.
    """
    if word[0].isupper():
        return True
    return word.isalpha() and word.isascii() is False and is_person_word(word)


def _with_surname_before(text: str, start: int, end: int) -> int:
    """Начало ФИО с фамилией слева, если NER взял только «Имя Отчество».

    Расширяет, только когда находка начинается с имени, а слово перед ней - с заглавной,
    с разбором «фамилия» и не подпись поля («Директор», «Подписант»).
    """
    words = WORD_RE.findall(text[start:end])
    if not words or name_gramme(words[0]) != "Name":
        return start
    window_start = max(0, start - HEAD_WINDOW)
    before = SURNAME_BEFORE_RE.search(text[window_start:start])
    if before is None:
        return start
    surname = before.group(1)
    if surname.upper() in CAPS_IP_STOPWORDS:
        return start
    # Главный разбор - фамилия: «Привет», «Сказка» (приветствие, название) не берутся.
    if not all(name_gramme(part) == "Surn" for part in surname.split("-")):
        return start
    return window_start + before.start(1)


CAPS_HEAD_RE = re.compile(r"(?:[А-ЯЁ]\.[ \t]?(?:[А-ЯЁ]\.)?|[а-яё]\.[ \t]?(?:[а-яё]\.)?)[ \t]*$")


def _is_caps_stop(word: str) -> bool:
    """Слово капсом (возможно, через дефис), которое не бывает частью ФИО."""
    return any(
        part in CAPS_IP_STOPWORDS or is_inanimate_common_noun(part) or is_non_name_word(part)
        for part in word.split("-")
    )


def _caps_ip_end(m: re.Match[str]) -> int | None:
    """Конец находки «ИП + ФИО капсом» или None, если это не ФИО.

    Первое слово не должно быть служебным или словарным существительным; следующие слова
    обрезаются перед первым таким словом (хвост ИНН/ОГРНИП тогда не берётся).
    """
    if _is_caps_stop(m.group("first")):
        return None
    rest = m.group("rest")
    for word in CAPS_WORD_IN_REST_RE.finditer(rest):
        if _is_caps_stop(word.group(1)):
            return m.start("rest") + word.start()
    return m.end()


def _case_kind(word: str) -> str:
    """Регистр слова: «upper», «lower» или пустая строка (смешанный/не кириллица)."""
    if word.isupper():
        return "upper"
    if word.islower():
        return "lower"
    return ""


def _can_extend(
    text: str, group: list[tuple[int, int, str]], m: re.Match[str], kind: str
) -> bool:
    """Продолжает ли слово m группу: только пробелы между словами и тот же регистр."""
    last_end = group[-1][1]
    gap = text[last_end:m.start()]
    return bool(CAPS_GAP_RE.fullmatch(gap)) and _case_kind(text[group[0][0]:group[0][1]]) == kind


def _first_candidate(ranges: list[tuple[int, int]], start: int) -> int:
    """Индекс первого диапазона, который может задеть точку start или лежит правее неё.

    Диапазоны отсортированы и не пересекаются (контракт find_tech_spans), поэтому концы
    тоже возрастают: из двух соседей точки start только левый может её накрывать.
    """
    index = bisect.bisect_left(ranges, (start,))
    if index > 0 and ranges[index - 1][1] > start:
        index -= 1
    return index


def _overlaps(ranges: list[tuple[int, int]], start: int, end: int) -> bool:
    """Пересекается ли [start, end) с любым из диапазонов.

    Args:
        ranges: Отсортированные непересекающиеся диапазоны (технические токены).
        start: Начало фрагмента.
        end: Конец фрагмента (не включительно).

    Returns:
        True, если есть общий символ. Поиск бинарный: O(log n) вместо прохода по всем.
    """
    index = _first_candidate(ranges, start)
    return index < len(ranges) and ranges[index][0] < end and ranges[index][1] > start


def _subtract(start: int, end: int, ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Вычитает диапазоны из [start, end); возвращает оставшиеся непустые куски по порядку.

    Args:
        start: Начало исходного фрагмента.
        end: Конец фрагмента (не включительно).
        ranges: Отсортированные непересекающиеся диапазоны (повторно не сортируются).
    """
    pieces: list[tuple[int, int]] = []
    cursor = start
    for index in range(_first_candidate(ranges, start), len(ranges)):
        r_start, r_end = ranges[index]
        if r_start >= end:
            break  # диапазоны отсортированы: правее только более далёкие
        if r_end <= cursor:
            continue
        if r_start > cursor:
            pieces.append((cursor, r_start))
        cursor = max(cursor, r_end)
    if cursor < end:
        pieces.append((cursor, end))
    return pieces


def _glued_to_word(text: str, start: int, end: int) -> bool:
    """Склеен ли фрагмент с соседним словом (буква, цифра или «_» вплотную с краем)."""
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    return (before.isalnum() or before == "_") and text[start].isalnum() or (
        (after.isalnum() or after == "_") and text[end - 1].isalnum()
    )


def _cut_foreign_next_lines(text: str, start: int, end: int) -> int:
    """Конец ФИО без строк, которые NER прихватил после перевода строки.

    «Резюме: Игорь Валентинович Крутоголов\nОпыт: 5 лет»: NER берёт «Опыт» в находку, и слово
    следующей строки уходило под токен ФИО. Строка после перевода остаётся в находке, только
    если начинается словом ФИО (перенос внутри имени: «Иванов Иван\nИванович»).
    """
    cut = text.find("\n", start, end)
    while 0 <= cut:
        word = WORD_RE.search(text, cut, end)
        if word is None or not _continues_name(text, start, cut, word):
            end = cut
            while end > start and text[end - 1] in TRIM_CHARS:
                end -= 1
            return end
        cut = text.find("\n", cut + 1, end)
    return end


MODIFIER_WINDOW = 40  # хватает на одно слово-определение с пробелами


def _typo_after_modifier(text: str, start: int, words: list[str]) -> bool:
    """Одно незнакомое слово с согласованным определением перед ним - опечатка, не ФИО.

    «Разбираем вашу Садачу вживую» (голосовое, 25.11.2026): расшифровка написала «Садачу»
    с заглавной вместо «задачу», NER отдал слово как фамилию. Признак опечатки (созвучная
    замена буквы до словарного неодушевлённого существительного) сам по себе раскрывал бы
    редкие фамилии («Кадар», «Танака»), поэтому нужно и согласованное определение прямо перед
    словом: «вашу/эту/новую задачу». Определение берётся из грамматики, а не из списка слов,
    так что правило работает для любых таких фраз.
    """
    if len(words) != 1:
        return False
    nouns = typo_noun_parses(words[0])
    if not nouns:
        return False
    before = list(WORD_RE.finditer(text, max(0, start - MODIFIER_WINDOW), start))
    if not before or text[before[-1].end():start].strip():
        return False  # перед словом знак препинания или ничего: определения нет
    return agrees_as_modifier(before[-1].group(), nouns)


def _split_name_lines(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Делит находку NER по переводам строк, где следующая строка - уже другое ФИО.

    Natasha отдаёт «Иванов Иван\nПетров Пётр» одним фрагментом. Раньше хвост после перевода
    просто отрезался (_cut_foreign_next_lines), и второй человек оставался немаскированным;
    теперь каждая строка - свой фрагмент и своя находка. Строка начинается с первого слова:
    номер, маркер списка или «|» перед ним в находку не входят.
    """
    pieces: list[tuple[int, int]] = []
    piece_start = start
    cut = text.find("\n", start, end)
    while 0 <= cut:
        word = WORD_RE.search(text, cut, end)
        if word is None:
            break
        if not _continues_name(text, piece_start, cut, word):
            pieces.append((piece_start, cut))
            piece_start = word.start()
        cut = text.find("\n", cut + 1, end)
    pieces.append((piece_start, end))
    return pieces


def _line_has_name_word(text: str, start: int, end: int) -> bool:
    """Во фрагменте строки есть слово со словарным разбором имя/фамилия/отчество."""
    return any(name_gramme(w) is not None for w in WORD_RE.findall(text, start, end))


def _continues_name(text: str, start: int, cut: int, word: re.Match[str]) -> bool:
    """Слово после перевода строки продолжает ФИО, а не начинает следующую строку.

    Перенос внутри одного ФИО редок: отчество на следующей строке («Белоусова Анна\nСергеевна»)
    или имя и фамилия, разорванные переносом («Анна\nБелоусова»). Всё остальное - новая строка,
    и склейка давала один токен на несколько строк:
    - «Имя: Диана Арепьева\nБуллеты:» (шаблон слайда, 25.11.2026): заголовок строки уходил под
      токен ФИО, модель не видела имени спикера и сочиняла фамилию, в слайд попадало «Буллеты»;
    - список людей по строке на каждого («Иванов Иван\nПетров Пётр», вывод `uniq -c`
      «      2 Петров») становился одним токеном: модель не могла назвать никого по отдельности,
      а при восстановлении в ответ шёл кусок списка с числами и отступами (25.11.2026).
    Поэтому строка продолжает ФИО, только если она начинается прямо со слова (без цифр, маркеров
    списка, «|»), слово - не заголовок с двоеточием, и вместе с предыдущим это одно ФИО:
    после двух и более слов - только отчество; после одного слова - пара «имя + фамилия».
    """
    if text[cut:word.start()].strip():
        return False  # «      2 Петров», «– Петров», «| Петров»: новая строка списка или таблицы
    if text[word.end():word.end() + 2].lstrip(" \t").startswith(":"):
        return False
    gramme = name_gramme(word.group())
    if gramme == "Patr":
        return True
    words_before = WORD_RE.findall(text, start, cut)
    if len(words_before) != 1:
        return False  # перед переводом уже полное ФИО: следующая строка - другой человек
    before = name_gramme(words_before[0])
    surname_like = gramme == "Surn" or (gramme is None and is_surname_candidate(word.group()))
    return (before == "Name" and surname_like) or (
        gramme == "Name" and (before == "Surn" or is_surname_candidate(words_before[0]))
    )


def _trim_non_name_words(text: str, start: int, end: int) -> tuple[int, int]:
    """Отрезает с краёв фрагмента слова, которые не бывают частью ФИО (глаголы и т.п.)."""
    words = list(WORD_RE.finditer(text, start, end))
    while words and is_non_name_word(words[0].group()):
        start = words.pop(0).end()
        while start < end and text[start] in TRIM_CHARS:
            start += 1
    while words and is_non_name_word(words[-1].group()):
        end = words.pop().start()
        while end > start and text[end - 1] in TRIM_CHARS:
            end -= 1
    return start, end


def _address_key(fragment: str) -> str:
    """Ключ адреса: название улицы в начальной форме, затем дом, корпус, квартира, индекс.

    Не зависит от сокращения, падежа ключевого слова, пометок «д.»/«дом» и порядка слов,
    поэтому «ул. Ленина, д. 5, кв. 12» и «на улице Ленина, дом 5, кв. 12» - один адрес.
    Название приводится к лемме по частям через дефис: «Тверской» и «Тверская» совпадут.

    Args:
        fragment: Фрагмент адреса из нормализованного текста.
    """
    names: list[str] = []
    numbers: list[str] = []
    street_type = ""
    pending: str | None = None  # метка квартиры/корпуса, ждущая номер
    for token in ADDRESS_TOKEN_RE.findall(fragment):
        low = token.casefold()
        if low[0].isdigit():
            numbers.append(f"{pending or ''}{low}")
            pending = None
        elif low in ADDRESS_SUFFIX_CODES:
            pending = ADDRESS_SUFFIX_CODES[low]
        elif low in ADDRESS_STREET_TYPE_CODES:
            street_type = f"{ADDRESS_STREET_TYPE_PREFIX}{ADDRESS_STREET_TYPE_CODES[low]}"
        elif low not in ADDRESS_NOISE_WORDS:
            names.append("-".join(common_lemma(part) for part in low.split("-")))
    return " ".join([*([street_type] if street_type else []), *names, *numbers])


def _after_preposition(text: str, start: int) -> bool:
    """Говорит, что непосредственно перед позицией (через пробелы) стоит предлог."""
    # Поиск по всему тексту с границами: проверка левой границы слова видит символы
    # за началом окна, поэтому обрезанное окном длинное слово за предлог не сойдёт.
    m = PREPOSITION_BEFORE_RE.search(text, max(0, start - PREPOSITION_WINDOW), start)
    return m is not None and m.group(1).lower() in PREPOSITIONS


def follows_preposition(text: str, start: int) -> bool:
    """Стоит ли непосредственно перед позицией предлог (публичная обёртка для restore)."""
    return _after_preposition(text, start)


def _with_preposition_genders(text: str, found: list[Detection]) -> list[Detection]:
    """Уточняет род в ключах ФИО, перед которыми стоит предлог (R9-A4-07).

    Фрагменты имён файлов (exact) не трогаются: у них нет предложного контекста.
    """
    result: list[Detection] = []
    for det in found:
        if det.pii_type is PiiType.PERSON and not det.exact and _after_preposition(
            text, det.start
        ):
            key = with_preposition_gender(det.key, text[det.start:det.end])
            if key != det.key:
                det = replace(det, key=key)
        elif det.pii_type is PiiType.PERSON and not det.exact and _is_feminine_subject(
            text, det.start, det.end
        ):
            det = replace(det, key=with_female_subject(det.key))
        result.append(det)
    return result


def _is_feminine_subject(text: str, start: int, end: int) -> bool:
    """ФИО начинает фразу, и за ним глагол женского рода («подписала») или «она»."""
    prefix = text[:start].rstrip(" \t")
    if prefix and prefix[-1] not in PHRASE_START_CHARS:
        return False
    after = FEMININE_SUBJECT_AFTER_RE.match(text, end)
    if after is None:
        return False
    word = after.group(1)
    return word == "она" or word not in NOT_FEMININE_VERBS


def _priority_order(det: Detection) -> tuple[int, int, int]:
    """Порядок выбора при пересечениях: сначала важнее, потом длиннее, потом левее."""
    return det.priority, -(det.end - det.start), det.start


# Типы, объединение которых - одно ФИО или контакт (обычный, не точный токен)
_NAME_TYPES = frozenset({PiiType.PERSON, PiiType.CONTACT})


def _resolve_overlaps(found: list[Detection], text: str) -> list[Detection]:
    """Сводит пересекающиеся находки к непересекающимся, не оставляя ПДн открытыми.

    Находки с общим символом собираются в группу; смежные (без общего символа) не
    склеиваются. Если важнейшая находка группы покрывает её целиком, остаётся она одна, как
    раньше. Иначе маскируется объединение диапазонов (R9-A4-03): раньше менее важная находка
    отбрасывалась целиком, и при словаре «Петров» от «Петров Иван Сергеевич» в модель
    уходило «[CONTACT] Иван Сергеевич». Один проход по отсортированным находкам, O(n log n).

    Args:
        found: Находки всех детекторов (могут пересекаться).
        text: Исходный текст: по нему строится ключ объединённой находки.

    Returns:
        Непересекающиеся находки, отсортированные по позиции.
    """
    result: list[Detection] = []
    group: list[Detection] = []
    group_end = 0
    for det in sorted(found, key=lambda d: (d.start, -d.end)):
        if group and det.start >= group_end:
            result.append(_merge_group(group, text))
            group = []
        group_end = max(group_end, det.end) if group else det.end
        group.append(det)
    if group:
        result.append(_merge_group(group, text))
    return result


def _merge_group(group: list[Detection], text: str) -> Detection:
    """Одна находка вместо группы пересекающихся: важнейшая или объединение диапазонов.

    Тип и ключ объединения выбраны так, чтобы /restore вернул ровно исходный фрагмент, а
    один и тот же человек получал в треде один токен:
      - только ФИО и контакты, среди них есть ФИО: это ФИО целиком, тип PERSON и обычный
        ключ ФИО по всему фрагменту. Токен тот же, что без словаря контактов (тогда NER
        находит то же ФИО целиком), работает сопоставление форм ФИО в треде;
      - только контакты: CONTACT, ключ - фрагмент без учёта регистра (как у контакта);
      - любая другая смесь (контакт задел телефон или адрес и т.п.): тип важнейшей находки и
        точный токен (exact): общий токен только у одинакового написания, поэтому нечёткое
        сопоставление ФИО не подменит этот фрагмент при /restore другим.

    Args:
        group: Пересекающиеся находки (не пустой список).
        text: Исходный текст.

    Returns:
        Находка на весь диапазон группы.
    """
    best = min(group, key=_priority_order)
    start = min(d.start for d in group)
    end = max(d.end for d in group)
    if best.start == start and best.end == end:
        return best
    fragment = text[start:end]
    types = {d.pii_type for d in group}
    if types <= _NAME_TYPES and PiiType.PERSON in types:
        key = person_key(IP_NOISE_RE.sub("", fragment))
        exact = any(d.exact for d in group)
        return Detection(start, end, PiiType.PERSON, key, best.priority, exact)
    if types == {PiiType.CONTACT}:
        return Detection(start, end, PiiType.CONTACT, fragment.casefold(), best.priority)
    if best.pii_type is PiiType.PERSON:
        key = person_key(IP_NOISE_RE.sub("", fragment))
    else:
        key = " ".join(fragment.casefold().split())
    return Detection(start, end, best.pii_type, key, best.priority, exact=True)
