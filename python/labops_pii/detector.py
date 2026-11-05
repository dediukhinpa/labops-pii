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
from labops_pii.morph import (
    WORD_RE,
    common_lemma,
    is_inanimate_common_noun,
    is_non_name_word,
    is_person_word,
    is_surname_candidate,
    lemma,
    name_gramme,
    person_key,
    request_cache,
    with_preposition_gender,
)
from labops_pii.pii_patterns import (
    ACCOUNT_RE,
    BARE_PHONE_RE,
    NICK_RE,
    PHONE_RE,
    SNILS_KEYWORD_WINDOW,
    SNILS_RE,
    TME_RE,
    find_address_spans,
    find_card_spans,
    find_snils_spans,
    normalize_text,
)
from labops_pii.profiles import get_profile
from labops_pii.tech_tokens import find_tech_spans

logger = logging.getLogger(__name__)

INITIAL_TAIL_RE = re.compile(r"[ \t]*[А-ЯЁ]\.[ \t]?(?:[А-ЯЁ]\.)?")
INITIAL_HEAD_RE = re.compile(r"[А-ЯЁ]\.[ \t]?(?:[А-ЯЁ]\.)?[ \t]*$")
TRIM_CHARS = " \t\n\r,.;:!?()«»\"'"
HEAD_WINDOW = 64  # окно слева от ФИО для поиска инициалов
# Слово-фамилия вплотную слева от «Имя Отчество» (в той же строке): NER его теряет, когда
# перед ним должность («директор Дудорова Марина Евгеньевна» - «Дудорова» читается как
# родительный падеж «директора Дудорова»), и фамилия уходила наружу открытым текстом.
SURNAME_BEFORE_RE = re.compile(r"([А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?)[ \t]+$")
KEYWORD_WINDOW = 16  # сколько символов слева от числа смотрим на ключевое слово
PHONE_DIGITS_WITH_PREFIX = 11
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
INITIALED_WORD = r"[А-ЯЁ][а-яё]{2,}(?:-[А-ЯЁ][а-яё]{2,})?"
TWO_INITIALS = r"[А-ЯЁ]\.[ \t]?[А-ЯЁ]\."
SURNAME_INITIALS_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z0-9_.-])({INITIALED_WORD})[ \t]+({TWO_INITIALS})(?![А-Яа-яЁё])"
)
INITIALS_SURNAME_RE = re.compile(
    rf"(?<![А-Яа-яЁёA-Za-z0-9_.-])({TWO_INITIALS})[ \t]?({INITIALED_WORD})"
    r"(?![А-Яа-яЁёA-Za-z0-9_-])"
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
PASSPORT_SEP_RE = re.compile(
    r"(?<![\d.,])\d{2}[ \t]?\d{2}"
    r"(?:[ \t]+(?:№|N|номер)?[ \t]*|[ \t]*(?:№|N|номер)[ \t]*)\d{6}(?!\d)"
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
    r"(?P<name>[A-Z][a-z]{1,19}(?:[ \t]+[A-Z][a-z]{1,19}){1,2})(?![A-Za-z])"
)
LATIN_NAME_WORD_RE = re.compile(r"[A-Z][a-z]+")
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
ADDRESS_NOISE_WORDS = frozenset({
    "улица", "улице", "улицу", "улицы", "ул", "проспект", "проспекта", "проспекте", "проспекту",
    "просп", "пр", "пр-т", "пр-кт", "переулок", "переулка", "переулке", "переулку", "пер",
    "бульвар", "бульвара", "бульваре", "бульвару", "б-р", "бул", "набережная", "набережной",
    "набережную", "наб", "шоссе", "ш", "площадь", "площади", "пл", "проезд", "проезда",
    "проезде", "проезду", "пр-д", "тупик", "тупика", "тупике", "тупику", "аллея", "аллеи",
    "аллее", "аллею", "д", "дом", "влд", "владение", "по", "на",
})
# Квартира, корпус и т.п. в ключе записываются одной буквенной меткой перед номером
ADDRESS_SUFFIX_CODES = {
    "корп": "к", "корпус": "к", "к": "к", "стр": "с", "строение": "с", "с": "с",
    "лит": "л", "литера": "л", "кв": "кв", "квартира": "кв", "оф": "оф", "офис": "оф",
    "пом": "пом", "помещение": "пом", "комн": "комн", "комната": "комн", "эт": "эт",
    "этаж": "эт",
}
ADDRESS_TOKEN_RE = re.compile(r"[А-Яа-яЁё]+(?:-[А-Яа-яЁё]+)*|\d+(?:-\d+)?[А-Яа-я]?")

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
                PSEUDONYMIZER_ADDRESS_MASK=off: поведение до этапа Г. None - из профиля.
        """
        self._mask_legal = mask_legal_entity_requisites
        # None - значение профиля (labops/webapp_v2: выкл., pragmatika: вкл.)
        self._mask_addresses = get_profile().mask_addresses if mask_addresses is None else (
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
        found += self._detect_persons(text, tech)
        found += self._detect_latin_names(text)
        found += self._detect_case_shifted_persons(text, tech)
        found += self._detect_initialed_surnames(text, tech)
        found += self._detect_known_names(text, known_lemmas, tech)
        found += self._detect_tech_names(text, tech, known_lemmas)
        if self._mask_legal:
            found += self._detect_orgs(text)
        return _with_preposition_genders(text, _resolve_overlaps(found, text))

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
        return [
            Detection(m.start(), m.end(), PiiType.EMAIL, m.group().lower(), PRIO_EMAIL)
            for m in EMAIL_RE.finditer(text)
        ]

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
        # Десять цифр подряд — телефон только после слова «тел» (ключевое слово внутри шаблона)
        for m in BARE_PHONE_RE.finditer(text):
            number = m.group(1)
            if checksums.is_valid_inn(number):
                continue
            if _keyword_before(text, m.start(1), KW_INN, word_start=True):
                continue
            result.append(Detection(m.start(1), m.end(1), PiiType.PHONE, number, PRIO_PHONE))
        return result

    def _detect_latin_names(self, text: str) -> list[Detection]:
        """Латинские ФИО после метки контакта («Contact: Li Wei») и их повторы в тексте.

        Найденное после метки имя ищется по всему тексту: целиком (в той же записи слов) и
        каждое слово отдельно (фамилия «Smith»), с точным совпадением регистра и границами
        слова. Без метки и без находки рядом одиночное латинское слово не маскируется.
        """
        result: list[Detection] = []
        names: list[list[str]] = []
        for m in LATIN_NAME_LABEL_RE.finditer(text):
            start = m.start("name")
            end = start
            words: list[str] = []
            for word in LATIN_NAME_WORD_RE.finditer(m.group("name")):
                if word.group().lower() in LATIN_NOT_NAME_WORDS:
                    break
                end = start + word.end()
                words.append(word.group())
            if len(words) >= LATIN_MIN_NAME_WORDS:
                result.append(Detection(
                    start, end, PiiType.PERSON, person_key(text[start:end]), PRIO_PERSON
                ))
                names.append(words)
        if names:
            result += self._latin_name_repeats(text, names)
        return result

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
        for m in NUM10_12_RE.finditer(text):
            digits = m.group()
            kw = _keyword_before(text, m.start(), KW_INN, word_start=True)
            if not (checksums.is_valid_inn(digits) or kw):
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
        for m in PASSPORT_KW_RE.finditer(text):
            if _keyword_before(text, m.start(), KW_PASSPORT):
                result.append(
                    Detection(m.start(), m.end(), PiiType.PASSPORT, m.group(), PRIO_PASSPORT)
                )
        return result

    def _detect_contacts(self, text: str, norm: str) -> list[Detection]:
        # Ники и ссылки Telegram (R4-SEC-9): ключ по написанию без учёта регистра, как у email
        sources = [(NICK_RE, norm), (TME_RE, text)]
        if self._contacts_re is not None:
            sources.append((self._contacts_re, text))
        return [
            Detection(m.start(), m.end(), PiiType.CONTACT, m.group().casefold(), PRIO_CONTACT)
            for pattern, source in sources
            for m in pattern.finditer(source)
        ]

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
            if len(word) > 1 and word[0].isupper() and lemma(word) in known_lemmas:
                result.append(
                    Detection(m.start(), m.end(), PiiType.PERSON, person_key(word), PRIO_PERSON)
                )
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
            grams = name_gramme(m.group()) if kind else None
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
            if _overlaps(tech, m.start(), m.end()) or not is_surname_candidate(m.group(1)):
                continue
            taken.add(m.start(2))
            result.append(self._initialed_person(text, m.start(), m.end()))
        for m in INITIALS_SURNAME_RE.finditer(text):
            if _overlaps(tech, m.start(), m.end()) or not is_surname_candidate(m.group(2)):
                continue
            start = m.start(2) if m.start(1) in taken else m.start()
            result.append(self._initialed_person(text, start, m.end()))
        return result

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

    def _detect_persons(self, text: str, tech: list[tuple[int, int]]) -> list[Detection]:
        """ФИО через Natasha NER (Slovnet), с захватом соседних инициалов."""
        doc = Doc(text)
        doc.segment(self._segmenter)
        doc.tag_ner(self._ner)
        result: list[Detection] = []
        for span in doc.spans:
            if span.type != "PER":
                continue
            for piece_start, piece_end in _subtract(span.start, span.stop, tech):
                found = self._person_from_piece(text, piece_start, piece_end, tech)
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
        while end > start and text[end - 1] in " \t\n\r,;:!?()«»\"'":
            end -= 1
        start, end = _trim_non_name_words(text, start, end)
        start = _with_surname_before(text, start, end)
        chunk = text[start:end]
        if end <= start or not CYRILLIC_RE.search(chunk):
            return None
        if _overlaps(tech, start, end) or _glued_to_word(text, start, end):
            return None  # захват вылез на имя файла/слово через «_»
        words = WORD_RE.findall(chunk)
        if words and all(is_inanimate_common_noun(w) for w in words):
            return None  # «Металлопрокат», «Сибирь» — названия, не ФИО
        if words and all(w.upper() in CAPS_IP_STOPWORDS for w in words):
            # Подпись поля, а не ФИО: в маскированном «Подписант: [PERSON_1]» NER принимал
            # «Подписант» за имя, и вторая проверка отклоняла сообщение (28.10.2026).
            return None
        return Detection(start, end, PiiType.PERSON, person_key(chunk), PRIO_PERSON)


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
    pending: str | None = None  # метка квартиры/корпуса, ждущая номер
    for token in ADDRESS_TOKEN_RE.findall(fragment):
        low = token.casefold()
        if low[0].isdigit():
            numbers.append(f"{pending or ''}{low}")
            pending = None
        elif low in ADDRESS_SUFFIX_CODES:
            pending = ADDRESS_SUFFIX_CODES[low]
        elif low not in ADDRESS_NOISE_WORDS:
            names.append("-".join(common_lemma(part) for part in low.split("-")))
    return " ".join([*names, *numbers])


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
        result.append(det)
    return result


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
