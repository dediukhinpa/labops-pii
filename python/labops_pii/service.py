"""Ядро псевдонимизации: замена ПДн токенами и обратное восстановление."""

from __future__ import annotations

import itertools
import logging
import re
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, replace

from labops_pii.config import DEFAULT_MAX_RESTORE_TOKENS
from labops_pii.detector import Detection, PiiDetector, PiiType, follows_preposition
from labops_pii.inflect import address_street_word_nominative
from labops_pii.jsonlog import log_info_formatted, thread_hash
from labops_pii.morph import (
    inflect_person,
    keys_compatible,
    person_case,
    person_key,
    split_key,
)
from labops_pii.store import ReplacementStore

logger = logging.getLogger(__name__)

TOKEN_RE = re.compile(r"\[([A-Z]+)_(\d+)\]")
# Буквальная метка вида «[PERSON_1]» во входе экранируется: после «[» вставляется невидимый
# символ, и restore её не принимает за токен (R3-ALG-30). При восстановлении экранирование
# снимается, так что итоговый текст совпадает с исходным.
ESCAPE_MARK = "\u200b"
# Падежная метка «[PERSON_1|datv]» (грамматика согласована с клиентом сервиса): её пишет только
# модель в ответе, поэтому в /restore она склоняет ФИО, а во входе /pseudonymize всегда буквальна.
CASE_CODES = "nomn|gent|datv|accs|ablt|loct"
LABEL_RE = re.compile(rf"\[([A-Z]+)_(\d+)(?:\|({CASE_CODES}))?\]")
SEEN_OR_ESCAPED_RE = re.compile(rf"\[({ESCAPE_MARK})?([A-Z]+)_(\d+)(?:\|({CASE_CODES}))?\]")
# Только у ФИО метка меняет текст; у остальных типов она игнорируется.
INFLECTABLE_TYPE = PiiType.PERSON.value
# Тип записи-псевдонима: ключ, который разрешился в существующий токен нечётким сопоставлением
# ФИО. Запись хранится отдельным типом (в счёт токенов и в индекс ФИО не попадает), её
# «оригинал» — настоящий токен. Так одно и то же написание получает один и тот же токен
# в треде, даже когда позже появится однофамилец (R3-ALG-29).
ALIAS_TYPE_SUFFIX = "_ALIAS"
# Типы с «мягким» сопоставлением ФИО между полными и краткими формами.
FUZZY_TYPES = frozenset({PiiType.PERSON})
# Разделитель в ключе «точного» токена (часть имени файла): отделяет ключ от написания.
EXACT_SEP = "\x00"
# Сколько совместимых ФИО достаточно найти, чтобы признать сопоставление неоднозначным.
AMBIGUITY_THRESHOLD = 2
# До скольких полных слов в ключе ФИО кандидаты ищутся перебором подмножеств (до 31 набора).
SUBSET_SEARCH_MAX_WORDS = 5


@dataclass(frozen=True, slots=True)
class EntityRef:
    """Сущность в ответе: тип и токен (без оригинала)."""

    type: str
    token: str


class TooManyTokensError(ValueError):
    """В тексте для восстановления слишком много разных токенов.

    Attributes:
        limit: Действующий предел.
    """

    def __init__(self, limit: int) -> None:
        super().__init__(f"too many tokens: limit is {limit}")
        self.limit = limit


class _PersonIndex:
    """Ключи ФИО треда с быстрым поиском совместимых.

    Строится один раз на запрос. Раньше на каждое новое ФИО из базы заново читались и
    расшифровывались все ключи треда и каждый сравнивался с новым: текст с сотнями разных
    ФИО обрабатывался за квадратичное время. Ключи совместимы, только если полные слова
    одного целиком входят в другой, поэтому кандидаты это либо ключи ровно с таким набором
    слов, как у подмножества искомого, либо ключи, содержащие самое редкое его слово.
    """

    def __init__(self, entries: list[tuple[str, str]]) -> None:
        """Создаёт индекс.

        Args:
            entries: Пары (ключ, токен) из таблицы замен.
        """
        self._by_word: dict[str, list[tuple[str, str]]] = {}
        self._by_word_set: dict[frozenset[str], list[tuple[str, str]]] = {}
        for key, token in entries:
            self.add(key, token)

    def add(self, key: str, token: str) -> None:
        """Добавляет ключ; ключи «точных» токенов (часть имени файла) в поиск не идут."""
        if EXACT_SEP in key:
            return
        words = _full_words(key)
        self._by_word_set.setdefault(words, []).append((key, token))
        for word in words:
            self._by_word.setdefault(word, []).append((key, token))

    def _candidates(self, words: frozenset[str]) -> Iterator[tuple[str, str]]:
        """Ключи, которые могут быть совместимы с набором слов (с повторами)."""
        if len(words) > SUBSET_SEARCH_MAX_WORDS:  # необычно длинный ключ: перебор по словам
            for word in words:
                yield from self._by_word.get(word, ())
            return
        ordered = sorted(words)
        for size in range(1, len(ordered) + 1):  # ключи, чьи слова входят в искомый
            for subset in itertools.combinations(ordered, size):
                yield from self._by_word_set.get(frozenset(subset), ())
        # ключи, в которые входит искомый: все они содержат его самое редкое слово
        yield from min((self._by_word.get(word, []) for word in ordered), key=len)

    def compatible_tokens(self, key: str) -> list[str]:
        """Токены совместимых ключей: не больше AMBIGUITY_THRESHOLD штук.

        Вызывающему важно только, один кандидат или нет, поэтому поиск останавливается,
        как только неоднозначность установлена.
        """
        words = _full_words(key)
        found: dict[str, None] = {}
        if not words:
            return []
        for other, token in self._candidates(words):
            if token not in found and keys_compatible(other, key):
                found[token] = None
                if len(found) >= AMBIGUITY_THRESHOLD:
                    break
        return list(found)


class _LazyPersonIndex:
    """Индекс ФИО треда (`_PersonIndex`), который строится при первом нечётком поиске.

    Построение - проход по всем ключам ФИО треда. Тексту без новых ФИО (большинство листьев
    JSON результата инструмента) индекс не нужен, а в треде с сотнями ФИО его построение
    занимало ~60 % времени короткого текста: пачка из сотен листьев держала слот конкуренции
    секунды (R9-A2-04). Результат поиска тот же: ключи ФИО, заведённые в этом запросе до
    построения, уже лежат в таблице (та же транзакция под тем же замком, кэш ключей ведёт
    add()), и построение их подхватит; после построения новые ключи добавляются в индекс.
    Ответ поиска от порядка ключей не зависит: важно лишь, один совместимый токен или больше.
    """

    def __init__(self, load: Callable[[], list[tuple[str, str]]]) -> None:
        """Создаёт ленивый индекс.

        Args:
            load: Чтение пар (ключ, токен) ФИО треда из таблицы замен.
        """
        self._load = load
        self._index: _PersonIndex | None = None

    def add(self, key: str, token: str) -> None:
        """Добавляет ключ в построенный индекс; до построения его подхватит чтение таблицы."""
        if self._index is not None:
            self._index.add(key, token)

    def compatible_tokens(self, key: str) -> list[str]:
        """Токены совместимых ключей (см. `_PersonIndex.compatible_tokens`)."""
        if self._index is None:
            self._index = _PersonIndex(self._load())
        return self._index.compatible_tokens(key)


def _full_words(key: str) -> frozenset[str]:
    """Полные слова ключа ФИО (инициалы и пометка рода отбрасываются)."""
    return frozenset(word for word in split_key(key)[0] if len(word) > 1)


def _escape_literal_tokens(text: str, foreign: set[str]) -> str:
    """Экранирует буквальные метки: «[TYPE_N]» из набора foreign и любые «[TYPE_N|падеж]».

    Падежные метки пишет только модель в ответе, поэтому во входе они всегда буквальны и
    экранируются безусловно (restore их не тронет).
    """
    def escape(match: re.Match[str]) -> str:
        """Ставит невидимый символ после «[» у метки, которую restore трогать нельзя."""
        simple = f"[{match.group(1)}_{match.group(2)}]"
        if match.group(3) is None and simple not in foreign:
            return match.group(0)
        return f"[{ESCAPE_MARK}{match.group(0)[1:]}"

    return LABEL_RE.sub(escape, text)


class Pseudonymizer:
    """Заменяет ПДн токенами `[TYPE_N]`, стабильными в пределах thread_id."""

    def __init__(
        self,
        detector: PiiDetector,
        store: ReplacementStore,
        max_restore_tokens: int = DEFAULT_MAX_RESTORE_TOKENS,
    ) -> None:
        """Создаёт сервис.

        Args:
            detector: Детектор ПДн.
            store: Таблица замен.
            max_restore_tokens: Предел числа разных токенов в тексте для /restore.
        """
        self._detector = detector
        self._store = store
        self._max_restore_tokens = max_restore_tokens
        self._lock = threading.Lock()  # токены выдаются последовательно

    def pseudonymize(
        self, thread_id: str, text: str, case_labels: bool = False
    ) -> tuple[str, list[EntityRef]]:
        """Маскирует ПДн в тексте.

        Args:
            thread_id: Идентификатор треда.
            text: Исходный текст.
            case_labels: Ставить у ФИО в косвенном падеже метку «[PERSON_N|падеж]» (см.
                `morph.person_case`). Номера токенов, таблица замен и `entities` от флага
                не зависят: метка только украшает текст ответа.

        Returns:
            Пара (текст с токенами, уникальные сущности в порядке появления).
        """
        with self._lock:
            # Любое обращение продлевает жизнь треда, даже текст без ПДн
            self._store.touch(thread_id)
            known = self._known_lemmas(thread_id)
        detections = self._detector.detect(text, known)
        parts: list[str] = []
        entities: list[EntityRef] = []
        seen: set[str] = set()
        cursor = 0
        # Один коммит на запрос; при сбое ни один токен запроса в таблице не остаётся.
        with self._lock, self._store.batch():
            persons = _LazyPersonIndex(
                lambda: self._store.list_keys(thread_id, PiiType.PERSON.value)
            )
            foreign = self._foreign_literals(thread_id, text)
            for det in detections:
                token = self._token_for(thread_id, det, text[det.start:det.end], persons)
                parts.append(_escape_literal_tokens(text[cursor:det.start], foreign))
                parts.append(self._labelled(token, det, text[det.start:det.end], case_labels))
                cursor = det.end
                if token not in seen:
                    seen.add(token)
                    entities.append(EntityRef(det.pii_type.value, token))
        parts.append(_escape_literal_tokens(text[cursor:], foreign))
        log_info_formatted(
            logger, "pseudonymize: thread=%s найдено=%d", thread_hash(thread_id), len(detections)
        )
        return "".join(parts), entities

    @staticmethod
    def _labelled(token: str, det: Detection, original: str, case_labels: bool) -> str:
        """Токен с падежной меткой, если она включена и падеж ФИО определён однозначно.

        Часть имени файла (`exact`) метку не получает: restore склонил бы кусок имени файла.
        """
        if not case_labels or det.pii_type.value != INFLECTABLE_TYPE or det.exact:
            return token
        case = person_case(original)
        return token if case is None else f"{token[:-1]}|{case}]"

    def pseudonymize_batch(
        self, thread_id: str, texts: Sequence[str], case_labels: bool = False
    ) -> list[tuple[str, list[EntityRef]]]:
        """Маскирует список текстов одного треда: ровно как вызовы `pseudonymize` подряд.

        Тексты не склеиваются: каждый детектируется отдельно, со своими леммами треда, иначе
        соседний лист менял бы контекст NER (и мог скрыть ПДн). Порядок обработки - порядок
        списка, поэтому номера токенов и ключи те же, что у N одиночных запросов (R9-A2-04).
        Коммит, как и у одиночного, на каждый текст: сбой на k-м тексте оставляет в таблице
        токены первых k-1, ровно как оборванная серия одиночных запросов.

        Returns:
            Для каждого текста пара (текст с токенами, его уникальные сущности).
        """
        return [self.pseudonymize(thread_id, text, case_labels) for text in texts]

    def remask(
        self, thread_id: str, text: str, case_labels: bool = False
    ) -> tuple[str, list[EntityRef]]:
        """Дозамаскировывает уже замаскированный текст: закрывает остаток ПДн после /check.

        Второй проход после `pseudonymize` в том же треде: детектор идёт по тексту с токенами
        (контекст NER у такого текста другой, и он находит то, что первый проход пропустил),
        найденное получает токены с той же нумерацией и из той же таблицы. Токены и падежные
        метки, уже стоящие в тексте, не экранируются и не трогаются (в отличие от
        `pseudonymize`, где метка во входе всегда буквальна), чтобы повторная маска была
        идемпотентной. Если находка захватила токен («[PERSON_1] Иван»), в таблицу пишется
        восстановленный оригинал, а не текст с токеном: иначе /restore вернул бы метку в
        аргументы инструмента.

        Args:
            thread_id: Идентификатор треда.
            text: Уже замаскированный текст.
            case_labels: Падежные метки у новых токенов ФИО (как в `pseudonymize`).

        Returns:
            Пара (текст с новыми токенами, уникальные сущности второго прохода).
        """
        with self._lock:
            self._store.touch(thread_id)
            known = self._known_lemmas(thread_id)
        detections = self._detector.detect(text, known)
        parts: list[str] = []
        entities: list[EntityRef] = []
        seen: set[str] = set()
        cursor = 0
        with self._lock, self._store.batch():
            persons = _LazyPersonIndex(
                lambda: self._store.list_keys(thread_id, PiiType.PERSON.value)
            )
            for found in detections:
                det, original = self._expand_tokens(thread_id, found, text[found.start:found.end])
                token = self._token_for(thread_id, det, original, persons)
                parts.append(text[cursor:det.start])
                parts.append(self._labelled(token, det, original, case_labels))
                cursor = det.end
                if token not in seen:
                    seen.add(token)
                    entities.append(EntityRef(det.pii_type.value, token))
        parts.append(text[cursor:])
        log_info_formatted(
            logger, "remask: thread=%s найдено=%d", thread_hash(thread_id), len(detections)
        )
        return "".join(parts), entities

    def _expand_tokens(
        self, thread_id: str, det: Detection, fragment: str
    ) -> tuple[Detection, str]:
        """Подставляет оригиналы вместо токенов внутри находки второго прохода.

        Находка без токенов возвращается как есть. Ключ ФИО пересчитывается по восстановленному
        тексту: иначе токен «Иван Петров» не сопоставился бы с тем же человеком в треде.
        """
        simple = {f"[{m.group(1)}_{m.group(2)}]" for m in LABEL_RE.finditer(fragment)}
        if not simple:
            return det, fragment
        originals = self._store.get_originals(thread_id, simple)

        def substitute(match: re.Match[str]) -> str:
            """Токен треда -> оригинал; чужая метка остаётся как есть."""
            return originals.get(f"[{match.group(1)}_{match.group(2)}]", match.group(0))

        original = LABEL_RE.sub(substitute, fragment)
        if det.pii_type is PiiType.PERSON and not det.exact:
            det = replace(det, key=person_key(original))
        return det, original

    def remask_batch(
        self, thread_id: str, texts: Sequence[str], case_labels: bool = False
    ) -> list[tuple[str, list[EntityRef]]]:
        """Дозамаскировывает список текстов одного треда: ровно как вызовы `remask` подряд."""
        return [self.remask(thread_id, text, case_labels) for text in texts]

    def _foreign_literals(self, thread_id: str, text: str) -> set[str]:
        """Буквальные метки входа, которых сервис в этом треде не выдавал.

        Метки, уже выданные в треде, проходят как есть: так повторная маскировка истории,
        где токены уже стоят, остаётся идемпотентной. Остальные экранируются: иначе позже
        выданный токен с тем же номером превратил бы чужую метку в ПДн при /restore.
        (Пользователь, вручную набравший уже выданный токен своего треда, получит своё же
        значение: чужие треды это не затрагивает.)
        """
        literals = {m.group(0) for m in TOKEN_RE.finditer(text)}
        if not literals:
            return set()
        return literals - set(self._store.get_originals(thread_id, literals))

    def delete_thread(self, thread_id: str) -> bool:
        """Удаляет все замены треда под общей блокировкой записи.

        Блокировка обязательна: в SQLite удаление посреди чужой пачки записей вошло бы в её
        транзакцию и откатилось бы вместе с ней при сбое, тред молча остался бы в таблице.

        Args:
            thread_id: Идентификатор треда.

        Returns:
            True, если у треда были замены.
        """
        with self._lock:
            return self._store.delete_thread(thread_id)

    def restore(self, thread_id: str, text: str) -> str:
        """Возвращает оригиналы вместо токенов этого треда; чужие токены не трогает.

        Все токены текста читаются из таблицы одной пачкой.

        Raises:
            TooManyTokensError: Разных токенов в тексте больше предела.
        """
        self._store.touch(thread_id)
        # Метки одного токена с разными падежами считаются одним токеном.
        tokens = {
            f"[{m.group(2)}_{m.group(3)}]"
            for m in SEEN_OR_ESCAPED_RE.finditer(text)
            if m.group(1) is None
        }
        if not tokens and ESCAPE_MARK not in text:
            return text
        if len(tokens) > self._max_restore_tokens:
            raise TooManyTokensError(self._max_restore_tokens)
        originals = self._store.get_originals(thread_id, tokens) if tokens else {}

        def substitute(match: re.Match[str]) -> str:
            """Токен -> оригинал (с падежом у ФИО); экранированная метка -> буквальная."""
            if match.group(1) is not None:
                return match.group(0).replace(ESCAPE_MARK, "", 1)
            original = originals.get(f"[{match.group(2)}_{match.group(3)}]")
            if original is None:  # чужой токен или номер вне треда: фрагмент как есть
                return match.group(0)
            # Адрес хранится в падеже первого упоминания. Без предлога перед токеном (поле
            # «адрес доставки», «по адресу [ADDRESS_1]») ключевое слово улицы ставится в
            # именительный; после предлога падеж первого упоминания оставляется как есть.
            if match.group(2) == PiiType.ADDRESS.value and not follows_preposition(
                text, match.start()
            ):
                return address_street_word_nominative(original)
            case = match.group(4)
            if case is None or match.group(2) != INFLECTABLE_TYPE:
                return original
            return inflect_person(original, case)

        return SEEN_OR_ESCAPED_RE.sub(substitute, text)

    def _known_lemmas(self, thread_id: str) -> set[str]:
        """Леммы полных слов ФИО, уже известных в треде."""
        return {
            word
            for key, _ in self._store.list_keys(thread_id, PiiType.PERSON.value)
            if EXACT_SEP not in key
            for word in split_key(key)[0]
            if len(word) > 1
        }

    def check(self, text: str, thread_id: str | None = None) -> list[str]:
        """Возвращает отсортированные типы ПДн, найденных в тексте (ничего не сохраняет).

        Args:
            text: Проверяемый текст.
            thread_id: Тред, чьи леммы ФИО учитываются при поиске. Нужен для текста, где токены
                уже заменены оригиналами (запрос внешнего инструмента): одинокая фамилия, которую
                NER без контекста не видит, ловится по лемме треда, как при маскировании.
                Без треда проверка идёт без лемм. Токены при этом не создаются.
        """
        known: set[str] = set()
        if thread_id is not None:
            with self._lock:
                self._store.touch(thread_id)
                known = self._known_lemmas(thread_id)
        return sorted({d.pii_type.value for d in self._detector.detect(text, known)})

    def _token_for(
        self, thread_id: str, det: Detection, original: str, persons: _LazyPersonIndex
    ) -> str:
        """Находит существующий токен или заводит новый."""
        pii_type = det.pii_type.value
        if det.exact:
            return self._exact_token_for(thread_id, det, original)
        existing = self._store.find_token(thread_id, pii_type, det.key)
        if existing is None:  # то же написание уже было частью имени файла
            existing = self._store.find_token(
                thread_id, pii_type, f"{det.key}{EXACT_SEP}{original}"
            )
        if existing is not None:
            return existing
        if det.pii_type in FUZZY_TYPES:
            alias_type = pii_type + ALIAS_TYPE_SUFFIX
            aliased = self._store.find_token(thread_id, alias_type, det.key)
            if aliased is not None:  # это написание уже сопоставлено раньше: токен не меняем
                resolved = self._store.get_original(thread_id, aliased)
                if resolved is not None:
                    return resolved
            candidates = persons.compatible_tokens(det.key)
            if len(candidates) == 1:  # неоднозначность -> новый токен, безопаснее
                self._remember_alias(thread_id, alias_type, det.key, candidates[0])
                return candidates[0]
        token = f"[{pii_type}_{self._store.count(thread_id, pii_type) + 1}]"
        self._store.add(thread_id, token, pii_type, det.key, original)
        if det.pii_type in FUZZY_TYPES:
            persons.add(det.key, token)
        return token

    def _remember_alias(self, thread_id: str, alias_type: str, key: str, token: str) -> None:
        """Запоминает, что ключ ФИО разрешился в token (запись-псевдоним, см. ALIAS_TYPE_SUFFIX)."""
        number = self._store.count(thread_id, alias_type) + 1
        # Первичный ключ таблицы (тред, токен): псевдоним получает собственную уникальную метку
        self._store.add(thread_id, f"{token}~{number}", alias_type, key, token)

    def _exact_token_for(self, thread_id: str, det: Detection, original: str) -> str:
        """Токен для части имени файла/пути: общий с обычным текстом только при том же написании.

        Иначе `/restore` вернул бы в имя файла чужую форму («Иванов И.И._договор.docx»
        вместо «Иванов_договор.docx»). Новый токен хранится под ключом «лемма + написание»,
        поэтому нечёткое сопоставление ФИО его не подхватывает.
        """
        pii_type = det.pii_type.value
        plain = self._store.find_token(thread_id, pii_type, det.key)
        if plain is not None and self._store.get_original(thread_id, plain) == original:
            return plain
        key = f"{det.key}{EXACT_SEP}{original}"
        existing = self._store.find_token(thread_id, pii_type, key)
        if existing is not None:
            return existing
        token = f"[{pii_type}_{self._store.count(thread_id, pii_type) + 1}]"
        self._store.add(thread_id, token, pii_type, key, original)
        return token
