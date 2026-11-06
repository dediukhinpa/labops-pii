"""Этап 32 (R5-PY-1..3): бинарный поиск диапазонов, кэш разбора pymorphy, кэш счётчиков."""

from __future__ import annotations

import contextlib
import functools
import random
import sqlite3
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import labops_pii.detector as detector_module
import labops_pii.morph as morph
from labops_pii.detector import (
    Detection,
    PiiDetector,
    PiiType,
    _overlaps,
    _resolve_overlaps,
    _subtract,
)
from labops_pii.service import Pseudonymizer
from labops_pii.store import COUNT_CACHE_ENTRIES, SqliteReplacementStore
from tests.pragmatika_pseudonymizer.pii_corpus import NEGATIVE, POSITIVE

RANDOM_SEED = 32
RANDOM_CASES = 400
# Пороги по времени с большим запасом на медленный CI: прежняя реализация на этих размерах
# занимала 19-25 с (замер этапа 32 «до»), новая укладывается в десятые доли секунды.
BIG_N = 20_000
TIME_LIMIT_SECONDS = 4.0


# --- эталон: прежние реализации (до этапа 32) ------------------------------------------

def _old_overlaps(ranges: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(start < r_end and end > r_start for r_start, r_end in ranges)


def _old_subtract(start: int, end: int, ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    pieces: list[tuple[int, int]] = []
    cursor = start
    for r_start, r_end in sorted(ranges):
        if r_end <= cursor or r_start >= end:
            continue
        if r_start > cursor:
            pieces.append((cursor, r_start))
        cursor = max(cursor, r_end)
    if cursor < end:
        pieces.append((cursor, end))
    return pieces


def _old_resolve(found: list[Detection]) -> list[Detection]:
    chosen: list[Detection] = []
    for det in sorted(found, key=lambda d: (d.priority, -(d.end - d.start), d.start)):
        if all(det.end <= c.start or det.start >= c.end for c in chosen):
            chosen.append(det)
    return sorted(chosen, key=lambda d: d.start)


def _random_ranges(rng: random.Random, limit: int) -> list[tuple[int, int]]:
    """Отсортированные непересекающиеся диапазоны, в том числе вплотную друг к другу."""
    ranges: list[tuple[int, int]] = []
    pos = rng.randint(0, 5)
    while pos < limit:
        length = rng.randint(1, 8)
        ranges.append((pos, pos + length))
        pos += length + rng.choice([0, 0, 1, 2, 5, 11])
    return ranges


def _random_detections(rng: random.Random, limit: int, count: int) -> list[Detection]:
    """Пересекающиеся, вложенные, смежные и совпадающие находки разных приоритетов."""
    dets = []
    for _ in range(count):
        start = rng.randint(0, limit)
        end = start + rng.randint(1, 12)
        dets.append(Detection(start, end, PiiType.EMAIL, f"k{start}", rng.randint(0, 9)))
    return dets


def test_overlaps_and_subtract_match_old_on_random() -> None:
    rng = random.Random(RANDOM_SEED)
    for _ in range(RANDOM_CASES):
        limit = rng.randint(1, 120)
        ranges = _random_ranges(rng, limit)
        for _ in range(30):
            start = rng.randint(0, limit + 5)
            end = start + rng.randint(1, 20)
            assert _overlaps(ranges, start, end) == _old_overlaps(ranges, start, end)
            assert _subtract(start, end, ranges) == _old_subtract(start, end, ranges)


def test_overlaps_edge_cases() -> None:
    ranges = [(5, 10), (10, 15), (20, 21)]
    assert not _overlaps([], 0, 5)
    assert not _overlaps(ranges, 0, 5)  # вплотную слева
    assert _overlaps(ranges, 0, 6)
    assert _overlaps(ranges, 9, 10)
    assert _overlaps(ranges, 12, 13)  # вложен
    assert not _overlaps(ranges, 15, 20)  # между диапазонами
    assert not _overlaps(ranges, 21, 30)
    assert _overlaps(ranges, 0, 100)  # накрывает всё
    assert _subtract(0, 30, ranges) == [(0, 5), (15, 20), (21, 30)]
    assert _subtract(6, 9, ranges) == []


def _covered(dets: list[Detection]) -> set[int]:
    """Позиции символов, покрытых хотя бы одной находкой."""
    return {pos for d in dets for pos in range(d.start, d.end)}


def test_resolve_overlaps_matches_old_on_random() -> None:
    """Где важнейшая находка покрывает свою группу, выбор прежний; иначе маска - объединение.

    R9-A4-03: ни один символ, покрытый любой находкой, не остаётся открытым; результат не
    пересекается и отсортирован; смежные находки не склеиваются.
    """
    rng = random.Random(RANDOM_SEED)
    text = "x" * 200
    for _ in range(RANDOM_CASES):
        limit = rng.randint(1, 150)
        found = _random_detections(rng, limit, rng.randint(0, 60))
        result = _resolve_overlaps(found, text)
        assert _covered(result) == _covered(found)
        assert all(a.end <= b.start for a, b in zip(result, result[1:]))
        old = _old_resolve(found)
        old_by_start = {d.start: d for d in old}
        for det in result:
            if det in found:  # выбрана исходная находка: та же, что выбрал бы прежний алгоритм
                assert old_by_start.get(det.start) == det


def test_resolve_overlaps_priority_and_length() -> None:
    low = Detection(0, 10, PiiType.PHONE, "a", 6)
    high = Detection(2, 8, PiiType.EMAIL, "b", 1)
    adjacent = Detection(10, 12, PiiType.PHONE, "c", 6)
    # важнейшая (EMAIL) не покрывает группу: маскируется объединение, тип важнейшей,
    # точный токен; смежная находка (начало = конец группы) остаётся отдельной
    merged, rest = _resolve_overlaps([low, high, adjacent], "0123456789AB")
    assert (merged.start, merged.end, merged.pii_type, merged.exact) == (0, 10, PiiType.EMAIL, True)
    assert rest == adjacent
    inner = Detection(0, 10, PiiType.EMAIL, "d", 1)
    assert _resolve_overlaps([inner, high], "0123456789") == [inner]


def test_resolve_overlaps_is_not_quadratic() -> None:
    found = [Detection(i * 7, i * 7 + 6, PiiType.EMAIL, "k", 1) for i in range(BIG_N)]
    started = time.perf_counter()
    result = _resolve_overlaps(found, "x" * (BIG_N * 7))
    assert time.perf_counter() - started < TIME_LIMIT_SECONDS
    assert len(result) == BIG_N


def test_overlaps_is_not_quadratic() -> None:
    tech = [(i * 20, i * 20 + 15) for i in range(BIG_N)]
    started = time.perf_counter()
    for i in range(BIG_N):  # слова между диапазонами: прежний перебор шёл по всем
        assert not _overlaps(tech, i * 20 + 16, i * 20 + 19)
    assert time.perf_counter() - started < TIME_LIMIT_SECONDS


def test_subtract_is_not_quadratic() -> None:
    tech = [(i * 20, i * 20 + 15) for i in range(BIG_N)]
    started = time.perf_counter()
    for i in range(BIG_N):
        assert _subtract(i * 20, i * 20 + 19, tech) == [(i * 20 + 15, i * 20 + 19)]
    assert time.perf_counter() - started < TIME_LIMIT_SECONDS


# --- R5-PY-2: кэш разбора ---------------------------------------------------------------

def test_morph_parse_called_once_per_word(monkeypatch: pytest.MonkeyPatch) -> None:
    analyzer = morph._analyzer()
    real_parse = analyzer.parse
    calls: list[str] = []

    def counting(word: str):  # noqa: ANN202
        calls.append(word)
        return real_parse(word)

    morph._parse_cached.cache_clear()
    monkeypatch.setattr(analyzer, "parse", counting)
    try:
        first = (
            morph.is_non_name_word("Позвонить"),
            morph.is_inanimate_common_noun("Металлопрокат"),
            morph.is_person_word("Петров"),
        )
        for _ in range(50):
            again = (
                morph.is_non_name_word("Позвонить"),
                morph.is_inanimate_common_noun("Металлопрокат"),
                morph.is_person_word("Петров"),
            )
            assert again == first
        assert sorted(calls) == ["металлопрокат", "петров", "позвонить"]
        assert first == (True, True, True)
    finally:
        monkeypatch.undo()
        morph._parse_cached.cache_clear()


def test_morph_cached_value_is_immutable() -> None:
    parsed = morph._parse_cached("иванов")
    assert isinstance(parsed, tuple)
    assert morph._parse_cached("иванов") is parsed


# --- R9-A4-08: повтор плотного списка ФИО в треде -------------------------------------
# Общий LRU разборов уменьшается до SMALL_PARSE_CACHE слов, чтобы список из DENSE_NAMES ФИО
# (втрое больше разных слов) вытеснял его так же, как текст в 70 000 знаков вытеснял кэш на
# 4 096 слов: до правки pymorphy звался на одно и то же слово многократно (9,2 с CPU на
# повторе 70 000 знаков), теперь не чаще раза на слово за запрос.
SMALL_PARSE_CACHE = 64
DENSE_NAMES = 300
DENSE_SEED = 2
_LOWER = "абвгдежзиклмнопрстуфхцчшщэюя"


def _dense_names(count: int) -> str:
    """Плотный список вымышленных ФИО «Фамилияов Имя Отчествоович, …» (как в замере ревью)."""
    rng = random.Random(DENSE_SEED)

    def word(length: int) -> str:
        return "".join(rng.choice(_LOWER) for _ in range(length)).capitalize()

    return "".join(f"{word(6)}ов {word(4)} {word(5)}ович, " for _ in range(count))


def _distinct_words(text: str) -> set[str]:
    return {w.lower().replace("ё", "е") for w in morph.WORD_RE.findall(text)}


@pytest.fixture
def small_parse_cache(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Маленький общий LRU разборов и счётчик вызовов pymorphy; кэши модуля чистые."""
    analyzer = morph._analyzer()
    real_parse = analyzer.parse
    calls: list[str] = []

    def counting(word: str):  # noqa: ANN202
        calls.append(word)
        return real_parse(word)

    for cached in (morph.lemma, morph._name_vote, morph._surname_vote, morph.name_gramme,
                   morph._likely_male_oblique_name):
        cached.cache_clear()
    small = functools.lru_cache(maxsize=SMALL_PARSE_CACHE)(morph._parse_cached.__wrapped__)
    monkeypatch.setattr(morph, "_parse_cached", small)
    monkeypatch.setattr(analyzer, "parse", counting)
    yield calls
    monkeypatch.undo()
    for cached in (morph.lemma, morph._name_vote, morph._surname_vote, morph.name_gramme,
                   morph._likely_male_oblique_name):
        cached.cache_clear()


def test_dense_names_repeat_parses_each_word_once(
    service: Pseudonymizer, small_parse_cache: list[str]
) -> None:
    """Повтор плотного списка ФИО в треде: каждое слово разбирается не больше раза за запрос."""
    text = _dense_names(DENSE_NAMES)
    assert len(_distinct_words(text)) > SMALL_PARSE_CACHE * 3
    service.pseudonymize("t", text)
    first = list(small_parse_cache)
    small_parse_cache.clear()
    service.pseudonymize("t", text)  # повтор: в треде уже известны леммы всех ФИО
    # Слова разбора - слова текста и их срезы (детектор сдвинутого регистра снимает букву).
    assert len(first) == len(set(first))
    assert len(small_parse_cache) == len(set(small_parse_cache))
    assert morph._request_memo.get() is None  # память запроса не переживает запрос


def test_request_cache_keeps_result(
    detector: PiiDetector, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Память разборов запроса не меняет находки и токены: сверка с работой без неё."""
    dense = _dense_names(DENSE_NAMES // 3)
    texts = [dense, *(text for text, _ in POSITIVE), *NEGATIVE]

    def run() -> tuple[list[list[Detection]], list[str]]:
        found = [detector.detect(text) for text in texts]
        service = Pseudonymizer(detector, SqliteReplacementStore(":memory:", fernet_key))
        masked = [service.pseudonymize("t", text)[0] for text in (dense, dense)]
        return found, masked

    with_memo = run()
    monkeypatch.setattr(detector_module, "request_cache", contextlib.nullcontext)
    assert run() == with_memo


# --- R5-PY-3: кэш счётчиков хранилища ---------------------------------------------------

def _truth(store: SqliteReplacementStore, thread: str, pii_type: str) -> int:
    row = store._conn.execute(
        "SELECT COUNT(*) FROM replacements WHERE thread_id=? AND pii_type=?",
        (thread, pii_type),
    ).fetchone()
    return int(row[0])


def _add_n(store: SqliteReplacementStore, thread: str, kind: str, start: int, n: int) -> None:
    for i in range(start, start + n):
        store.add(thread, f"[{kind}_{i}]", kind, f"key{i}", f"orig{i}")


def test_count_matches_after_add(store: SqliteReplacementStore) -> None:
    assert store.count("t", "EMAIL") == 0  # кэш заполнен нулём
    _add_n(store, "t", "EMAIL", 1, 5)
    assert store.count("t", "EMAIL") == _truth(store, "t", "EMAIL") == 5
    assert store.count("t", "PHONE") == 0
    assert store.count("other", "EMAIL") == 0


def test_count_after_duplicate_insert(store: SqliteReplacementStore) -> None:
    _add_n(store, "t", "EMAIL", 1, 3)
    assert store.count("t", "EMAIL") == 3
    with pytest.raises(sqlite3.IntegrityError):  # тот же ключ (UNIQUE по хешу ключа)
        store.add("t", "[EMAIL_99]", "EMAIL", "key1", "dup")
    with pytest.raises(sqlite3.IntegrityError):  # тот же токен (PRIMARY KEY)
        store.add("t", "[EMAIL_1]", "EMAIL", "new", "dup")
    assert store.count("t", "EMAIL") == _truth(store, "t", "EMAIL") == 3


def test_count_after_batch_rollback(store: SqliteReplacementStore) -> None:
    _add_n(store, "t", "EMAIL", 1, 2)
    assert store.count("t", "EMAIL") == 2
    with pytest.raises(RuntimeError), store.batch():
        _add_n(store, "t", "EMAIL", 3, 4)
        assert store.count("t", "EMAIL") == 6
        raise RuntimeError("отказ посреди запроса")
    assert store.count("t", "EMAIL") == _truth(store, "t", "EMAIL") == 2
    with store.batch():  # успешная пачка фиксируется
        _add_n(store, "t", "EMAIL", 3, 2)
    assert store.count("t", "EMAIL") == _truth(store, "t", "EMAIL") == 4


def test_count_after_retention(fernet_key: str) -> None:
    now = [1_000_000_000.0]
    store = SqliteReplacementStore(":memory:", fernet_key, clock=lambda: now[0])
    _add_n(store, "old", "EMAIL", 1, 3)
    assert store.count("old", "EMAIL") == 3
    now[0] += 60 * 86_400
    _add_n(store, "fresh", "EMAIL", 1, 2)
    assert store.purge_expired(30) == 1
    assert store.count("old", "EMAIL") == _truth(store, "old", "EMAIL") == 0
    assert store.count("fresh", "EMAIL") == 2
    _add_n(store, "old", "EMAIL", 1, 1)  # тред с тем же именем начинается заново
    assert store.count("old", "EMAIL") == 1


def test_count_sees_write_from_other_connection(tmp_path: Path, fernet_key: str) -> None:
    path = tmp_path / "db.sqlite"
    first = SqliteReplacementStore(path, fernet_key)
    second = SqliteReplacementStore(path, fernet_key)
    assert first.count("t", "EMAIL") == 0
    _add_n(second, "t", "EMAIL", 1, 3)  # другой процесс пишет в тот же файл
    assert first.count("t", "EMAIL") == _truth(first, "t", "EMAIL") == 3
    _add_n(first, "t", "EMAIL", 4, 1)
    assert second.count("t", "EMAIL") == 4


def test_count_cache_is_bounded(store: SqliteReplacementStore) -> None:
    for i in range(COUNT_CACHE_ENTRIES + 50):
        store.count(f"thread{i}", "EMAIL")
    assert len(store._counts) <= COUNT_CACHE_ENTRIES
    _add_n(store, "thread0", "EMAIL", 1, 2)  # вытесненная запись пересчитывается
    assert store.count("thread0", "EMAIL") == 2


def test_count_with_parallel_threads(fernet_key: str) -> None:
    store = SqliteReplacementStore(":memory:", fernet_key)
    threads_n, per_thread = 4, 60
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            for i in range(per_thread):
                store.count("shared", "EMAIL")
                store.add("shared", f"[EMAIL_{index}_{i}]", "EMAIL", f"k{index}_{i}", "o")
                store.count(f"own{index}", "EMAIL")
                store.add(f"own{index}", f"[EMAIL_{i}]", "EMAIL", f"k{i}", "o")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    pool = [threading.Thread(target=worker, args=(i,)) for i in range(threads_n)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    assert not errors
    assert store.count("shared", "EMAIL") == _truth(store, "shared", "EMAIL")
    assert store.count("shared", "EMAIL") == threads_n * per_thread
    for index in range(threads_n):
        assert store.count(f"own{index}", "EMAIL") == per_thread


def test_count_scaling_not_quadratic(fernet_key: str, tmp_path: Path) -> None:
    store = SqliteReplacementStore(tmp_path / "big.sqlite", fernet_key)
    n = 6_000
    started = time.perf_counter()
    with store.batch():
        for i in range(n):
            store.add("t", f"[EMAIL_{store.count('t', 'EMAIL') + 1}]", "EMAIL", f"k{i}", "o")
    assert time.perf_counter() - started < 10.0
    assert store.count("t", "EMAIL") == n
