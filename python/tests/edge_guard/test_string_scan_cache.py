"""Кэш прохода по строкам JSON: результат scan_body тот же, что без кэша; пределы кэша."""

import hashlib
import json

import pytest

from labops_pii.guard import detector
from labops_pii.guard.detector import (
    BodyNotJsonError,
    _StringScanCache,
    decode_body,
    find_pii_types,
    scan_body,
)
from tests.edge_guard.pii_corpus import NEGATIVE, POSITIVE

# Длиннее STRING_CACHE_MIN_CHARS, иначе строка в кэш не попадёт
FILLER = "служебный текст без персональных данных " * 3
SMALL_CACHE_ENTRIES = 3
SMALL_CACHE_CHARS = 1000
REPEAT_STEPS = 5


def _uncached_scan(body: bytes, require_json: bool = False) -> set[str]:
    """Эталон: тот же scan_body, но строки проверяются прямым find_pii_types."""
    original = detector._STRING_CACHE
    detector._STRING_CACHE = _PassThrough()  # type: ignore[assignment]
    try:
        return scan_body(body, require_json=require_json)
    finally:
        detector._STRING_CACHE = original


class _PassThrough:
    """Подмена кэша без памяти."""

    def find(self, text: str) -> frozenset[str]:
        return frozenset(find_pii_types(text))


@pytest.fixture(autouse=True)
def _clean_cache() -> None:
    detector._STRING_CACHE.clear()


def _bodies() -> list[bytes]:
    texts = [text for text, _ in POSITIVE] + NEGATIVE
    bodies = [json.dumps({"m": [FILLER + t]}, ensure_ascii=False).encode() for t in texts]
    bodies.append(json.dumps({FILLER + "ключ 8 916 123 45 67": 1, "n": 12345678901}).encode())
    bodies.append("﻿".encode("utf-8") + json.dumps({"a": FILLER}).encode())
    bodies.append(json.dumps({"a": FILLER}).encode("utf-16"))
    bodies.append(b'{"a": "' + FILLER.encode() + b' \\ud800"}')  # одиночный суррогат
    return bodies


def test_cached_result_equals_uncached() -> None:
    """С кэшем (в том числе на повторе) результат совпадает с расчётом без кэша."""
    for body in _bodies():
        expected = _uncached_scan(body)
        for _ in range(2):  # второй проход идёт из кэша
            assert scan_body(body) == expected


def test_positive_corpus_still_detected_via_cache() -> None:
    for text, kind in POSITIVE:
        body = json.dumps({"m": FILLER + text}, ensure_ascii=False).encode()
        for _ in range(2):
            assert kind in scan_body(body)


def test_fail_closed_unchanged() -> None:
    with pytest.raises(BodyNotJsonError):
        scan_body(b"not json " + FILLER.encode(), require_json=True)
    assert scan_body(b"not json 8 916 123 45 67") == _uncached_scan(b"not json 8 916 123 45 67")
    with pytest.raises(detector.BodyTooLargeError):
        scan_body(b"x" * 10, max_bytes=5)


def test_decode_body_called_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real = decode_body
    monkeypatch.setattr(detector, "decode_body", lambda b: (calls.append(1), real(b))[1])
    scan_body(json.dumps({"a": FILLER}).encode())
    assert len(calls) == 1


def test_repeated_strings_hit_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """История запроса растёт, а повторные строки заново не считаются."""
    calls: list[str] = []
    real = detector.find_pii_types
    monkeypatch.setattr(detector, "find_pii_types", lambda t: (calls.append(t), real(t))[1])
    history = [f"{FILLER} шаг {i}" for i in range(REPEAT_STEPS)]
    for step in range(1, REPEAT_STEPS + 1):
        scan_body(json.dumps({"m": history[:step]}).encode())
    string_calls = [t for t in calls if t in history]
    assert len(string_calls) == REPEAT_STEPS  # каждая строка один раз, а не по разу на шаг


def test_cache_holds_only_hash_and_types() -> None:
    cache = _StringScanCache(SMALL_CACHE_ENTRIES, SMALL_CACHE_CHARS)
    text = FILLER + "тел 8 916 123 45 67"
    assert cache.find(text) == frozenset({"phone"})
    (key, (types, size)), = cache._items.items()
    assert key == hashlib.sha256(text.encode()).digest()
    assert types == frozenset({"phone"}) and size == len(text)
    assert text not in repr(cache._items)


def test_cache_limits_entries_and_chars() -> None:
    cache = _StringScanCache(SMALL_CACHE_ENTRIES, SMALL_CACHE_CHARS)
    for i in range(SMALL_CACHE_ENTRIES * 3):
        cache.find(f"{FILLER} {i}")
    entries, chars = cache.stats()
    assert entries == SMALL_CACHE_ENTRIES
    cache.clear()
    big = "я" * (SMALL_CACHE_CHARS // 2 + 1)
    cache.find(big + "1")
    cache.find(big + "2")  # вместе больше предела объёма: старая запись вытеснена
    entries, chars = cache.stats()
    assert entries == 1 and chars <= SMALL_CACHE_CHARS
    cache.find("ы" * (SMALL_CACHE_CHARS + 1))  # длиннее предела: не кэшируется, но считается
    assert cache.stats() == (entries, chars)


def test_cache_lru_order() -> None:
    cache = _StringScanCache(SMALL_CACHE_ENTRIES, SMALL_CACHE_CHARS)
    first = f"{FILLER} first"
    cache.find(first)
    for i in range(SMALL_CACHE_ENTRIES - 1):
        cache.find(f"{FILLER} {i}")
    cache.find(first)  # обращение освежает запись
    cache.find(f"{FILLER} новая")
    key = hashlib.sha256(first.encode()).digest()
    assert key in cache._items
