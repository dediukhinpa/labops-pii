"""Тесты поиска технических токенов: эквивалентность прежнему шаблону и линейное время (S-03)."""

from __future__ import annotations

import random
import re
import time

import pytest

from labops_pii.tech_tokens import FILE_EXTENSIONS, find_tech_spans

# Прежний шаблон (эталон для сравнения на коротких строках; на длинных он квадратичный)
LEGACY_TECH_RE = re.compile(
    r"[\w\-]*_[\w\-]*(?:[_.][\w\-]+)*"
    rf"|[\w\-]+(?:[_.][\w\-]+)*\.(?:{FILE_EXTENSIONS})(?![\w])"
    r"|(?:[A-Za-z]:\\|~?/|\.{1,2}/)[^\s\"'<>|?*]*"
    r"|[\w.\-]+(?:[/\\][\w.\-]+){2,}",
    re.IGNORECASE,
)

FUZZ_ALPHABET = [
    "a", "b", "_", "-", ".", "/", "\\", " ", ":", "~", "C", "xlsx", "xls", "csv", "jpg",
    "jpeg", "docx", "ж", "1", "'", "*", ".xlsx", "_a", "a.", "./", "../",
]
FUZZ_CASES = 60_000
FUZZ_MAX_TOKENS = 12
FUZZ_SEED = 20261007

# Худший замер после правки около 1,1 с на 1 МБ; предел с запасом x5
PATHOLOGICAL_CHARS = 1_000_000
TIME_LIMIT_SECONDS = 5.5


def _legacy(text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in LEGACY_TECH_RE.finditer(text)]


def test_equivalent_to_legacy_regex_on_random_short_strings() -> None:
    rng = random.Random(FUZZ_SEED)
    for _ in range(FUZZ_CASES):
        text = "".join(rng.choices(FUZZ_ALPHABET, k=rng.randint(1, FUZZ_MAX_TOKENS)))
        assert find_tech_spans(text) == _legacy(text), repr(text)


@pytest.mark.parametrize(
    "text",
    [
        "Иванов_договор.docx и Прайс_2026.xlsx",
        "файл C:\\Users\\Ivan\\Документы\\a.pdf и ~/reports/a.csv",
        "см. /srv/docs/a/b.txt, ./x/y/z и ../up/z.md",
        "plain words without technical tokens",
        "foo.bar_baz and a.xlsx-b_c.csv",
    ],
)
def test_known_examples_match_legacy(text: str) -> None:
    assert find_tech_spans(text) == _legacy(text)


@pytest.mark.parametrize(
    "unit",
    ["a", "a-", "a.", "a_", "a.b_", "/", "a/", "a/b ", ".", "C:", "~", "ab.cd", "a.xlsx-",
     "a..", "x_y.z/", "a.xl"],
)
def test_pathological_input_is_linear(unit: str) -> None:
    text = unit * (PATHOLOGICAL_CHARS // len(unit))
    start = time.perf_counter()
    find_tech_spans(text)
    assert time.perf_counter() - start < TIME_LIMIT_SECONDS


def test_dotted_underscore_chain_is_not_exponential() -> None:
    """Прежний шаблон зависал на `a.` + `b_` * N: экспоненциальный откат."""
    text = "a." + "b_" * 50_000
    start = time.perf_counter()
    spans = find_tech_spans(text)
    assert time.perf_counter() - start < TIME_LIMIT_SECONDS
    assert spans == [(2, len(text))]
