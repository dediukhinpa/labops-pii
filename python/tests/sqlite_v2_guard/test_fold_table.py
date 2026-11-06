"""Статическая таблица свёртки символов: равна прежней ленивой и не растёт от входа."""

import sys
import unicodedata

from labops_pii import pii_patterns
from labops_pii.pii_patterns import normalize_text

# Прежние явные правила: тире и «/» -> «-», невидимые -> пробел
DASHES = (0x00AD, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2043, 0x2212, 0xFE58,
          0xFE63, 0xFF0D, 0x2044, 0x2215, 0xFF0F, ord("/"))
SURROGATES = range(0xD800, 0xE000)
HOSTILE_STEP = 7
INVISIBLE = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)


def _reference_image(code: int) -> int:
    """Образ символа по прежнему ленивому правилу (эталон для сравнения)."""
    if code in DASHES:
        return ord("-")
    if code in INVISIBLE:
        return ord(" ")
    char = chr(code)
    digit = unicodedata.decimal(char, None)
    if digit is not None:
        return ord(str(digit))
    folded = unicodedata.normalize("NFKC", char)
    return ord(folded) if len(folded) == 1 else code


def test_static_table_equals_lazy_reference_on_all_codepoints() -> None:
    table = pii_patterns._FOLD
    for code in range(sys.maxunicode + 1):
        assert table.get(code, code) == _reference_image(code), hex(code)


def test_table_has_only_non_identity_entries() -> None:
    assert all(key != value for key, value in pii_patterns._FOLD.items())


def test_table_does_not_grow_on_hostile_input() -> None:
    size = len(pii_patterns._FOLD)
    codes = range(0x20, sys.maxunicode + 1, HOSTILE_STEP)
    hostile = "".join(chr(c) for c in codes if not SURROGATES.start <= c < SURROGATES.stop)
    assert len(normalize_text(hostile)) == len(hostile)
    assert len(pii_patterns._FOLD) == size
