"""Адверсариальный «грязный» ввод: невидимые знаки, Bidi-метки и латинские гомоглифы.

Проверяет, что обфускация не приводит ни к утечке ПДн (false negative), ни к порче не-ПДн
или необратимости (false positive). На origin/prod эти случаи текли: NER и цифровые шаблоны
шли по сырому тексту и не узнавали имя или номер, разорванный форматирующим знаком или
собранный из латинских гомоглифов (см. CHANGELOG 1.2.2 «грязный ввод»).
"""

from __future__ import annotations

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.pii_patterns import normalize_text, strip_format_chars
from labops_pii.service import Pseudonymizer

# Невидимые и направляющие (Bidi) знаки нулевой ширины
ZWSP = "​"
ZWNJ = "‌"
NBSP = " "
SHY = "­"
WJ = "⁠"
BOM = "﻿"
LRM = "‎"
RLM = "‏"
ALM = "؜"
LRE = "‪"
PDF_CHAR = "‬"
LRI = "⁦"
PDI = "⁩"
BIDI_MARKS = (LRM, RLM, ALM, LRE, "‫", PDF_CHAR, "‭", "‮", LRI, "⁧",
              "⁨", PDI)


def _types(detector: PiiDetector, text: str) -> set[str]:
    return {d.pii_type.value for d in detector.detect(text)}


# --- Нормализация: длина сохраняется, направляющие знаки сворачиваются ---------------------

@pytest.mark.parametrize("mark", BIDI_MARKS)
def test_strip_format_chars_folds_bidi_to_space(mark: str) -> None:
    """Каждая Bidi-метка становится пробелом, позиции не сдвигаются."""
    text = f"Иванов{mark}Пётр"
    folded = strip_format_chars(text)
    assert len(folded) == len(text)
    assert folded == "Иванов Пётр"


@pytest.mark.parametrize("mark", BIDI_MARKS)
def test_normalize_text_also_folds_bidi(mark: str) -> None:
    """normalize_text (цифровой путь) тоже убирает Bidi-метки, не меняя длину."""
    text = f"500100732259{mark}"
    assert len(normalize_text(text)) == len(text)
    assert normalize_text(text) == "500100732259 "


# --- Цифровые ПДн с направляющими знаками -------------------------------------------------

def test_phone_keeps_country_code_with_bidi(detector: PiiDetector) -> None:
    """Bidi-метка после «+7» не отрезает код страны: раньше в находку попадал только «(902)…»."""
    text = f"тел +7{LRM} (902) 123-45-67"
    found = [d for d in detector.detect(text) if d.pii_type.value == "PHONE"]
    assert len(found) == 1
    assert text[found[0].start:found[0].end].startswith("+7")


def test_phone_wrapped_in_bidi_isolate(detector: PiiDetector) -> None:
    assert "PHONE" in _types(detector, f"{LRI}+7 902 555 12 34{PDI}")


def test_inn_with_bidi_after_keyword(detector: PiiDetector) -> None:
    assert "INN" in _types(detector, f"ИНН{LRM} 500100732259")


# --- ФИО с невидимыми и направляющими знаками ---------------------------------------------

@pytest.mark.parametrize("mark", [LRM, RLM, LRE, LRI])
def test_leading_bidi_does_not_hide_name(detector: PiiDetector, mark: str) -> None:
    """Направляющая метка перед именем не прячет ФИО от NER (раньше утечка)."""
    assert "PERSON" in _types(detector, f"{mark}Иванов Пётр Сергеевич")


@pytest.mark.parametrize("mark", [ZWSP, ZWNJ, NBSP, SHY, WJ, BOM, LRM])
def test_invisible_inside_name_still_detected(detector: PiiDetector, mark: str) -> None:
    assert "PERSON" in _types(detector, f"Договор с Ива{mark}новым Петром Сергеевичем")


# --- Гомоглифы: латиница, подмешанная в кириллическое имя ----------------------------------

@pytest.mark.parametrize("text", [
    "Пeтрoв Сeргeй",          # строчные гомоглифы e, o
    "Ивaнoв Пётр Сергеевич",  # гомоглиф a, o в фамилии
    "ИВAНОВ ИВАН",            # заглавные: латинская A
    "ивaнов пётр сергеевич",  # всё строчными, гомоглиф a
])
def test_homoglyph_name_is_detected(detector: PiiDetector, text: str) -> None:
    """Имя из латинских гомоглифов маскируется (раньше NER его не узнавал)."""
    assert "PERSON" in _types(detector, text)


@pytest.mark.parametrize("text", [
    "See the README and the CSV export",   # чистая латиница
    "Отправь ссылку на GitHub и в Telegram",  # латинские слова рядом с кириллицей
    "Платёж по курсу USD и EUR на счёт",
    "core cope scope — английские слова",
])
def test_latin_words_are_not_false_persons(detector: PiiDetector, text: str) -> None:
    """Настоящая латиница (не внутри смешанного слова) не становится ложным ФИО."""
    assert "PERSON" not in _types(detector, text)


# --- Обратимость и идемпотентность на грязном вводе ----------------------------------------

DIRTY_ROUNDTRIP = [
    f"Договор с Ива{ZWSP}новым Петром",
    f"Иванов{NBSP}Пётр звонил в офис",
    f"Ива{SHY}нов Пётр Сергеевич",
    f"{LRM}Иванов Пётр Сергеевич подписал акт",
    f"{LRI}+7 902 555 12 34{PDI} — рабочий",
    "Пeтрoв Сeргeй прислал счёт",
    "ИВAНОВ ИВАН оформил заказ",
    f"Контакт: Ива{ZWSP}нов П.С., тел +7(902)123-45-67, ИНН 500100732259",
]


@pytest.mark.parametrize("text", DIRTY_ROUNDTRIP)
def test_roundtrip_byte_exact_on_dirty_input(service: Pseudonymizer, text: str) -> None:
    """restore(pseudonymize(x)) == x побайтно даже на обфусцированном вводе."""
    out, _ = service.pseudonymize("adv", text)
    assert "[" in out  # что-то замаскировано
    assert service.restore("adv", out) == text


@pytest.mark.parametrize("text", DIRTY_ROUNDTRIP)
def test_masking_is_idempotent_on_dirty_input(service: Pseudonymizer, text: str) -> None:
    """Повторная маскировка уже замаскированного текста ничего не ломает."""
    once, _ = service.pseudonymize("idem", text)
    twice, _ = service.pseudonymize("idem", once)
    assert once == twice


def test_homoglyph_and_clean_name_share_token(service: Pseudonymizer) -> None:
    """Гомоглифная и чистая запись одного имени в треде получают один токен (ключ чистый)."""
    clean, _ = service.pseudonymize("share", "Петров Сергей")
    homo, _ = service.pseudonymize("share", "Пeтрoв Сeргeй")
    assert clean.strip() == homo.strip()
