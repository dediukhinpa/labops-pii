"""Guard (вторая линия) против обфускации: Bidi-метки и латинские гомоглифы в ФИО.

В guard-only развёртываниях (edge/litellm без псевдонимизатора) guard — единственный барьер:
необнаруженное имя в режиме enforce ушло бы в модель. Невидимые и направляющие знаки убирает
общий normalize_text; гомоглифы сворачивает fold_name_homoglyphs на поверхности ФИО.
"""

from __future__ import annotations

import pytest

from labops_pii.guard.detector import find_pii_types

LRM = "‎"
RLM = "‏"
LRI = "⁦"
PDI = "⁩"
ZWSP = "​"
NBSP = " "


@pytest.mark.parametrize("text", [
    f"{LRM}Иванов Пётр Сергеевич",
    f"{RLM}Иванов Пётр Сергеевич",
    f"Иванов{NBSP}Пётр Сергеевич",
    f"Договор подписал Ива{ZWSP}нов Пётр Сергеевич",
])
def test_name_with_invisible_marks_still_blocks(text: str) -> None:
    """Невидимые и направляющие знаки вокруг/внутри ФИО не прячут его от guard."""
    assert "name" in find_pii_types(text)


@pytest.mark.parametrize("text", [
    "Пeтрoв Сeргeй",          # строчные гомоглифы
    "ИВAНОВ ИВАН ПЕТРОВИЧ",   # латинская A в капсе
    "Ивaнoв Пётр Сергеевич",  # гомоглиф в фамилии
])
def test_homoglyph_name_still_blocks(text: str) -> None:
    """Имя из латинских гомоглифов блокируется guard (раньше проходило в enforce)."""
    assert "name" in find_pii_types(text)


@pytest.mark.parametrize("text", [
    "See the CSV export on GitHub",
    "Платёж в USD и EUR на счёт компании",
    "core cope scope — обычные английские слова",
])
def test_latin_words_do_not_trigger_false_name(text: str) -> None:
    """Настоящая латиница рядом с кириллицей не даёт ложного «name»."""
    assert "name" not in find_pii_types(text)


def test_phone_country_code_survives_bidi() -> None:
    assert "phone" in find_pii_types(f"{LRI}+7 902 555 12 34{PDI}")
