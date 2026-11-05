"""Этап 22: нормализация, паритет со слоем guard, род, стабильность токенов, экранирование."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.morph import keys_compatible, person_key
from labops_pii.pii_patterns import is_luhn_valid, normalize_text
from labops_pii.service import Pseudonymizer
from tests.labops_pseudonymizer.pii_corpus import NEGATIVE, POSITIVE

ROOT = Path(__file__).resolve().parents[3]
GUARD_DIR = ROOT / "gateway" / "pii-guard"
# Типы, по которым псевдонимизатор обязан совпадать с guard на общем корпусе
STRICT_TYPES = {"phone", "card", "account", "email"}
TOKEN_RE = re.compile(r"\[[A-Z]+_\d+\]")


def _types(detector: PiiDetector, text: str) -> set[str]:
    return {d.pii_type.value.lower() for d in detector.detect(text)}


@pytest.fixture(scope="module")
def legal(legal_detector: PiiDetector) -> PiiDetector:
    return legal_detector


# --- R3-SEC-6 / R3-ALG-3 / R3-ALG-15 / R3-SEC-8: общий корпус ----------------------

@pytest.mark.parametrize(("text", "expected"), POSITIVE)
def test_corpus_positive_found(legal: PiiDetector, text: str, expected: str) -> None:
    assert expected in _types(legal, text)


@pytest.mark.parametrize("text", NEGATIVE)
def test_corpus_negative_not_found(legal: PiiDetector, text: str) -> None:
    assert not _types(legal, text) & STRICT_TYPES


def test_pseudonymizer_and_guard_agree_on_corpus(legal: PiiDetector) -> None:
    """Слои не расходятся: на общем корпусе набор найденных строгих типов совпадает."""
    pytest.importorskip("fastapi")
    guard = _guard_detector()
    if guard is None:
        pytest.skip("pii-guard недоступен (отдельный образ)")
    for text, _ in POSITIVE:
        ours = _types(legal, text) & STRICT_TYPES
        theirs = guard.find_pii_types(text) & STRICT_TYPES
        assert ours == theirs, text
    for text in NEGATIVE:
        assert not (guard.find_pii_types(text) & STRICT_TYPES), text


@pytest.mark.parametrize("digits", ["7707083893", "500100732259"])
def test_valid_inn_without_word_guard_parity_default_detector(
    detector: PiiDetector, digits: str
) -> None:
    """ИНН без слова: guard видит `inn`, детектор по умолчанию маскирует, после маски пусто."""
    guard = _guard_detector()
    if guard is None:
        pytest.skip("pii-guard недоступен (отдельный образ)")
    text = f"реквизиты {digits} пришли"
    assert "inn" in guard.find_pii_types(text)
    assert "inn" in _types(detector, text)
    masked = "реквизиты [INN_1] пришли"
    assert not guard.find_pii_types(masked)


def test_default_detector_agrees_with_guard_on_corpus(detector: PiiDetector) -> None:
    """Общий корпус на детекторе по умолчанию (а не только на legal)."""
    guard = _guard_detector()
    if guard is None:
        pytest.skip("pii-guard недоступен (отдельный образ)")
    for text, _expected in POSITIVE:
        ours = _types(detector, text) & STRICT_TYPES
        assert ours == guard.find_pii_types(text) & STRICT_TYPES, text
    for text in NEGATIVE:
        assert not _types(detector, text) & STRICT_TYPES, text


def _guard_detector():  # noqa: ANN202
    """Детектор guard из того же пакета (раньше загружался по пути соседнего образа)."""
    import importlib

    return importlib.import_module("labops_pii.guard.detector")


def test_guard_uses_the_single_pattern_module() -> None:
    """Копий шаблонов нет: guard берёт ровно тот же модуль, что и псевдонимизатор."""
    import labops_pii.guard.detector as guard_detector
    import labops_pii.pii_patterns as patterns

    assert guard_detector.normalize_text is patterns.normalize_text


def test_guard_token_types_cover_all_pseudonymizer_types() -> None:
    from labops_pii.detector import PiiType

    from labops_pii.guard.detector import TOKEN_TYPES

    assert {t.value for t in PiiType} <= set(TOKEN_TYPES)



def test_normalize_keeps_length_and_maps() -> None:
    text = "８９１６ №5 8–916/12 3 … ＠"
    out = normalize_text(text)
    assert len(out) == len(text)
    assert out.startswith("8916 №5 8-916-12 3")
    assert "@" in out


def test_luhn() -> None:
    assert is_luhn_valid("4111111111111111")
    assert not is_luhn_valid("4111111111111112")
    assert not is_luhn_valid("411111111111111")  # 15 цифр: не карта


def test_replacement_keeps_surrounding_text(service: Pseudonymizer) -> None:
    """Нормализация не сдвигает позиции: текст вокруг телефона и «№» остаётся прежним."""
    text = "Заказ № 5… звоните 8–916–123–45–67 после ８ часов"
    masked, _ = service.pseudonymize("t-norm", text)
    assert "916" not in masked and "[PHONE_1]" in masked
    assert masked.startswith("Заказ № 5… звоните ")
    assert masked.endswith(" после ８ часов")
    assert service.restore("t-norm", masked) == text


def test_company_account_always_masked(detector: PiiDetector, legal: PiiDetector) -> None:
    company = "р/с 40702810123456789012"
    person = "счёт 40817810099910004312"
    assert "account" in _types(detector, company)
    assert "account" in _types(legal, company)
    assert "account" in _types(detector, person)


def test_snils_keyword_window_far_from_number(detector: PiiDetector) -> None:
    text = "СНИЛС страхового свидетельства № 123-456-789 01"
    assert "snils" in _types(detector, text)


def test_card_with_bad_luhn_is_not_masked(detector: PiiDetector) -> None:
    assert "card" not in _types(detector, "артикул 4111 1111 1111 1112")


# --- R3-ALG-14: род в ключе ФИО -------------------------------------------------------

def test_person_key_has_gender() -> None:
    assert person_key("Иванов И.И.") != person_key("Иванова И.И.")
    assert person_key("Иванов Иван Петрович") != person_key("Иванова Анна Петровна")
    assert person_key("Иванова Анна") == person_key("Ивановой Анны")


def test_keys_compatible_respects_gender() -> None:
    assert not keys_compatible(person_key("Иванов И."), person_key("Иванова И."))
    assert keys_compatible(person_key("Иванов И."), person_key("Иванов Иван"))
    # ключ без рода (старые записи) совместим с любым родом
    assert keys_compatible("иванов иван", person_key("Иванов Иван"))


def test_male_and_female_get_different_tokens(service: Pseudonymizer) -> None:
    masked_m, _ = service.pseudonymize("t-g", "Письмо подписал Иванов И.И. вчера")
    masked_f, _ = service.pseudonymize("t-g", "Письмо подписала Иванова И.И. сегодня")
    tokens_m = TOKEN_RE.findall(masked_m)
    tokens_f = TOKEN_RE.findall(masked_f)
    assert tokens_m and tokens_f and tokens_m != tokens_f
    assert "Иванов И.И." in service.restore("t-g", masked_m)
    assert "Иванова И.И." in service.restore("t-g", masked_f)


# --- R3-ALG-29: токен того же текста стабилен внутри треда -----------------------------

def test_same_text_same_token_after_new_namesake(service: Pseudonymizer) -> None:
    thread = "t-stable"
    service.pseudonymize(thread, "Иванов И. приехал")
    first, _ = service.pseudonymize(thread, "Позвонил Иванов")
    service.pseudonymize(thread, "Иванов Пётр приехал")
    again, _ = service.pseudonymize(thread, "Позвонил Иванов")
    assert first == again
    assert TOKEN_RE.search(first)


# --- R3-ALG-30: литералы токенов во входе --------------------------------------------

def test_literal_token_issued_later_is_not_restored_to_pii(service: Pseudonymizer) -> None:
    """Метка из входа, которой сервис не выдавал, позже совпавшая с выданным токеном."""
    thread = "t-esc"
    text = "в шаблоне стоит метка [PERSON_2], не подставляй"
    masked, _ = service.pseudonymize(thread, text)
    assert "[PERSON_2]" not in masked  # входная метка не выглядит как настоящий токен
    service.pseudonymize(thread, "Подписал Иванов Пётр, согласовал Сидоров Олег")  # P1, P2
    assert service.restore(thread, masked) == text


def test_already_issued_token_passes_unchanged(service: Pseudonymizer) -> None:
    """Идемпотентность: повторная маскировка истории с выданными токенами их не портит."""
    service.pseudonymize("t-idem", "Подписал Иванов Пётр Сергеевич")
    masked, _ = service.pseudonymize("t-idem", "Позвони [PERSON_1]")
    assert masked == "Позвони [PERSON_1]"


def test_literal_token_next_to_real_person(service: Pseudonymizer) -> None:
    thread = "t-esc2"
    text = "Метка [PERSON_1], а подписал Иванов Пётр Сергеевич"
    masked, entities = service.pseudonymize(thread, text)
    assert "Иванов" not in masked
    assert service.restore(thread, masked) == text
    assert entities


# --- R3-ALG-31: ФИО из 4+ слов заглавными -----------------------------------------------

@pytest.mark.parametrize(
    ("text", "words"),
    [
        ("ИВАНОВА АННА МАРИЯ СЕРГЕЕВНА", ("ИВАНОВА", "АННА", "МАРИЯ", "СЕРГЕЕВНА")),
        ("получил ПЕТРОВ ИВАН СЕРГЕЕВИЧ АЛЕКСАНДР", ("ПЕТРОВ", "ИВАН", "СЕРГЕЕВИЧ")),
    ],
)
def test_four_word_caps_person_fully_masked(
    service: Pseudonymizer, text: str, words: tuple[str, ...]
) -> None:
    masked, _ = service.pseudonymize("t-caps4", text)
    assert not any(w in masked for w in words), masked
