"""Белый список слов: слово из PII_ALLOWED_WORDS (пример: «Вектрика») не маскируется как ФИО или организация."""

from __future__ import annotations

import pytest

from labops_pii.allowlist import allowed_stems, is_allowed_fragment, strip_allowed_words
from tests.env_sets import ENV_SETS, use_env_set

FORMS = [
    "Вектрика", "Вектрики", "Вектрике", "Вектрику", "Вектрикой", "«Вектрика»",
    '"Вектрикой"', "вектрику", "ВЕКТРИКА",
]
SENTENCES = [
    "Мы работаем с Вектрикой уже год",
    "Это сообщение из Вектрики",
    "в Вектрике заказ готов",
    "Проект «Вектрика» запущен",
    "Отправь это в Вектрику",
]


@pytest.mark.parametrize("name", sorted(ENV_SETS))
def test_every_env_set_allows_the_project_name(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, name)
    assert all(is_allowed_fragment(form) for form in FORMS)


def test_other_words_not_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, "labops")
    assert not is_allowed_fragment("Вектрик Иванов")
    assert not is_allowed_fragment("Иванов")
    assert not is_allowed_fragment("Alex")  # имена в список не входят


def test_no_words_allowed_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Список слов по умолчанию пуст: слова задаёт только PII_ALLOWED_WORDS."""
    monkeypatch.delenv("PII_ALLOWED_WORDS", raising=False)
    assert allowed_stems() == ()
    assert not is_allowed_fragment("Вектрика")
    assert strip_allowed_words("из Вектрики") == "из Вектрики"


def test_extra_words_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PII_ALLOWED_WORDS", "Альф, Омег")
    assert is_allowed_fragment("Альфой") and not is_allowed_fragment("Бета")


def test_strip_keeps_positions(monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, "labops")
    text = "Иванов из Вектрики"
    stripped = strip_allowed_words(text)
    assert len(stripped) == len(text) and stripped.startswith("Иванов из ")
    assert stripped.strip() == "Иванов из"


@pytest.mark.parametrize("name", sorted(ENV_SETS))
def test_service_does_not_mask_project_name(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Сервис: на всех формах и в предложениях нет находок PERSON/ORG во всех профилях."""
    use_env_set(monkeypatch, name)
    from labops_pii.detector import PiiDetector

    detector = PiiDetector(mask_legal_entity_requisites=True)
    for text in [*FORMS, *SENTENCES]:
        types = {d.pii_type.value for d in detector.detect(text)}
        assert not types & {"PERSON", "ORG", "CONTACT"}, text


def test_real_person_next_to_project_name_still_masked(monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, "sqlite_v2")
    from labops_pii.detector import PiiDetector

    text = "Иванов Иван Иванович из Вектрики"
    found = [text[d.start:d.end] for d in PiiDetector().detect(text) if d.pii_type == "PERSON"]
    assert found and all("Вектрик" not in f for f in found)


@pytest.mark.parametrize("name", sorted(ENV_SETS))
def test_guard_does_not_flag_project_name(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, name)
    monkeypatch.setenv("PII_GUARD_NAMES_MODE", "enforce")
    from labops_pii.guard import detector

    for text in [*FORMS, *SENTENCES]:
        assert "name" not in detector.find_pii_types(text), text


# --- Память strip_allowed_words на вырожденном тексте ---
DEGENERATE_REPEATS = 2_000_000
# Потолок пика сверх входа: ~8 байт на символ (список символов) тест гарантированно нарушает
PEAK_BYTES_PER_CHAR = 4
EQUIVALENCE_SAMPLES = [
    "", "Иванов из Вектрики", "С.Вектрика и Вектрика-Плюс, «Вектрикой» ВЕКТРИКА",
    "Пектин С.Вектрика", "А.Вектрика", "ХВектрика Вектрик Вектриками Вектрикаааа",
    "a-a-a Альфой, Омегу; Бета", "вектрика", "Ё.Вектрика ёё Омег-Альф", "x С.Альф y",
]


def _old_strip(text: str) -> str:
    """Прежняя реализация через список символов (эталон для сравнения результатов)."""
    from labops_pii.allowlist import (
        ALLOWED_WORDS_ENV, GLUED_INITIAL_LEN, GLUED_INITIAL_RE, WORD_RE, is_allowed_word,
    )

    stems = allowed_stems()
    if not stems:
        return text
    chars = list(text)
    for match in WORD_RE.finditer(text):
        if not is_allowed_word(match.group(), stems):
            continue
        start = match.start()
        glued = text[max(start - GLUED_INITIAL_LEN, 0):start]
        if GLUED_INITIAL_RE.fullmatch(glued) and (
            start == GLUED_INITIAL_LEN or not text[start - GLUED_INITIAL_LEN - 1].isalpha()
        ):
            start -= GLUED_INITIAL_LEN
        chars[start:match.end()] = " " * (match.end() - start)
    return "".join(chars)


def test_strip_matches_reference_on_ordinary_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PII_ALLOWED_WORDS", "Вектрик, Альф, Омег")
    for text in EQUIVALENCE_SAMPLES:
        assert strip_allowed_words(text) == _old_strip(text), text
    use_env_set(monkeypatch, "labops")
    for text in [*FORMS, *SENTENCES, *EQUIVALENCE_SAMPLES]:
        assert strip_allowed_words(text) == _old_strip(text), text


def test_strip_peak_memory_is_linear_on_degenerate_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """2 млн повторов «a-» не должны раздувать память сверх малой константы от длины."""
    import tracemalloc

    monkeypatch.setenv("PII_ALLOWED_WORDS", "Вектрик")
    text = "a-" * DEGENERATE_REPEATS + "a"
    tracemalloc.start()
    try:
        result = strip_allowed_words(text)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == text
    assert peak <= PEAK_BYTES_PER_CHAR * len(text), peak
