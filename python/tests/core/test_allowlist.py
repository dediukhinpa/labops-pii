"""Белый список слов: «Прагматика» (название проекта) не маскируется как ФИО или организация."""

from __future__ import annotations

import pytest

from labops_pii.allowlist import allowed_stems, is_allowed_fragment, strip_allowed_words
from tests.env_sets import ENV_SETS, use_env_set

FORMS = [
    "Прагматика", "Прагматики", "Прагматике", "Прагматику", "Прагматикой", "«Прагматика»",
    '"Прагматикой"', "прагматику", "ПРАГМАТИКА",
]
SENTENCES = [
    "Мы работаем с Прагматикой уже год",
    "Это сообщение из Прагматики",
    "в Прагматике заказ готов",
    "Проект «Прагматика» запущен",
    "Отправь это в Прагматику",
]


@pytest.mark.parametrize("name", sorted(ENV_SETS))
def test_every_env_set_allows_the_project_name(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, name)
    assert all(is_allowed_fragment(form) for form in FORMS)


def test_other_words_not_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, "labops")
    assert not is_allowed_fragment("Прагматик Иванов")
    assert not is_allowed_fragment("Иванов")
    assert not is_allowed_fragment("Tony")  # имена агентов в список не входят


def test_no_words_allowed_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Список слов по умолчанию пуст: слова задаёт только PII_ALLOWED_WORDS."""
    monkeypatch.delenv("PII_ALLOWED_WORDS", raising=False)
    assert allowed_stems() == ()
    assert not is_allowed_fragment("Прагматика")
    assert strip_allowed_words("из Прагматики") == "из Прагматики"


def test_extra_words_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PII_ALLOWED_WORDS", "Альф, Омег")
    assert is_allowed_fragment("Альфой") and not is_allowed_fragment("Бета")


def test_strip_keeps_positions(monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, "labops")
    text = "Иванов из Прагматики"
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
    use_env_set(monkeypatch, "pragmatika")
    from labops_pii.detector import PiiDetector

    text = "Иванов Иван Иванович из Прагматики"
    found = [text[d.start:d.end] for d in PiiDetector().detect(text) if d.pii_type == "PERSON"]
    assert found and all("Прагматик" not in f for f in found)


@pytest.mark.parametrize("name", sorted(ENV_SETS))
def test_guard_does_not_flag_project_name(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    use_env_set(monkeypatch, name)
    monkeypatch.setenv("PII_GUARD_NAMES_MODE", "enforce")
    from labops_pii.guard import detector

    for text in [*FORMS, *SENTENCES]:
        assert "name" not in detector.find_pii_types(text), text
