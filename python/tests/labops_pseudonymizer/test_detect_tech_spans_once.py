"""Технические токены считаются один раз на `detect`, результат не меняется."""

from __future__ import annotations

import pytest

import labops_pii.detector as detector_module
from labops_pii.detector import Detection, PiiDetector
from labops_pii.detector import _resolve_overlaps, _with_preposition_genders
from labops_pii.morph import request_cache
from labops_pii.tech_tokens import find_tech_spans

KNOWN_LEMMAS = {"иванов", "петров"}
TEXTS = [
    "Позвоните Иванову Ивану Ивановичу по телефону +7 912 345-67-89, почта ivanov@mail.ru.",
    "Файл Иванов_Иван_договор.pdf лежит в C:\\Документы\\Петров\\счёт_Сидоров.xlsx.",
    "См. /srv/share/Петрова_О.И/прайс-лист.xlsx и отчёт_Сидорова.docx, подписал Петров А.Б.",
    "ИВАНОВ ИВАН ИВАНОВИЧ и иванов и.и. согласовали акт_сверки_Петров.pdf вчера.",
    "Обычный текст без ФИО и технических токенов, только цены 100 500 руб.",
    "",
]


def _reference_detect(
    detector: PiiDetector, text: str, known_lemmas: set[str]
) -> list[Detection]:
    """Прежнее поведение: каждый детектор получает свежий результат `find_tech_spans`."""
    found: list[Detection] = []
    with request_cache():
        norm = detector_module.normalize_text(text)
        found += detector._detect_ip(text, norm)
        found += detector._detect_email(norm)
        found += detector._detect_phone(norm)
        found += detector._detect_numbers(norm)
        found += detector._detect_contacts(text, norm)
        found += detector._detect_persons(text, find_tech_spans(text))
        found += detector._detect_latin_names(text)
        found += detector._detect_case_shifted_persons(text, find_tech_spans(text))
        found += detector._detect_initialed_surnames(text, find_tech_spans(text))
        found += detector._detect_known_names(text, known_lemmas, find_tech_spans(text))
        found += detector._detect_tech_names(text, find_tech_spans(text), known_lemmas)
        return _with_preposition_genders(text, _resolve_overlaps(found, text))


@pytest.mark.parametrize("text", TEXTS)
def test_detect_matches_per_detector_spans(detector: PiiDetector, text: str) -> None:
    """Общий список диапазонов даёт те же находки, что отдельный пересчёт в каждом детекторе."""
    assert detector.detect(text, KNOWN_LEMMAS) == _reference_detect(detector, text, KNOWN_LEMMAS)


@pytest.mark.parametrize("text", TEXTS)
def test_find_tech_spans_called_once(
    detector: PiiDetector, text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """За один `detect` `find_tech_spans` вызывается не больше одного раза."""
    calls: list[int] = []

    def counting(value: str) -> list[tuple[int, int]]:
        calls.append(1)
        return find_tech_spans(value)

    monkeypatch.setattr(detector_module, "find_tech_spans", counting)
    detector.detect(text, KNOWN_LEMMAS)
    assert len(calls) == 1
