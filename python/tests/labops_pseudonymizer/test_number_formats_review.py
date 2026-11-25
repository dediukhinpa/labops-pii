"""ПДн в записи, которая уходила открытой: цифры, контакты, латиница (ревью и матрица 25.11.2026).

Номера вымышленные; ИНН, карты и счета подобраны с верной контрольной суммой.
"""

from __future__ import annotations

import time

import pytest

from labops_pii.detector import PiiDetector
from labops_pii.guard.detector import find_pii_types
from labops_pii.service import Pseudonymizer

# Предел на враждебный ряд пробелов: прежний шаблон паспорта давал секунды
HOSTILE_SPACES = 64_000
HOSTILE_SECONDS = 2.0


def _types(detector: PiiDetector, text: str) -> list[tuple[str, str]]:
    return [(d.pii_type.value, text[d.start:d.end]) for d in detector.detect(text)]


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("Паспорт серия 4510, номер 123456", "4510, номер 123456"),
        ("Паспорт: серия 4510 номер: 123456", "4510 номер: 123456"),
        ("паспорт 4510-123456", "4510-123456"),
        ("Серия: 45 10, № 123456", "45 10, № 123456"),
    ],
)
def test_passport_with_punctuation_near_keyword(
    detector: PiiDetector, text: str, fragment: str
) -> None:
    assert ("PASSPORT", fragment) in _types(detector, text)


def test_passport_punctuation_without_keyword_is_not_passport(detector: PiiDetector) -> None:
    assert all(t != "PASSPORT" for t, _ in _types(detector, "Заказ 4510-123456 отгружен"))


def test_passport_pattern_is_linear_on_hostile_spaces(detector: PiiDetector) -> None:
    started = time.perf_counter()
    detector.detect("1234" + " " * HOSTILE_SPACES + "x")
    assert time.perf_counter() - started < HOSTILE_SECONDS


def test_inn_in_groups_after_keyword(detector: PiiDetector) -> None:
    assert _types(detector, "ИНН 5497 0940 0950") == [("INN", "5497 0940 0950")]
    # без слова «ИНН» группы цифр - не ИНН
    assert _types(detector, "Код 5497 0940 0950") == []


@pytest.mark.parametrize(
    "text",
    ["р/с 4070 2810 1380 0002 2345", "р/с 4081 7810 0999 1000 4313"],
)
def test_account_in_groups_of_four(detector: PiiDetector, text: str) -> None:
    found = _types(detector, text)
    assert [frag for _, frag in found] == [text[len("р/с "):]]
    assert "account" in find_pii_types(text)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("+7 916 12 345 67", "+7 916 12 345 67"),
        ("тел. 8 916 1234 567", "8 916 1234 567"),
        ("Телефон: 8 916 12-34-567", "8 916 12-34-567"),
    ],
)
def test_phone_in_unusual_grouping(detector: PiiDetector, text: str, fragment: str) -> None:
    assert _types(detector, text) == [("PHONE", fragment)]
    assert "phone" in find_pii_types(text)


@pytest.mark.parametrize(
    "text",
    ["арт. 8 916 12 34 567", "Заказ 2026-11-25, 9161234 шт", "сумма 8 916 12 34 567 руб"],
)
def test_unusual_grouping_without_plus7_or_keyword_is_not_phone(
    detector: PiiDetector, text: str
) -> None:
    assert all(t != "PHONE" for t, _ in _types(detector, text))


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("звоните 8/916/123/45/67 в любое время", "phone"),
        ("тел 8/916/123/45/67 г. Москва", "phone"),
        ("карта 4276/1600/1234/5675", "card"),
        ("счёт 40817/810/0/9991/0004312 в банке", "account"),
    ],
)
def test_guard_does_not_split_pii_written_with_slashes(text: str, kind: str) -> None:
    """«в» (как «В», вольт) и «г.» после номера не делают его списком размеров."""
    assert kind in find_pii_types(text)


@pytest.mark.parametrize("text", ["Кружка 425/660/1000 мл", "Объём 425/660/10/20 мл"])
def test_guard_still_splits_size_lists(text: str) -> None:
    assert "phone" not in find_pii_types(text)


@pytest.mark.parametrize(
    "text",
    [
        "Паспорт серия 4510, номер 123456",
        "ИНН 5497 0940 0950",
        "р/с 4081 7810 0999 1000 4313",
        "+7 916 12 345 67",
    ],
)
def test_new_formats_round_trip(service: Pseudonymizer, text: str) -> None:
    masked, _ = service.pseudonymize("n", text)
    assert not any(ch.isdigit() for ch in masked.replace("_1]", "]"))
    assert service.restore("n", masked) == text


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("Профиль: https://vk.com/ivan.petrov88.", "https://vk.com/ivan.petrov88"),
        ("instagram.com/ivan_petrov88", "instagram.com/ivan_petrov88"),
        ("https://vk.com/id123456789", "https://vk.com/id123456789"),
    ],
)
def test_social_profile_links_are_contacts(
    detector: PiiDetector, text: str, fragment: str
) -> None:
    assert _types(detector, text) == [("CONTACT", fragment)]


def test_social_domain_inside_other_url_is_not_contact(detector: PiiDetector) -> None:
    assert _types(detector, "Смотрите https://example.com/vk.com/x") == []


@pytest.mark.parametrize(
    "text",
    [
        "ivan.petrov [at] mail.ru",
        "ivan.petrov @ mail.ru",
        "ivan.petrov собака mail.ru",
        "Пишите: ivan.petrov(at)yandex.ru.",
    ],
)
def test_email_written_around_at_sign(service: Pseudonymizer, text: str) -> None:
    masked, _ = service.pseudonymize("o", text)
    assert "ivan.petrov" not in masked
    assert service.restore("o", masked) == text
    assert "email" in find_pii_types(text)


def test_email_around_at_sign_shares_token_with_plain_form(service: Pseudonymizer) -> None:
    plain, _ = service.pseudonymize("o2", "ivan.petrov@mail.ru")
    obfuscated, _ = service.pseudonymize("o2", "ivan.petrov [at] mail.ru")
    assert plain == obfuscated == "[EMAIL_1]"


@pytest.mark.parametrize("text", ["look at example.com", "цена 5 @ file.txt", "skype для бизнеса"])
def test_phrases_are_not_email_or_skype(detector: PiiDetector, text: str) -> None:
    assert _types(detector, text) == []


@pytest.mark.parametrize(
    ("text", "login"),
    [
        ("skype: ivan.petrov88", "ivan.petrov88"),
        ("Скайп - live:ivan_p88, звоните", "live:ivan_p88"),
    ],
)
def test_skype_login_is_contact(detector: PiiDetector, text: str, login: str) -> None:
    assert _types(detector, text) == [("CONTACT", login)]


def test_email_pattern_is_fast_on_long_words(detector: PiiDetector) -> None:
    started = time.perf_counter()
    detector.detect(("a" * 60 + " ") * 1000 + "@ " * 1000)
    find_pii_types(("a" * 60 + " @ ") * 1000)
    assert time.perf_counter() - started < HOSTILE_SECONDS


@pytest.mark.parametrize(
    ("text", "fragment"),
    [("Contact: Hans Müller", "Hans Müller"), ("HANS MÜLLER", "HANS MÜLLER")],
)
def test_latin_name_with_diacritics(detector: PiiDetector, text: str, fragment: str) -> None:
    assert _types(detector, text) == [("PERSON", fragment)]


@pytest.mark.parametrize("text", ["Über den Fluss", "Straße Bäckerei"])
def test_latin_words_with_diacritics_are_not_names(detector: PiiDetector, text: str) -> None:
    assert _types(detector, text) == []


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("тел 9161234567", "PHONE"),  # сумма ИНН сходится случайно: после «тел» это телефон
        ("ИНН 9161234567", "INN"),
        ("Реквизиты: 7707083893", "INN"),
    ],
)
def test_phone_keyword_beats_checksum_only_inn(
    detector: PiiDetector, text: str, kind: str
) -> None:
    assert [t for t, _ in _types(detector, text)] == [kind]
