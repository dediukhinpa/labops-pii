"""Свойство restore(pseudonymize(x)) == x и регрессии по границам замены (этап 8A)."""

from __future__ import annotations

import re

import pytest

from labops_pii.service import Pseudonymizer
from tests.pragmatika_pseudonymizer.recall_sets import CAPS_CLEAN, CAPS_PII, EASY, FILES_CLEAN, FILES_PII, HARD, score

# Реалистичные строки: имена файлов, пути, JSON, строки прайса, письма, слова через «_ - .».
ROUNDTRIP_STRINGS: list[str] = [
    "Металлопрокат_прайс.xlsx",
    '{"path":"Металлопрокат_прайс.xlsx"}',
    "Металлопрокат",
    "Металлопрокат_прайс",
    "прайс_Металлопрокат_Сибирь_2026.xlsx",
    "Договор_поставки_Иванов_И.И.docx",
    "Счёт-фактура_№123_от_01.09.2026.pdf",
    "/home/user/Документы/Прайсы/Металлопрокат_прайс.xlsx",
    "C:\\Users\\Менеджер\\Загрузки\\Спецификация_Арматура.docx",
    "./out/Сводная-таблица.Закупки.csv",
    '{"files":["Прайс_Альфа.xlsx","Прайс_Бета.xlsx"],"owner":"Сидоров А.В."}',
    '{"name": "Иванов Пётр", "phone": "+7 (902) 123-45-67", "file": "КП_Иванов.pdf"}',
    '{"text":"позвони Петрову, +7 (902) 123-45-67"}',
    "Цемент М500 Д0 50кг мешок | 420,00 | Holcim | 1200 шт | арт. 4510123",
    "Арматура А500С d12 11.7м | 61 500,00 руб/т | ГОСТ 34028-2016",
    "Кабель ВВГнг(А)-LS 3х2,5 | 78,40 руб/м | бухта 100 м",
    "Металлопрокат Сибирь | Лист г/к 3 мм | 58 400 руб/т",
    "Поставщик Металлопрокат прислал прайс_июнь.xlsx",
    "Вложение: Металлопрокат_прайс.xlsx (2 МБ)",
    "Файл Иванов_прайс.xlsx готов",
    "Здравствуйте, Мария Петровна!\nПросим выставить счёт, файл прайс_2026.xlsx в приложении.",
    "С уважением, Сидоров А.В., тел. 8-902-555-12-34, sidorov@buildco.ru",
    "Контакт: Кузнецов Алексей Петрович, файл Кузнецов_договор.docx",
    "позвони Петрову, +7 (902) 123-45-67",
    "ИП Орлов О.О. ИНН 500100732259 прислал Орлов_счёт.pdf",
    "Письмо отправлено на sales.dept@metalloprokat-group.ru, копия в Металлопрокат_архив",
    "См. отчёт my_report_final.v2.xlsx и Отчёт-итоговый.docx",
    "snake_case_слово и kebab-case-слово и dotted.слово.тут",
    "https://example.com/files/Металлопрокат_прайс.xlsx?download=1",
    "Тендер_№5 / Лот-3 / Позиция.7",
    "Закупка: Металлопрокат, Стройматериалы_опт, Крепёж-Центр.",
    "",
    "   ",
    "Просто текст без ПДн.",
]


@pytest.mark.parametrize("text", ROUNDTRIP_STRINGS)
def test_roundtrip_fresh_thread(service: Pseudonymizer, text: str) -> None:
    out, _ = service.pseudonymize("rt", text)
    assert service.restore("rt", out) == text


def test_roundtrip_whole_set_in_one_thread(service: Pseudonymizer) -> None:
    """Все строки подряд в одном треде: токены накапливаются, round-trip держится.

    Исключение по дизайну: разные формы одного ФИО делят токен, и `/restore` отдаёт форму,
    встретившуюся первой (см. README), поэтому строгое равенство проверяем для строк,
    где в треде нет другой формы того же человека, а для остальных — на свежем треде
    (`test_roundtrip_fresh_thread`). Главное здесь — хвосты и «съеденные» куски не появляются.
    """
    for text in ROUNDTRIP_STRINGS:
        out, entities = service.pseudonymize("rt", text)
        restored = service.restore("rt", out)
        if not any(e.type == "PERSON" for e in entities):
            assert restored == text, text
        else:
            assert len(restored) <= len(text) + 40, text  # без разрастания «_прайс_прайс»


def test_regression_three_steps_one_thread(service: Pseudonymizer) -> None:
    """Дефект e2e: три вызова одного треда давали 'Металлопрокат_прайс_прайс.xlsx'."""
    plain = "Металлопрокат_прайс.xlsx"
    as_json = '{"path":"Металлопрокат_прайс.xlsx"}'
    out1, _ = service.pseudonymize("t", plain)
    out2, _ = service.pseudonymize("t", as_json)
    assert "прайс" in out1 and "прайс" in out2  # хвост «_прайс» не съеден токеном
    assert service.restore("t", out1) == plain
    assert service.restore("t", out2) == as_json
    assert service.restore("t", "[PERSON_1]_прайс.xlsx") == "[PERSON_1]_прайс.xlsx"


def test_regression_known_name_inside_underscore_word(service: Pseudonymizer) -> None:
    """Фамилия в слове через «_» заменяется целым словом; разделитель и хвост остаются."""
    service.pseudonymize("t", "Иванов Пётр прислал счёт")
    text = "Иванов_прайс.xlsx и Иванов Пётр"
    out, _ = service.pseudonymize("t", text)
    assert out == "[PERSON_2]_прайс.xlsx и [PERSON_1]"
    assert service.restore("t", out) == text


def test_replaced_fragment_equals_stored_original(service: Pseudonymizer) -> None:
    """Оригинал токена — ровно заменённый фрагмент, без хвостов."""
    text = "Передай Сидорову А.В._прайс и Кузнецов К.К. ждёт"
    out, _ = service.pseudonymize("t", text)
    assert service.restore("t", out) == text


@pytest.mark.parametrize(
    "text",
    [
        "Металлопрокат_прайс.xlsx",
        "Прайс_Металлопрокат.xlsx",
        "Металлопрокат",
        "Поставщик Металлопрокат прислал прайс",
        "Металлопрокат Сибирь",
        "/srv/data/Металлопрокат/прайс.xlsx",
        "отчёт Спецификация_Арматура.docx",
        "Закупки_Урал_2026.pdf",
    ],
)
def test_no_false_positive_on_files_and_companies(service: Pseudonymizer, text: str) -> None:
    out, entities = service.pseudonymize("t", text)
    assert out == text and entities == []


def _fresh(service: Pseudonymizer, text: str) -> str:
    import uuid

    return service.pseudonymize(str(uuid.uuid4()), text)[0]


def test_recall_easy_set_not_degraded(service: Pseudonymizer) -> None:
    hit, total = score(lambda t: _fresh(service, t), EASY)
    assert (hit, total) >= (35, 37)  # базовый замер до правки: 35 из 37


def test_recall_hard_set_not_degraded(service: Pseudonymizer) -> None:
    hit, total = score(lambda t: _fresh(service, t), HARD)
    assert (hit, total) >= (33, 34)  # базовый замер до правки: 33 из 34


def test_recall_files_with_names(service: Pseudonymizer) -> None:
    """ФИО внутри имён файлов и путей маскируется (замер без разбора частей: 0 из 26)."""
    hit, total = score(lambda t: _fresh(service, t), FILES_PII)
    assert hit == total, (hit, total)


@pytest.mark.parametrize("text", [t for t, _ in FILES_PII])
def test_files_with_names_roundtrip_and_separators(service: Pseudonymizer, text: str) -> None:
    out, _ = service.pseudonymize("f", text)
    assert service.restore("f", out) == text
    # заменены только слова ФИО: «каркас» из разделителей и остальных слов сохранён
    skeleton = re.sub(r"\[PERSON_\d+\]", "§", out)
    assert len(skeleton) <= len(text)


@pytest.mark.parametrize("text", FILES_CLEAN)
def test_files_without_names_untouched(service: Pseudonymizer, text: str) -> None:
    out, entities = service.pseudonymize("f", text)
    assert out == text and entities == []


def test_file_name_exact_forms_same_token_and_restore(service: Pseudonymizer) -> None:
    """Тот же ФИО в имени файла и в тексте: токен общий, если написание совпадает."""
    out, _ = service.pseudonymize("f", "Файл Иванов_договор.docx и звонил Иванов Пётр")
    assert out == "Файл [PERSON_1]_договор.docx и звонил [PERSON_2]"  # «Иванов» ≠ «Иванов Пётр»
    plain, _ = service.pseudonymize("f", "Иванов Пётр")
    assert plain == "[PERSON_2]" and service.restore("f", plain) == "Иванов Пётр"
    out2, _ = service.pseudonymize("f", "Иванов_договор.docx ещё раз")
    assert out2.startswith("[PERSON_1]_договор.docx")
    assert service.restore("f", out2) == "Иванов_договор.docx ещё раз"


def test_file_name_different_form_not_corrupted(service: Pseudonymizer) -> None:
    """Имя файла не получает форму ФИО из письма («Иванов И.И._договор.docx»)."""
    letter, _ = service.pseudonymize("f", "Контакт: Иванов И.И.")
    name, _ = service.pseudonymize("f", "Иванов_договор.docx")
    assert service.restore("f", letter) == "Контакт: Иванов И.И."
    assert service.restore("f", name) == "Иванов_договор.docx"


def test_recall_caps_names(service: Pseudonymizer) -> None:
    """ФИО заглавными и строчными скрываются (замер до правки R2-S-1: 4 из 24)."""
    hit, total = score(lambda t: _fresh(service, t), CAPS_PII)
    assert hit == total, (hit, total)


@pytest.mark.parametrize("text", CAPS_CLEAN)
def test_caps_organizations_not_masked(service: Pseudonymizer, text: str) -> None:
    out, entities = service.pseudonymize("c", text)
    assert out == text and entities == []


def test_caps_names_roundtrip(service: Pseudonymizer) -> None:
    for text in ("Подписал ИВАНОВ ИВАН ИВАНОВИЧ", "ответил иванов и.и. вчера"):
        out, _ = service.pseudonymize(text, text)
        assert "ИВАНОВ" not in out and "иванов" not in out
        assert service.restore(text, out) == text


def test_caps_detection_linear_and_limit(service: Pseudonymizer) -> None:
    """Длинный текст из слов заглавными обрабатывается за разумное время."""
    import time

    text = ("ИВАНОВ " * 5000 + "СТАЛЬ СЕРВИС " * 3000)[:70_000]
    started = time.monotonic()
    service.pseudonymize("lin", text)
    assert time.monotonic() - started < 30


def test_roundtrip_org_requisites_by_default(service: Pseudonymizer) -> None:
    """ИНН организации, счёт и ОГРН маскируются при умолчании и возвращаются без искажений."""
    text = (
        "ООО «Ромашка», ИНН 7707083893, ОГРН 1027700132195, "
        "р/с 40702810123456789012, к/с 30101810400000000225"
    )
    out, _ = service.pseudonymize("t-req", text)
    for secret in ("7707083893", "1027700132195", "40702810123456789012", "30101810400000000225"):
        assert secret not in out
    assert service.restore("t-req", out) == text
    args = '{"inn":"[INN_1]","ogrn":"[OGRN_1]"}'
    assert service.restore("t-req", args) == '{"inn":"7707083893","ogrn":"1027700132195"}'
