"""Тесты детектора: каждый тип ПДн, ИП против юрлица, ложные срабатывания."""

from __future__ import annotations

import pytest

from labops_pii import checksums
from labops_pii.detector import PiiDetector, PiiType
from tests.pragmatika_pseudonymizer.conftest import found

VALID_INN10 = "7707083893"
VALID_INN12 = "500100732259"
VALID_OGRN = "1027700132195"
VALID_OGRNIP = "304500116000157"


def test_checksums_known_values() -> None:
    assert checksums.is_valid_inn(VALID_INN10)
    assert checksums.is_valid_inn(VALID_INN12)
    assert not checksums.is_valid_inn("7707083894")
    assert checksums.is_valid_ogrn(VALID_OGRN)
    assert checksums.is_valid_ogrnip(VALID_OGRNIP)
    assert checksums.is_valid_snils("11223344595")
    assert not checksums.is_valid_snils("11223344596")


@pytest.mark.parametrize(
    "phone",
    [
        "+7 (902) 123-45-67",
        "8 902 123 45 67",
        "89021234567",
        "+79021234567",
        "8-902-123-45-67",
        "8 (902) 123-45-67",
        "(902) 123-45-67",
        "902-123-45-67",
    ],
)
def test_phone_formats(detector: PiiDetector, phone: str) -> None:
    text = f"Звоните по номеру {phone} после обеда"
    assert found(detector, text) == [("PHONE", phone)]


def test_email(detector: PiiDetector) -> None:
    text = "Пишите на Sales.Dept+rfq@Supplier-Group.ru, ответим."
    assert found(detector, text) == [("EMAIL", "Sales.Dept+rfq@Supplier-Group.ru")]


def test_inn_person_always_masked(detector: PiiDetector) -> None:
    text = f"ИНН {VALID_INN12}"
    assert found(detector, text) == [("INN", VALID_INN12)]


def test_inn_without_checksum_ignored(detector: PiiDetector) -> None:
    assert found(detector, "Артикул 1234567890 на складе") == []


def test_snils(detector: PiiDetector) -> None:
    assert found(detector, "СНИЛС 112-233-445 95") == [("SNILS", "112-233-445 95")]


def test_passport(detector: PiiDetector) -> None:
    assert found(detector, "паспорт 4510 123456 выдан") == [("PASSPORT", "4510 123456")]
    assert found(detector, "паспорт серия 45 10 № 123456")[0][0] == "PASSPORT"
    assert found(detector, "паспорт 4510123456")[0][0] == "PASSPORT"


def test_ogrnip_masked_by_default(detector: PiiDetector) -> None:
    assert found(detector, f"ОГРНИП {VALID_OGRNIP}") == [("OGRNIP", VALID_OGRNIP)]


def test_legal_entity_numeric_requisites_masked_by_default(detector: PiiDetector) -> None:
    """Числовые реквизиты маскируются всегда, название организации - только по флагу."""
    text = f"ООО «Ромашка», ИНН {VALID_INN10}, ОГРН {VALID_OGRN}"
    assert found(detector, text) == [("INN", VALID_INN10), ("OGRN", VALID_OGRN)]


def test_legal_entity_requisites_flag(legal_detector: PiiDetector) -> None:
    text = f"ООО «Ромашка», ИНН {VALID_INN10}, ОГРН {VALID_OGRN}"
    assert found(legal_detector, text) == [
        ("ORG", "ООО «Ромашка»"),
        ("INN", VALID_INN10),
        ("OGRN", VALID_OGRN),
    ]


def test_ip_masked_entirely_with_inn(detector: PiiDetector) -> None:
    text = f"Поставщик ИП Иванов И.И. ИНН {VALID_INN12} отгрузил цемент"
    assert found(detector, text) == [("PERSON", f"ИП Иванов И.И. ИНН {VALID_INN12}")]


def test_ip_full_name(detector: PiiDetector) -> None:
    text = "Договор с ИП Смирнов Алексей Петрович заключён"
    assert found(detector, text) == [("PERSON", "ИП Смирнов Алексей Петрович")]


def test_ooo_vs_ip_distinct(detector: PiiDetector) -> None:
    text = f"ООО «Альфа» (ИНН {VALID_INN10}) и ИП Сидоров С.С."
    assert found(detector, text) == [("INN", VALID_INN10), ("PERSON", "ИП Сидоров С.С.")]


def test_person_with_initials(detector: PiiDetector) -> None:
    assert found(detector, "Контакт: Сидоров А.В., тел. снизу") == [("PERSON", "Сидоров А.В.")]


def test_imperative_not_part_of_name(detector: PiiDetector) -> None:
    assert found(detector, "Позвони Петрову, пожалуйста") == [("PERSON", "Петрову")]


def test_price_rows_have_no_pii(detector: PiiDetector) -> None:
    rows = [
        "Цемент М500 Д0 50кг мешок | 420,00 | Holcim | 1200 шт | арт. 4510123",
        "Арматура А500С d12 11.7м | 61 500,00 руб/т | ГОСТ 34028-2016",
        "Перфоратор Bosch GBH 2-26 DRE | 18 990,00 | в наличии 14",
        "Кабель ВВГнг(А)-LS 3х2,5 | 78,40 руб/м | бухта 100 м",
    ]
    for row in rows:
        assert found(detector, row) == [], row


def test_contacts_dictionary_exact(contacts_detector: PiiDetector) -> None:
    text = "Передай дядя коля, что вася рабочий уехал, а рабочий день дяди закончился"
    assert found(contacts_detector, text) == [
        ("CONTACT", "дядя коля"),
        ("CONTACT", "вася рабочий"),
    ]


def test_types_enum_covers_expected() -> None:
    assert {t.value for t in PiiType} >= {"PERSON", "PHONE", "EMAIL", "INN", "SNILS", "PASSPORT"}


@pytest.mark.parametrize(
    ("text", "phone"),
    [
        ("тел 999 123 45 67", "999 123 45 67"),
        ("тел. 9991234567", "9991234567"),
        ("прайс_89991234567.xlsx", "89991234567"),
        ("тел89991234567", "89991234567"),
        ("N89991234567", "89991234567"),
        ("моб:9991234567 звонить", "9991234567"),
        ("контакт 999 1234567", "999 1234567"),
    ],
)
def test_phone_without_prefix_and_in_file_names(
    detector: PiiDetector, text: str, phone: str
) -> None:
    """R2-S-4: телефоны без +7/8, с буквами и «_» слева, в именах файлов."""
    assert ("PHONE", phone) in found(detector, text)


@pytest.mark.parametrize(
    "text",
    [
        "Артикул 9991234567 на складе",
        "Заказ 123 456 78 90 принят",
        "Сумма 1 500 000 00 00 руб",
        "Счёт 40702810123456789012 открыт",
        "Дата 12.09.2026 и 3,89991234567",
        "ИНН 7707083893 организации",
        "Позиция 99-12-34 шт",
        "Партия 1234567890123",
    ],
)
def test_phone_not_confused_with_numbers(detector: PiiDetector, text: str) -> None:
    """Артикулы, суммы, счета, ИНН, даты телефоном не считаются."""
    assert all(t != "PHONE" for t, _ in found(detector, text))


def test_default_detector_masks_org_inn_without_word(detector: PiiDetector) -> None:
    """ИНН организации с верной суммой маскируется и без слова «ИНН», и при флаге по умолчанию."""
    assert found(detector, "добавь поставщика ООО Ромашка ИНН 7707083893") == [
        ("INN", VALID_INN10)
    ]
    assert found(detector, f"реквизиты {VALID_INN10} пришли") == [("INN", VALID_INN10)]


def test_default_detector_inn_kpp_and_accounts(detector: PiiDetector) -> None:
    assert found(detector, "ИНН/КПП 7707083893/770701001") == [("INN", VALID_INN10)]
    text = "р/с 40702810123456789012 к/с 30101810400000000225"
    assert found(detector, text) == [
        ("ACCOUNT", "40702810123456789012"),
        ("ACCOUNT", "30101810400000000225"),
    ]
    assert found(detector, f"ОГРН {VALID_OGRN}") == [("OGRN", VALID_OGRN)]


@pytest.mark.parametrize("mask_org", [False, True])
def test_flag_controls_only_organization_names(mask_org: bool) -> None:
    """Набор числовых типов не зависит от флага; ORG появляется только при true."""
    det = PiiDetector(mask_legal_entity_requisites=mask_org)
    text = (
        f"ООО Ромашка ИНН {VALID_INN10} ОГРН {VALID_OGRN} "
        "р/с 40702810123456789012 к/с 30101810400000000225"
    )
    types = [t for t, _ in found(det, text)]
    assert [t for t in types if t != "ORG"] == ["INN", "OGRN", "ACCOUNT", "ACCOUNT"]
    assert ("ORG" in types) is mask_org


@pytest.mark.parametrize(
    "text",
    [
        "арт. 1234567890",
        "Артикул 4510123456",
        "Артикул 452000123456 в наличии",
        "Позиция 1234567890 | 1 234 567,89 | шт",
        "Позиция 123456789012 | 15 шт",
        "Труба длинная 1234567890 мм",
        "Труба Длинный 1234567890 мм",
    ],
)
def test_articles_without_checksum_and_keyword_not_masked(
    detector: PiiDetector, text: str
) -> None:
    assert found(detector, text) == []


def test_keyword_needs_left_word_boundary(detector: PiiDetector) -> None:
    """«инн» внутри слова ключевым не считается, а «ИНН1234…» и «ИНН:1234…» - считается."""
    assert found(detector, "Труба длинная 1234567890 мм") == []
    assert found(detector, "ИНН1234567890") == [("INN", "1234567890")]
    assert found(detector, "ИНН:1234567890") == [("INN", "1234567890")]
    assert found(detector, "ИНН 1234567890") == [("INN", "1234567890")]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("загранпаспорт 4512345678", [("PASSPORT", "4512345678")]),
        ("Загранпаспорт: 4512345678", [("PASSPORT", "4512345678")]),
        ("внутренний паспорт 4512345678", [("PASSPORT", "4512345678")]),
        ("паспорт 4512345678", [("PASSPORT", "4512345678")]),
        ("СНИЛС11223344595", [("SNILS", "11223344595")]),
        ("загранпаспортсерия 4512345678", [("PASSPORT", "4512345678")]),
    ],
)
def test_keyword_without_left_boundary_except_inn(
    detector: PiiDetector, text: str, expected: list[tuple[str, str]]
) -> None:
    """Левая граница нужна только «инн»: «загранпаспорт 4512345678» находится, как до этапа."""
    assert found(detector, text) == expected


def test_inn_keyword_inside_word_still_not_keyword(detector: PiiDetector) -> None:
    """«инн» внутри слов («длинная», «машинная») ключевым не считается, а у «ИНН» - да."""
    assert found(detector, "машинная деталь 1234567890") == []
    assert found(detector, "ИНН 1234567890") == [("INN", "1234567890")]


@pytest.mark.parametrize(
    "text",
    ["арт.7707083893 цена", "сумма 1,7707083893", "п.1.7707083893"],
)
def test_ten_digits_after_separator_are_checked_like_pii_guard(
    detector: PiiDetector, text: str
) -> None:
    """Левая граница как у pii-guard: число с верной суммой после «.» и «,» маскируется."""
    assert found(detector, text) == [("INN", "7707083893")]


def test_ean13_is_not_ogrn_without_keyword(detector: PiiDetector) -> None:
    """Номер с верной «ОГРН»-суммой, но не на 1/5 без слова «ОГРН» - штрихкод, не реквизит."""
    assert found(detector, "Штрихкод 4600000000002") == []
    assert found(detector, "ОГРН 4600000000002") == [("OGRN", "4600000000002")]
    assert found(detector, "Номер 5000000000006") == [("OGRN", "5000000000006")]
    assert found(detector, f"Номер {VALID_OGRN}") == [("OGRN", VALID_OGRN)]
