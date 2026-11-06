"""Тесты детектора ПДн."""

import pytest

from labops_pii.guard.detector import find_pii_types, is_valid_inn, is_valid_snils, scan_body

# Синтетические значения с корректной контрольной суммой (не реальные лица)
INN10 = "7707083893"
INN12 = "500100732259"
SNILS = "112-233-445 95"


@pytest.mark.parametrize(
    "text",
    [
        "звоните +7 (916) 123-45-67",
        "тел 8 916 123 45 67",
        "89161234567",
        "+79161234567",
    ],
)
def test_phone_found(text: str) -> None:
    assert "phone" in find_pii_types(text)


def test_email_found() -> None:
    assert find_pii_types("пишите ivan.petrov@example.ru срочно") == {"email"}


def test_inn_valid_checksum() -> None:
    assert is_valid_inn(INN10)
    assert is_valid_inn(INN12)
    assert find_pii_types(f"ИНН {INN10}") == {"inn"}
    assert find_pii_types(f"ИНН {INN12}") == {"inn"}


def test_inn_bad_checksum_ignored() -> None:
    assert find_pii_types("номер 7707083890") == set()


def test_snils() -> None:
    assert is_valid_snils("11223344595")
    assert "snils" in find_pii_types(SNILS)
    assert "snils" in find_pii_types("11223344595")
    assert find_pii_types("СНИЛС 112-233-445 96") == set()


def test_tokens_pass() -> None:
    text = "Контакт [PERSON_1], тел [PHONE_2], почта [EMAIL_3], ИНН [INN_4]"
    assert find_pii_types(text) == set()


def test_clean_text_with_ordinary_numbers() -> None:
    text = "Заказ 12345, 250 шт, цена 1999.90 руб, артикул AB-100500"
    assert find_pii_types(text) == set()


def test_json_unicode_escape_not_hiding() -> None:
    body = b'{"messages":[{"content":"\\u0442\\u0435\\u043b +7 916 123 45 67"}]}'
    assert "phone" in scan_body(body)


def test_nested_json_and_number() -> None:
    body = b'{"a":{"b":["x", {"c": "mail me: a@b.com"}]}}'
    assert scan_body(body) == {"email"}


def test_non_json_scanned() -> None:
    assert scan_body("ИНН 7707083893".encode()) == {"inn"}


def test_invalid_utf8_does_not_crash() -> None:
    assert scan_body(b"\xff\xfe +79161234567") == {"phone"}


# --- Регрессии S-04: email без суперлинейного времени ---

# Худший замер после правки: 0,5 с на 1 МБ; предел с запасом x5
PATHOLOGICAL_BYTES = 1_000_000
TIME_LIMIT_SECONDS = 2.5


@pytest.mark.parametrize(
    "text",
    [
        "a@b.co",
        "ivan.petrov+tag@mail.example.ru",
        "x_y%z@sub-domain.example-site.com.",
        "see <a@b.cc>, ok",
        "a@b.c.dd",
        "A@B.COM",
        "@@a@b.cc",
        "a" * 200 + "@example.com",  # длинная локальная часть: хвост всё равно найден
    ],
)
def test_email_found_variants(text: str) -> None:
    assert find_pii_types(text) == {"email"}


@pytest.mark.parametrize(
    "text",
    [
        "a@b",
        "a@b.c",
        "@example.com",
        "a@.example.com",
        "a@b..com",
        "a @b.com",
        "user@123.456",
        "a@" + "z" * 300 + ".com",  # домен длиннее 255 не по RFC
    ],
)
def test_email_not_found_variants(text: str) -> None:
    assert "email" not in find_pii_types(text)


def test_email_found_after_pathological_prefix() -> None:
    assert "email" in find_pii_types("a." * 5000 + "@x.ru")


@pytest.mark.parametrize(
    "unit",
    ["a", "a.", "a@", "1 ", "123-", "a-", "[A_", "7 ", ("a" * 60) + "@"],
)
def test_pathological_body_is_fast(unit: str) -> None:
    import time

    body = (unit * (PATHOLOGICAL_BYTES // len(unit))).encode()
    start = time.perf_counter()
    scan_body(body)
    assert time.perf_counter() - start < TIME_LIMIT_SECONDS


def test_pathological_domain_is_fast() -> None:
    import time

    body = ("x@" + "b." * (PATHOLOGICAL_BYTES // 2)).encode()
    start = time.perf_counter()
    scan_body(body)
    assert time.perf_counter() - start < TIME_LIMIT_SECONDS


def test_scan_limit_fail_closed() -> None:
    from labops_pii.guard import detector

    with pytest.raises(detector.BodyTooLargeError):
        scan_body(b"x" * 11, max_bytes=10)
    assert scan_body(b"x" * 10, max_bytes=10) == set()


def test_scan_limit_default_equals_default_body_limit() -> None:
    """Один источник истины: без явного предела действует предел тела по умолчанию."""
    from labops_pii.guard.edge import app
    from labops_pii.guard import detector

    assert app.DEFAULT_MAX_BODY == detector.DEFAULT_MAX_SCAN_BYTES
    assert not hasattr(detector, "MAX_SCAN_BYTES")  # отдельного зашитого предела больше нет


def test_all_types_still_detected_in_one_body() -> None:
    text = f"тел 8 916 123 45 67, a@b.ru, ИНН {INN10}, СНИЛС {SNILS}"
    assert find_pii_types(text) == {"phone", "email", "inn", "snils"}


# --- Хеши и UUID не исключаются из проверки (детектор намеренно строгий) ---

# Синтетические значения: случайные цифры внутри дают ИНН/СНИЛС/телефон. Вырезать «похожее
# на хеш» нельзя: так же выглядит ИНН, приклеенный к hex-строке. Строки с длинными цифровыми
# сериями не должно отправлять модели само ядро.
HASH_WITH_INN = "2790bb018cd5d187a9fda2ef65322a48cbbc6c9419f48c75687dd5121032888d"
HASH_WITH_SNILS = "5d35b0b9601e21f2cf8442ea04f304b2d15deeccb7427c20819162454d31d862"
UUID_WITH_PHONE = "a4c4aff9-4ab6-44d8-8053-5688084e5c92"
HEX_GLUED_INN = "deadbeefdeadbeefdeadbe7707083893"  # 22 hex-символа и ИНН 7707083893


def test_inn_glued_to_hex_string_is_found() -> None:
    """Регрессия: маскирование «хешей» прятало ИНН в конце 32-символьной hex-строки."""
    assert find_pii_types(HEX_GLUED_INN) == {"inn"}
    assert scan_body(f'{{"id": "{HEX_GLUED_INN}"}}'.encode()) == {"inn"}
    assert scan_body(f'{{"fileHash": "sha:{HEX_GLUED_INN}"}}'.encode()) == {"inn"}


@pytest.mark.parametrize(
    ("token", "expected"),
    [(HASH_WITH_INN, "inn"), (HASH_WITH_SNILS, "snils"), (UUID_WITH_PHONE, "phone")],
)
def test_hash_and_uuid_with_digit_runs_are_reported(token: str, expected: str) -> None:
    """Ожидаемое срабатывание: цифровая серия в хеше или UUID неотличима от ПДн."""
    assert expected in find_pii_types(token)
    assert expected in scan_body(f'{{"fileHash": "{token}", "id": "x:{token}"}}'.encode())


def test_pii_next_to_hash_is_found() -> None:
    assert "inn" in find_pii_types(f"{HASH_WITH_INN} ИНН {INN10}")
    assert "phone" in find_pii_types(f"{UUID_WITH_PHONE} звоните +7 916 123 45 67")
    assert "email" in find_pii_types(f"{HASH_WITH_INN}@example.ru")


def test_short_digit_runs_in_words_still_found() -> None:
    assert find_pii_types(f"id{INN10}") == {"inn"}
    assert find_pii_types(f"abcdef-{INN12}-abcdef") == {"inn"}


# --- R2-S-2: тело, которое не разобралось как JSON, не обходит проверку ---

PHONE_ESCAPED_JSON = '{"c":"\\u0442\\u0435\\u043b +7 916 123 45 67"}'



def test_utf8_bom_with_escaped_phone() -> None:
    body = b"\xef\xbb\xbf" + PHONE_ESCAPED_JSON.encode()
    assert "phone" in scan_body(body)


def test_giant_integer_does_not_hide_escaped_phone() -> None:
    body = ('{"n": ' + "0" * 5000 + ', "c": "\\u0034\\u0034 +7 916 123 45 67"}').encode()
    assert "phone" in scan_body(body)
    escaped_only = ('{"n": ' + "0" * 5000 + ', "c": "\\u002b79161234567"}').encode()
    assert "phone" in scan_body(escaped_only)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le"])
def test_utf16_and_utf32_bodies_decoded(encoding: str) -> None:
    plain = '{"c": "звоните +7 916 123 45 67"}'.encode(encoding)
    assert "phone" in scan_body(plain)
    escaped = PHONE_ESCAPED_JSON.encode(encoding)
    assert "phone" in scan_body(escaped)


def test_utf16_with_inn_in_value() -> None:
    assert "inn" in scan_body(f'{{"c": "ИНН {INN10}"}}'.encode("utf-16"))


def test_broken_json_still_expands_unicode_escapes() -> None:
    body = b'{"c": "\\u002b7 916 123 45 67", broken'
    assert "phone" in scan_body(body)


def test_escaped_surrogate_pair_and_digits_expanded() -> None:
    body = b'{"c": "\\ud83d\\ude00 \\u0038\\u0039161234567"}'
    assert "phone" in scan_body(body)


def test_duplicate_keys_do_not_hide_first_value() -> None:
    body = b'{"c": "\\u002b79161234567", "c": "ok"}'
    assert "phone" in scan_body(body)


def test_deep_nesting_with_escaped_phone() -> None:
    body = ("[" * 5000 + '"\\u002b79161234567"' + "]" * 5000).encode()
    assert "phone" in scan_body(body)


def test_clean_utf16_and_bom_bodies_pass() -> None:
    assert scan_body('{"c": "привет"}'.encode("utf-16")) == set()
    assert scan_body(b'\xef\xbb\xbf{"c": "hello"}') == set()


# --- R2-S-3: токен-оболочка вырезается только если её выдал псевдонимизатор ---

@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("[INN_500100732259]", {"inn"}),
        ("[PHONE_89991234567]", {"phone"}),
        ("[PHONE_+79161234567]", {"phone"}),
        ("[PHONE_1x] +79161234567", {"phone"}),
        ("[FOO_1] +79161234567", {"phone"}),
    ],
)
def test_fake_token_content_still_detected(text: str, expected: set[str]) -> None:
    assert expected <= find_pii_types(text)


@pytest.mark.parametrize(
    "token",
    ["PERSON", "PHONE", "EMAIL", "INN", "OGRN", "OGRNIP", "SNILS", "PASSPORT", "CONTACT", "ORG"],
)
def test_real_pseudonymizer_tokens_pass(token: str) -> None:
    assert find_pii_types(f"контакт [{token}_1] и [{token}_123456]") == set()


# --- R2-S-4: телефоны без префикса и в именах файлов ---

@pytest.mark.parametrize(
    "text",
    [
        "тел 999 123 45 67",
        "тел. 9991234567",
        "прайс_89991234567.xlsx",
        "тел89991234567",
        "N89991234567",
        "моб:9991234567",
        "999 1234567",
    ],
)
def test_phone_without_prefix_and_in_file_names(text: str) -> None:
    assert "phone" in find_pii_types(text)


@pytest.mark.parametrize(
    "text",
    [
        "артикул 9991234567",
        "тел 7707083893",
        "ИНН 7707083893",
        "сумма 1 500 000 00 00",
        "заказ 123 456 78 90",
        "счёт 40702810123456789012",
        "3,89991234567",
        "дата 12.09.2026",
        "партия 1234567890123",
    ],
)
def test_phone_not_confused_with_numbers(text: str) -> None:
    assert "phone" not in find_pii_types(text)


def test_inn_still_reported_as_inn_not_phone() -> None:
    assert find_pii_types(f"ИНН {INN10}") == {"inn"}


def test_r9_snils_rule_shared_with_pseudonymizer() -> None:
    """R9-A4-04: СНИЛС шлюз ищет общим правилом pii_patterns (им же маскирует pseudonymizer)."""
    from labops_pii.guard import detector
    from labops_pii.pii_patterns import find_snils_spans

    assert detector.find_snils_spans is find_snils_spans
    assert "snils" in find_pii_types("Артикул 31234567846, 12 шт.")
    assert "snils" in find_pii_types("номер 112-233-445 95")
    assert "snils" not in find_pii_types("Артикул 31234567847, 12 шт.")  # сумма не сходится
    assert "snils" not in find_pii_types("[SNILS_1] 12 шт.")
    # 11 цифр внутри более длинной серии - не СНИЛС
    assert find_snils_spans("312345678461") == []
