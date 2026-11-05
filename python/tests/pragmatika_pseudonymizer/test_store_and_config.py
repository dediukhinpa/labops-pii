"""Тесты хранилища (шифрование) и конфигурации (старт без ключа)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from labops_pii.__main__ import main
from labops_pii.config import ENV_API_TOKEN, ENV_KEY, ConfigError, load_contacts, load_settings
from labops_pii.store import SqliteReplacementStore
from tests.env_sets import ENV_SETS


def test_store_encrypts_values_on_disk(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "t.sqlite3"
    store = SqliteReplacementStore(db, fernet_key)
    store.add("t1", "[PERSON_1]", "PERSON", "иванов", "Иванов Иван")
    store.close()
    raw = b"".join(
        bytes(c) if isinstance(c, (bytes, bytearray)) else str(c).encode()
        for row in sqlite3.connect(db).execute("SELECT * FROM replacements")
        for c in row
    )
    assert "Иван".encode() not in raw and b"ivanov" not in raw


def test_store_roundtrip_and_wrong_key(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "t.sqlite3"
    store = SqliteReplacementStore(db, fernet_key)
    store.add("t1", "[EMAIL_1]", "EMAIL", "a@x.ru", "A@x.ru")
    assert store.get_original("t1", "[EMAIL_1]") == "A@x.ru"
    assert store.find_token("t1", "EMAIL", "a@x.ru") == "[EMAIL_1]"
    assert store.get_original("t2", "[EMAIL_1]") is None
    other = SqliteReplacementStore(db, Fernet.generate_key().decode())
    assert other.find_token("t1", "EMAIL", "a@x.ru") is None  # другой слепой индекс


def test_no_key_refuses_to_start() -> None:
    sqlite = {**ENV_SETS["pragmatika"], ENV_API_TOKEN: "tok"}
    with pytest.raises(ConfigError, match=ENV_KEY):
        load_settings(sqlite)
    with pytest.raises(ConfigError, match=ENV_KEY):
        load_settings({**sqlite, ENV_KEY: "   "})


def test_invalid_key_refused_without_leaking_it() -> None:
    with pytest.raises(ConfigError) as info:
        load_settings({
            **ENV_SETS["pragmatika"], ENV_API_TOKEN: "tok", ENV_KEY: "not-a-fernet-key-SECRETVALUE"
        })
    assert "SECRETVALUE" not in str(info.value)


def test_main_exits_nonzero_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_KEY, raising=False)
    assert main() == 1


def test_settings_repr_hides_key(fernet_key: str) -> None:
    settings = load_settings({**ENV_SETS["pragmatika"], ENV_KEY: fernet_key, ENV_API_TOKEN: "tok"})
    assert fernet_key not in repr(settings)
    assert settings.mask_legal_entity_requisites is False


def test_flags_and_contacts_file(tmp_path: Path, fernet_key: str) -> None:
    contacts = tmp_path / "c.txt"
    contacts.write_text("# комментарий\nДядя Коля\n\nВася\n", encoding="utf-8")
    settings = load_settings(
        {
            ENV_KEY: fernet_key,
            ENV_API_TOKEN: "tok",
            "PSEUDONYMIZER_MASK_LEGAL_ENTITY": "true",
            "PSEUDONYMIZER_CONTACTS_FILE": str(contacts),
        }
    )
    assert settings.mask_legal_entity_requisites is True
    assert settings.contacts == ("Дядя Коля", "Вася")
    with pytest.raises(ConfigError):
        load_contacts(tmp_path / "missing.txt")


def test_max_text_chars_config(fernet_key: str) -> None:
    from labops_pii.config import DEFAULT_MAX_TEXT_CHARS, ENV_MAX_TEXT

    base = {ENV_KEY: fernet_key, ENV_API_TOKEN: "tok"}
    assert load_settings(base).max_text_chars == DEFAULT_MAX_TEXT_CHARS
    assert load_settings({**base, ENV_MAX_TEXT: "1234"}).max_text_chars == 1234
    for bad in ("0", "-5", "abc"):
        with pytest.raises(ConfigError):
            load_settings({**base, ENV_MAX_TEXT: bad})
