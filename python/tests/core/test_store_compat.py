"""Совместимость форматов хранилища с базами исходных копий (читаем и пишем в их схеме)."""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from labops_pii.store import (
    V2_PREFIX,
    V2_PREFIX_BYTES,
    V3_PREFIX,
    V3_PREFIX_BYTES,
    SqliteReplacementStore,
)

STORES = Path(__file__).resolve().parents[1] / "fixtures" / "stores"
# Тестовый ключ Fernet из нулевых байт (не секрет)
TEST_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
SCHEME_BY_NAME = {"pragmatika": "v2", "labops": "v3"}


def _fixture(name: str, tmp_path: Path) -> tuple[Path, dict]:
    """Копия базы исходной копии (файл репо не меняется) и её описание."""
    meta = json.loads((STORES / f"{name}.hashes.json").read_text(encoding="utf-8"))
    db = tmp_path / f"{name}.sqlite3"
    shutil.copy(STORES / f"{name}.sqlite3", db)
    return db, meta


@pytest.mark.parametrize("name", sorted(SCHEME_BY_NAME))
@pytest.mark.parametrize("write_scheme", ["v2", "v3"])
def test_library_reads_original_database(name: str, write_scheme: str, tmp_path: Path) -> None:
    """База, записанная кодом исходной копии, читается при любой схеме записи."""
    db, meta = _fixture(name, tmp_path)
    store = SqliteReplacementStore(db, meta["key"], key_scheme=write_scheme)
    for thread, token, pii_type, key, original in meta["rows"]:
        assert store.find_token(thread, pii_type, key) == token
        assert store.get_original(thread, token) == original
        assert (key, token) in store.list_keys(thread, pii_type)
    assert store.legacy_row_count() == 0


@pytest.mark.parametrize("name", sorted(SCHEME_BY_NAME))
def test_blind_index_equals_original(name: str) -> None:
    """Слепые индексы библиотеки побайтно равны индексам исходной копии."""
    meta = json.loads((STORES / f"{name}.hashes.json").read_text(encoding="utf-8"))
    store = SqliteReplacementStore(":memory:", meta["key"], key_scheme=SCHEME_BY_NAME[name])
    for thread, _token, _type, key, _original in meta["rows"]:
        assert store._hash(thread, key) == meta["hashes"][f"{thread}|{key}"]  # noqa: SLF001


def test_pragmatika_scheme_writes_v2_only(tmp_path: Path) -> None:
    """Профиль Прагматики пишет v2: файл остаётся читаемым прежним кодом (откат возможен)."""
    store = SqliteReplacementStore(tmp_path / "p.sqlite3", TEST_KEY, key_scheme="v2")
    store.add("agent:1", "[PERSON_1]", "PERSON", "петров", "Петров")
    store.close()
    with sqlite3.connect(tmp_path / "p.sqlite3") as conn:
        key_hash, key_enc, value_enc = conn.execute(
            "SELECT key_hash, key_enc, value_enc FROM replacements"
        ).fetchone()
    assert key_hash.startswith(V2_PREFIX) and not key_hash.startswith(V3_PREFIX)
    assert bytes(key_enc).startswith(V2_PREFIX_BYTES)
    assert bytes(value_enc).startswith(V2_PREFIX_BYTES)
    assert not bytes(value_enc).startswith(V3_PREFIX_BYTES)


def test_labops_scheme_writes_v3(tmp_path: Path) -> None:
    """Профиль labops пишет v3 (ключи по префиксу треда)."""
    store = SqliteReplacementStore(tmp_path / "l.sqlite3", TEST_KEY, key_scheme="v3")
    store.add("agent:1", "[PERSON_1]", "PERSON", "петров", "Петров")
    store.close()
    with sqlite3.connect(tmp_path / "l.sqlite3") as conn:
        (key_hash,) = conn.execute("SELECT key_hash FROM replacements").fetchone()
    assert key_hash.startswith(V3_PREFIX)


# --- Схема записи задаётся PSEUDONYMIZER_KEY_SCHEME (профилей нет) ----------------------

@pytest.mark.parametrize("name", sorted(SCHEME_BY_NAME))
def test_env_scheme_reads_original_database(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Хранилище без явной схемы берёт её из окружения и читает базу исходной копии."""
    monkeypatch.setenv("PSEUDONYMIZER_KEY_SCHEME", SCHEME_BY_NAME[name])
    db, meta = _fixture(name, tmp_path)
    store = SqliteReplacementStore(db, meta["key"])
    for thread, token, pii_type, key, original in meta["rows"]:
        assert store.find_token(thread, pii_type, key) == token
        assert store.get_original(thread, token) == original
    assert store.legacy_row_count() == 0


@pytest.mark.parametrize(("scheme", "prefix"), [("v2", V2_PREFIX), ("v3", V3_PREFIX)])
def test_env_scheme_decides_write_format(
    scheme: str, prefix: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Схема из окружения определяет формат записи: v2 или v3 (и только он)."""
    monkeypatch.setenv("PSEUDONYMIZER_KEY_SCHEME", scheme)
    db = tmp_path / "env.sqlite3"
    store = SqliteReplacementStore(db, TEST_KEY)
    store.add("agent:1", "[PERSON_1]", "PERSON", "петров", "Петров")
    store.close()
    with sqlite3.connect(db) as conn:
        (key_hash,) = conn.execute("SELECT key_hash FROM replacements").fetchone()
    other = V3_PREFIX if prefix == V2_PREFIX else V2_PREFIX
    assert key_hash.startswith(prefix) and not key_hash.startswith(other)


def test_v2_database_stays_readable_by_v3_service_and_back(tmp_path: Path) -> None:
    """Файл, записанный в v2, читается сервисом со схемой v3 и наоборот (читаются все схемы)."""
    db = tmp_path / "mix.sqlite3"
    writer = SqliteReplacementStore(db, TEST_KEY, key_scheme="v2")
    writer.add("agent:1", "[PERSON_1]", "PERSON", "петров", "Петров")
    writer.close()
    reader = SqliteReplacementStore(db, TEST_KEY, key_scheme="v3")
    assert reader.find_token("agent:1", "PERSON", "петров") == "[PERSON_1]"
    reader.add("agent:1", "[PERSON_2]", "PERSON", "сидоров", "Сидоров")
    reader.close()
    back = SqliteReplacementStore(db, TEST_KEY, key_scheme="v2")
    assert back.find_token("agent:1", "PERSON", "сидоров") == "[PERSON_2]"
