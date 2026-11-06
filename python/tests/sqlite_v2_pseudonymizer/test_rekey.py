"""Тесты разделения ключей (S-02): чтение старых данных, схема v2, rekey, неверный ключ."""

from __future__ import annotations

import base64
import hashlib
import hmac
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken

from labops_pii import rekey
from labops_pii.config import ENV_KEY
from labops_pii.store import SCHEMA, V2_PREFIX, V2_PREFIX_BYTES, SqliteReplacementStore

ROWS = [
    ("t1", "[PERSON_1]", "PERSON", "иванов", "Иванов Иван"),
    ("t1", "[EMAIL_1]", "EMAIL", "a@x.ru", "A@x.ru"),
    ("t2", "[PHONE_1]", "PHONE", "9161234567", "+7 916 123-45-67"),
]


def _write_v1(db: Path, master: str) -> None:
    """Пишет строки так, как это делал код до разделения ключей (один ключ для всего)."""
    fernet = Fernet(master.encode())
    secret = base64.urlsafe_b64decode(master.encode())
    conn = sqlite3.connect(db)
    conn.execute(SCHEMA)
    for thread, token, pii, key, original in ROWS:
        conn.execute(
            "INSERT INTO replacements VALUES (?,?,?,?,?,?)",
            (
                thread, token, pii,
                hmac.new(secret, key.encode(), hashlib.sha256).hexdigest(),
                fernet.encrypt(key.encode()),
                fernet.encrypt(original.encode()),
            ),
        )
    conn.commit()
    conn.close()


def _raw_rows(db: Path) -> list[tuple[str, bytes, bytes]]:
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT key_hash, key_enc, value_enc FROM replacements").fetchall()
    conn.close()
    return [(str(h), bytes(k), bytes(v)) for h, k, v in rows]


def test_keys_are_separated(tmp_path: Path, fernet_key: str) -> None:
    store = SqliteReplacementStore(tmp_path / "a.sqlite3", fernet_key)
    master = base64.urlsafe_b64decode(fernet_key.encode())
    assert store._index_secret != master
    # Fernet-ключ v2 не совпадает с мастер-ключом и не выводится из индексного секрета
    derived = store._fernet._signing_key + store._fernet._encryption_key  # noqa: SLF001
    assert derived != master
    assert derived != store._index_secret


def test_new_data_written_in_v2(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "n.sqlite3"
    store = SqliteReplacementStore(db, fernet_key)
    store.add(*ROWS[0])
    assert store.get_original("t1", "[PERSON_1]") == "Иванов Иван"
    assert store.find_token("t1", "PERSON", "иванов") == "[PERSON_1]"
    store.close()
    (key_hash, key_enc, value_enc), = _raw_rows(db)
    assert key_hash.startswith(V2_PREFIX)
    assert key_enc.startswith(V2_PREFIX_BYTES) and value_enc.startswith(V2_PREFIX_BYTES)
    # Старым (общим) ключом v2-данные не читаются
    with pytest.raises(InvalidToken):
        Fernet(fernet_key.encode()).decrypt(value_enc[len(V2_PREFIX_BYTES):])


def test_legacy_data_still_readable_and_searchable(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "old.sqlite3"
    _write_v1(db, fernet_key)
    store = SqliteReplacementStore(db, fernet_key)
    assert store.legacy_row_count() == len(ROWS)
    assert store.get_original("t1", "[EMAIL_1]") == "A@x.ru"
    assert store.find_token("t1", "EMAIL", "a@x.ru") == "[EMAIL_1]"
    assert dict(store.list_keys("t1", "PERSON")) == {"иванов": "[PERSON_1]"}
    # новая запись идёт по v2 и соседствует со старыми
    store.add("t1", "[EMAIL_2]", "EMAIL", "b@x.ru", "B@x.ru")
    assert store.get_original("t1", "[EMAIL_2]") == "B@x.ru"
    assert store.legacy_row_count() == len(ROWS)


def test_rekey_migrates_everything_and_is_idempotent(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "r.sqlite3"
    _write_v1(db, fernet_key)
    store = SqliteReplacementStore(db, fernet_key)
    report = store.rekey_legacy()
    assert (report.total, report.legacy, report.migrated) == (len(ROWS), len(ROWS), len(ROWS))
    assert store.legacy_row_count() == 0
    for thread, token, pii, key, original in ROWS:
        assert store.get_original(thread, token) == original
        assert store.find_token(thread, pii, key) == token
    again = store.rekey_legacy()
    assert (again.legacy, again.migrated) == (0, 0)
    store.close()
    # после rekey в файле нет ничего старой схемы
    for key_hash, key_enc, value_enc in _raw_rows(db):
        assert key_hash.startswith(V2_PREFIX)
        assert key_enc.startswith(V2_PREFIX_BYTES) and value_enc.startswith(V2_PREFIX_BYTES)


def test_rekey_dry_run_does_not_write(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "d.sqlite3"
    _write_v1(db, fernet_key)
    before = _raw_rows(db)
    store = SqliteReplacementStore(db, fernet_key)
    report = store.rekey_legacy(dry_run=True)
    store.close()
    assert (report.legacy, report.migrated, report.dry_run) == (len(ROWS), 0, True)
    assert _raw_rows(db) == before


def test_wrong_key_errors_and_changes_nothing(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "w.sqlite3"
    _write_v1(db, fernet_key)
    before = _raw_rows(db)
    wrong = SqliteReplacementStore(db, Fernet.generate_key().decode())
    with pytest.raises(InvalidToken):
        wrong.rekey_legacy()
    with pytest.raises(InvalidToken):
        wrong.get_original("t1", "[EMAIL_1]")
    wrong.close()
    assert _raw_rows(db) == before


def test_rekey_cli(tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "c.sqlite3"
    _write_v1(db, fernet_key)
    monkeypatch.setenv(ENV_KEY, fernet_key)
    assert rekey.main(["--db", str(db), "--dry-run"]) == rekey.EXIT_OK
    assert not list(tmp_path.glob("*.bak-*"))  # dry-run бэкап не делает
    assert rekey.main(["--db", str(db)]) == rekey.EXIT_OK
    backups = list(tmp_path.glob("c.sqlite3.bak-*"))
    assert len(backups) == 1 and backups[0].stat().st_mode & 0o777 == rekey.BACKUP_FILE_MODE
    store = SqliteReplacementStore(db, fernet_key)
    assert store.legacy_row_count() == 0
    store.close()
    # бэкап хранит прежнюю схему и по-прежнему читается
    old = SqliteReplacementStore(backups[0], fernet_key)
    assert old.legacy_row_count() == len(ROWS)
    old.close()


def test_rekey_cli_wrong_key_exit_code(
    tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "x.sqlite3"
    _write_v1(db, fernet_key)
    before = _raw_rows(db)
    monkeypatch.setenv(ENV_KEY, Fernet.generate_key().decode())
    assert rekey.main(["--db", str(db), "--no-backup"]) == rekey.EXIT_FAILED
    assert _raw_rows(db) == before
    monkeypatch.delenv(ENV_KEY)
    assert rekey.main(["--db", str(db)]) == rekey.EXIT_USAGE


# --- Копия перед перешифрованием: права с момента создания, ключ проверяется до копии ---


def test_backup_created_with_owner_only_mode(
    tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Файл копии с самого начала 0600: окна, когда его читают другие, нет."""
    import os

    db = tmp_path / "m.sqlite3"
    _write_v1(db, fernet_key)
    seen: list[int] = []
    real_connect = sqlite3.connect

    def spy(target: str, *args: object, **kwargs: object) -> sqlite3.Connection:
        if ".bak-" in str(target):
            # к моменту открытия копии файл уже создан и закрыт от группы и остальных
            seen.append(Path(str(target)).stat().st_mode & 0o777)
        return real_connect(target, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rekey.sqlite3, "connect", spy)
    # chmod после копирования не должен быть тем, что обеспечивает права
    monkeypatch.setattr(Path, "chmod", lambda self, mode: None)
    old_umask = os.umask(0o022)
    try:
        backup = rekey.make_backup(db)
    finally:
        os.umask(old_umask)
    assert seen == [rekey.BACKUP_FILE_MODE]
    assert backup.stat().st_mode & 0o777 == rekey.BACKUP_FILE_MODE
    restored = SqliteReplacementStore(backup, fernet_key)
    assert restored.get_original("t1", "[EMAIL_1]") == "A@x.ru"
    restored.close()


def test_wrong_key_leaves_no_backup(
    tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Неверный ключ обнаруживается до копии: лишней копии таблицы замен не остаётся."""
    db = tmp_path / "k.sqlite3"
    _write_v1(db, fernet_key)
    before = _raw_rows(db)
    monkeypatch.setenv(ENV_KEY, Fernet.generate_key().decode())
    assert rekey.main(["--db", str(db)]) == rekey.EXIT_FAILED
    assert sorted(p.name for p in tmp_path.iterdir()) == ["k.sqlite3"]
    assert _raw_rows(db) == before


def test_failed_copy_removes_partial_backup(
    tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сбой копирования: недописанный файл удаляется, перешифрование не начинается."""
    db = tmp_path / "f.sqlite3"
    _write_v1(db, fernet_key)
    before = _raw_rows(db)

    def broken(source: Path, target: Path) -> None:
        target.write_bytes(b"partial")
        raise OSError("disk full")

    monkeypatch.setattr(rekey, "_copy_database", broken)
    with pytest.raises(OSError, match="disk full"):
        rekey.make_backup(db)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.sqlite3"]
    monkeypatch.setenv(ENV_KEY, fernet_key)
    assert rekey.main(["--db", str(db)]) == rekey.EXIT_FAILED
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.sqlite3"]
    assert _raw_rows(db) == before


def test_backup_does_not_overwrite_existing_file(
    tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Имя копии занято (вторая копия в ту же секунду): чужой файл не трогаем."""
    db = tmp_path / "e.sqlite3"
    _write_v1(db, fernet_key)
    monkeypatch.setattr(rekey.time, "strftime", lambda _fmt: "20260101-000000")
    first = rekey.make_backup(db)
    content = first.read_bytes()
    with pytest.raises(FileExistsError):
        rekey.make_backup(db)
    assert first.read_bytes() == content


def test_rekey_cli_dry_run_leaves_file_byte_identical(
    tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Раньше открытие хранилища в --dry-run дописывало метки активности тредов
    db = tmp_path / "d.sqlite3"
    _write_v1(db, fernet_key)
    before = db.read_bytes()
    monkeypatch.setenv(ENV_KEY, fernet_key)
    assert rekey.main(["--db", str(db), "--dry-run"]) == rekey.EXIT_OK
    assert db.read_bytes() == before


@pytest.mark.parametrize("args", [["--dry-run"], ["--no-backup"]])
def test_rekey_cli_on_file_without_tables(
    tmp_path: Path, fernet_key: str, monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    # Пустой файл SQLite (без таблиц): перешифровывать нечего, это не ошибка
    db = tmp_path / "empty.sqlite3"
    sqlite3.connect(db).close()
    monkeypatch.setenv(ENV_KEY, fernet_key)
    assert rekey.main(["--db", str(db), *args]) == rekey.EXIT_OK
