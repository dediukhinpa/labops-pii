"""Этап 26 (R4-RES-10): ретенция таблицы замен и кэш ключей list_keys."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from labops_pii.config import (
    DEFAULT_RETENTION_DAYS,
    ENV_API_TOKEN,
    ENV_KEY,
    ENV_RETENTION_DAYS,
    ConfigError,
    load_settings,
)
from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer
from labops_pii.store import SECONDS_PER_DAY, SqliteReplacementStore
from tests.pragmatika_pseudonymizer.conftest import API_TOKEN, make_client


class Clock:
    """Управляемые часы."""

    def __init__(self, now: float = 1_000_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance_days(self, days: float) -> None:
        self.now += days * SECONDS_PER_DAY


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def timed(fernet_key: str, clock: Clock) -> SqliteReplacementStore:
    return SqliteReplacementStore(":memory:", fernet_key, clock=clock)


def _fill(store: SqliteReplacementStore, thread: str) -> None:
    store.add(thread, "[PERSON_1]", "PERSON", "иванов иван", "Иванов Иван")
    store.add(thread, "[PHONE_1]", "PHONE", "9161234567", "+7 916 123-45-67")


# --- ретенция -------------------------------------------------------------------------

def test_expired_thread_removed_fresh_kept(timed: SqliteReplacementStore, clock: Clock) -> None:
    _fill(timed, "old")
    clock.advance_days(60)
    _fill(timed, "new")
    clock.advance_days(40)  # old: 100 дней без обращений, new: 40
    assert timed.purge_expired(90) == 1
    assert timed.get_original("old", "[PERSON_1]") is None
    assert timed.get_original("new", "[PERSON_1]") == "Иванов Иван"
    assert timed.count("old", "PERSON") == 0


def test_access_extends_life(timed: SqliteReplacementStore, clock: Clock) -> None:
    _fill(timed, "t")
    clock.advance_days(80)
    assert timed.get_originals("t", ["[PERSON_1]"]) == {"[PERSON_1]": "Иванов Иван"}
    clock.advance_days(80)  # с момента последнего обращения 80 дней
    assert timed.purge_expired(90) == 0
    assert timed.get_original("t", "[PHONE_1]") == "+7 916 123-45-67"


def test_retention_disabled_with_zero(timed: SqliteReplacementStore, clock: Clock) -> None:
    _fill(timed, "t")
    clock.advance_days(10_000)
    assert timed.purge_expired(0) == 0
    assert timed.count("t", "PERSON") == 1


def test_legacy_file_without_activity_gets_start_date(
    tmp_path: Path, fernet_key: str, clock: Clock
) -> None:
    """База без thread_activity (до этапа 26): при открытии тред получает дату старта."""
    db = tmp_path / "old.sqlite3"
    first = SqliteReplacementStore(db, fernet_key, clock=clock)
    _fill(first, "t")
    first.close()
    conn = sqlite3.connect(db)
    conn.execute("DROP TABLE thread_activity")
    conn.commit()
    conn.close()
    clock.advance_days(500)
    reopened = SqliteReplacementStore(db, fernet_key, clock=clock)
    assert reopened.purge_expired(90) == 0  # не удалён сразу: давности нет
    clock.advance_days(91)
    assert reopened.purge_expired(90) == 1


def test_old_rows_format_unchanged(tmp_path: Path, fernet_key: str) -> None:
    """Таблица replacements не менялась: прежние файлы и rekey.py совместимы."""
    db = tmp_path / "s.sqlite3"
    store = SqliteReplacementStore(db, fernet_key)
    _fill(store, "t")
    store.close()
    conn = sqlite3.connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(replacements)")]
    conn.close()
    assert cols == ["thread_id", "token", "pii_type", "key_hash", "key_enc", "value_enc"]


def test_purge_skipped_inside_batch(timed: SqliteReplacementStore, clock: Clock) -> None:
    _fill(timed, "old")
    clock.advance_days(200)
    with timed.batch():
        assert timed.purge_expired(90) == 0
    assert timed.purge_expired(90) == 1


def test_create_app_purges_at_start(
    detector: PiiDetector, fernet_key: str, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SqliteReplacementStore(":memory:", fernet_key, clock=clock)
    _fill(store, "old")
    clock.advance_days(100)
    client = make_client(detector, monkeypatch, store, retention_hours=90 * 24)
    assert store.count("old", "PERSON") == 0
    assert client.get("/health").status_code == 200


def test_runtime_purge_not_more_often_than_interval(
    detector: PiiDetector, fernet_key: str, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SqliteReplacementStore(":memory:", fernet_key, clock=clock)
    calls: list[int] = []
    real = store.purge_idle

    def spy(seconds: float) -> int:
        # Сервис отдаёт срок в секундах (общий путь для памяти и SQLite)
        calls.append(int(seconds))
        return real(seconds)

    store.purge_idle = spy  # type: ignore[method-assign]
    client = make_client(detector, monkeypatch, store, retention_hours=7 * 24)
    for _ in range(5):
        client.post("/pseudonymize", json={"thread_id": "t", "text": "привет"})
    assert calls == [7 * 86_400]  # только запуск при старте


def test_retention_settings() -> None:
    key = Fernet.generate_key().decode()
    base = {ENV_KEY: key, ENV_API_TOKEN: API_TOKEN}
    assert load_settings(base).retention_days == DEFAULT_RETENTION_DAYS
    assert load_settings({**base, ENV_RETENTION_DAYS: "30"}).retention_days == 30
    assert load_settings({**base, ENV_RETENTION_DAYS: "0"}).retention_days == 0
    for bad in ("-1", "abc"):
        with pytest.raises(ConfigError):
            load_settings({**base, ENV_RETENTION_DAYS: bad})


# --- кэш list_keys --------------------------------------------------------------------

class DecryptCounter:
    """Считает расшифровки хранилища."""

    def __init__(self, store: SqliteReplacementStore) -> None:
        self.count = 0
        self._real = store._decrypt  # noqa: SLF001
        store._decrypt = self  # type: ignore[method-assign]  # noqa: SLF001

    def __call__(self, blob: bytes, thread_id: str) -> str:
        self.count += 1
        return self._real(blob, thread_id)


def _persons(store: SqliteReplacementStore, thread: str, n: int) -> None:
    for i in range(1, n + 1):
        store.add(thread, f"[PERSON_{i}]", "PERSON", f"фамилия{i} имя", f"Фамилия{i} Имя")


def test_list_keys_decrypts_once(store: SqliteReplacementStore) -> None:
    _persons(store, "t", 30)
    counter = DecryptCounter(store)
    first = store.list_keys("t", "PERSON")
    assert counter.count <= 30
    counter.count = 0
    for _ in range(5):
        assert store.list_keys("t", "PERSON") == first
    assert counter.count == 0


def test_list_keys_sees_new_rows_without_full_decrypt(store: SqliteReplacementStore) -> None:
    _persons(store, "t", 20)
    store.list_keys("t", "PERSON")
    counter = DecryptCounter(store)
    store.add("t", "[PERSON_21]", "PERSON", "новый человек", "Новый Человек")
    keys = store.list_keys("t", "PERSON")
    assert ("новый человек", "[PERSON_21]") in keys and len(keys) == 21
    assert counter.count == 0


def test_cache_dropped_on_batch_rollback(store: SqliteReplacementStore) -> None:
    _persons(store, "t", 3)
    store.list_keys("t", "PERSON")
    with pytest.raises(RuntimeError), store.batch():
        store.add("t", "[PERSON_4]", "PERSON", "призрак", "Призрак")
        raise RuntimeError("отмена")
    keys = store.list_keys("t", "PERSON")
    assert len(keys) == 3 and all(k != "призрак" for k, _ in keys)


def test_cache_sees_rows_written_by_another_connection(tmp_path: Path, fernet_key: str) -> None:
    db = tmp_path / "x.sqlite3"
    a = SqliteReplacementStore(db, fernet_key)
    b = SqliteReplacementStore(db, fernet_key)
    _persons(a, "t", 2)
    assert len(a.list_keys("t", "PERSON")) == 2
    b.add("t", "[PERSON_3]", "PERSON", "чужой человек", "Чужой Человек")
    assert len(a.list_keys("t", "PERSON")) == 3  # счётчик в базе разошёлся с кэшем


def test_cache_is_bounded_and_correct(fernet_key: str) -> None:
    store = SqliteReplacementStore(":memory:", fernet_key, key_cache_entries=2)
    for t in ("a", "b", "c"):
        _persons(store, t, 2)
        assert len(store.list_keys(t, "PERSON")) == 2
    assert len(store._key_cache) <= 2  # noqa: SLF001
    assert len(store.list_keys("a", "PERSON")) == 2


def test_service_does_not_decrypt_all_keys_every_call(
    detector: PiiDetector, store: SqliteReplacementStore
) -> None:
    service = Pseudonymizer(detector, store)
    _persons(store, "t", 40)
    service.pseudonymize("t", "Позвоните Петрову Петру Петровичу")  # прогрев кэша
    counter = DecryptCounter(store)
    service.pseudonymize("t", "Он сказал что завтра будет")
    assert counter.count == 0
