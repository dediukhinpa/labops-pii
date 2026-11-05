"""Тесты хранилища в памяти: откат пачки, простой треда, удаление, потокобезопасность."""

from __future__ import annotations

import threading

import pytest

from labops_pii.store import (
    SECONDS_PER_HOUR,
    MemoryReplacementStore,
    ReplacementConflictError,
    ReplacementStore,
    SqliteReplacementStore,
)

START_TIME = 1_000_000.0
THREADS = 8
PER_THREAD = 200


class Clock:
    """Подменяемые часы: время двигается руками, без sleep."""

    def __init__(self) -> None:
        self.now = START_TIME

    def __call__(self) -> float:
        return self.now

    def advance_hours(self, hours: float) -> None:
        self.now += hours * SECONDS_PER_HOUR


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def mem(clock: Clock) -> MemoryReplacementStore:
    return MemoryReplacementStore(clock=clock)


def test_rollback_restores_previous_state(mem: MemoryReplacementStore) -> None:
    mem.add("t", "[EMAIL_1]", "EMAIL", "a@x.ru", "A@x.ru")
    with pytest.raises(RuntimeError), mem.batch():
        mem.add("t", "[EMAIL_2]", "EMAIL", "b@x.ru", "b@x.ru")
        mem.add("new", "[PHONE_1]", "PHONE", "79", "+79")
        raise RuntimeError("сбой")
    assert mem.count("t", "EMAIL") == 1
    assert mem.find_token("t", "EMAIL", "b@x.ru") is None
    assert mem.list_keys("new", "PHONE") == []
    assert mem.get_original("t", "[EMAIL_1]") == "A@x.ru"
    # после отката номер снова свободен
    mem.add("t", "[EMAIL_2]", "EMAIL", "c@x.ru", "c@x.ru")


def test_duplicate_token_or_key_rejected(mem: MemoryReplacementStore) -> None:
    mem.add("t", "[EMAIL_1]", "EMAIL", "a", "A")
    with pytest.raises(ReplacementConflictError):
        mem.add("t", "[EMAIL_9]", "EMAIL", "a", "A")
    with pytest.raises(ReplacementConflictError):
        mem.add("t", "[EMAIL_1]", "EMAIL", "z", "Z")
    assert mem.count("t", "EMAIL") == 1


def test_idle_thread_purged_and_access_extends_life(
    mem: MemoryReplacementStore, clock: Clock
) -> None:
    mem.add("old", "[EMAIL_1]", "EMAIL", "a", "A")
    mem.add("live", "[EMAIL_1]", "EMAIL", "a", "A")
    clock.advance_hours(20)
    assert mem.get_original("live", "[EMAIL_1]") == "A"  # restore продлевает жизнь
    clock.advance_hours(5)
    assert mem.purge_idle(24 * SECONDS_PER_HOUR) == 1
    assert mem.get_original("old", "[EMAIL_1]") is None
    assert mem.get_original("live", "[EMAIL_1]") == "A"
    assert mem.purge_idle(0) == 0  # 0 — не удалять


def test_purge_skipped_inside_batch(mem: MemoryReplacementStore, clock: Clock) -> None:
    mem.add("old", "[EMAIL_1]", "EMAIL", "a", "A")
    clock.advance_hours(48)
    with mem.batch():
        assert mem.purge_idle(SECONDS_PER_HOUR) == 0
    assert mem.purge_idle(SECONDS_PER_HOUR) == 1


@pytest.fixture(params=["memory", "sqlite"])
def any_store(request: pytest.FixtureRequest, fernet_key: str) -> ReplacementStore:
    if request.param == "memory":
        return MemoryReplacementStore()
    return SqliteReplacementStore(":memory:", fernet_key)


def test_delete_thread_is_idempotent_and_isolated(any_store: ReplacementStore) -> None:
    any_store.add("a", "[PERSON_1]", "PERSON", "иванов", "Иванов")
    any_store.add("b", "[PERSON_1]", "PERSON", "иванов", "Иванов")
    assert any_store.delete_thread("a") is True
    assert any_store.delete_thread("a") is False
    assert any_store.delete_thread("never-existed") is False
    assert any_store.count("a", "PERSON") == 0
    assert any_store.get_original("a", "[PERSON_1]") is None
    assert any_store.get_original("b", "[PERSON_1]") == "Иванов"


def test_concurrent_adds_are_consistent(mem: MemoryReplacementStore) -> None:
    def worker(n: int) -> None:
        for i in range(PER_THREAD):
            mem.add("t", f"[EMAIL_{n}_{i}]", "EMAIL", f"{n}-{i}", "x")

    pool = [threading.Thread(target=worker, args=(n,)) for n in range(THREADS)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    assert mem.count("t", "EMAIL") == THREADS * PER_THREAD
    assert len(mem.list_keys("t", "EMAIL")) == THREADS * PER_THREAD
