"""Короткий срок хранения SQLite не удаляет тред, к которому обращаются постоянно."""

from __future__ import annotations

from cryptography.fernet import Fernet

from labops_pii.store import SqliteReplacementStore

HOUR = 3_600
MINUTE = 60
REQUEST_EVERY_MIN = 7
PURGE_EVERY_MIN = 1


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def test_active_thread_survives_one_hour_retention() -> None:
    # Обращения раз в 7 мин, очистка каждую минуту: прежде метка писалась раз в час и
    # к очистке на 61-й минуте была старше часа, хотя последний запрос был на 56-й
    clock = Clock()
    store = SqliteReplacementStore(
        ":memory:", Fernet.generate_key().decode(), clock, key_scheme="v2"
    )
    store.add("t", "[PERSON_1]", "PERSON", "иванов", "Иванов")
    for minute in range(1, 3 * 60 + 1):
        clock.now += MINUTE
        if minute % REQUEST_EVERY_MIN == 0:
            assert store.get_original("t", "[PERSON_1]") == "Иванов", f"удалён к {minute} мин"
        if minute % PURGE_EVERY_MIN == 0:
            store.purge_idle(HOUR)


def test_idle_thread_still_purged() -> None:
    clock = Clock()
    store = SqliteReplacementStore(
        ":memory:", Fernet.generate_key().decode(), clock, key_scheme="v2"
    )
    store.add("t", "[PERSON_1]", "PERSON", "иванов", "Иванов")
    store.purge_idle(HOUR)
    clock.now += 2 * HOUR
    assert store.purge_idle(HOUR) == 1
    assert store.get_original("t", "[PERSON_1]") is None
