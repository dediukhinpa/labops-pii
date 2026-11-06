"""Сессия без ПДн в новых сообщениях продлевает жизнь треда (не удаляется по сроку хранения)."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer
from labops_pii.store import MemoryReplacementStore, SqliteReplacementStore

HOUR = 3_600
RETENTION = 24 * HOUR
SESSION_HOURS = 30


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _store(kind: str, clock: Clock) -> SqliteReplacementStore | MemoryReplacementStore:
    if kind == "memory":
        return MemoryReplacementStore(clock)
    return SqliteReplacementStore(
        ":memory:", Fernet.generate_key().decode(), clock, key_scheme="v2"
    )


@pytest.mark.parametrize("kind", ["sqlite", "memory"])
def test_thread_without_new_pii_survives_retention(detector: PiiDetector, kind: str) -> None:
    clock = Clock()
    store = _store(kind, clock)
    service = Pseudonymizer(detector, store)
    first, _ = service.pseudonymize("t", "Позвони Иванову Ивану Ивановичу, +7 916 123-45-67")
    for _hour in range(SESSION_HOURS):
        clock.now += HOUR
        service.pseudonymize("t", "Хорошо, продолжаем")
        store.purge_idle(RETENTION)
    # Тред жив: токены первого сообщения по-прежнему восстанавливаются
    assert "Иванов" in service.restore("t", first)
