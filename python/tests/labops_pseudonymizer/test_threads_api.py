"""DELETE /threads/{id}, boot_id в /health, простой треда, изоляция тредов."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

import labops_pii.api as api
from labops_pii.detector import PiiDetector
from labops_pii.store import SECONDS_PER_HOUR, MemoryReplacementStore, ReplacementStore
from labops_pii.service import Pseudonymizer
from tests.labops_pseudonymizer.conftest import AUTH_HEADERS, make_client

NO_CONTENT = 204
TEXT = "Позвони Петрову, +7 (902) 123-45-67"
TTL_HOURS = 24
START_TIME = 1_000_000.0


def test_delete_requires_token(detector: PiiDetector, monkeypatch: pytest.MonkeyPatch) -> None:
    bare = make_client(detector, monkeypatch, headers=None)
    assert bare.delete("/threads/t1").status_code == 401
    wrong = bare.delete("/threads/t1", headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401


def test_delete_is_idempotent_204(client: TestClient) -> None:
    assert client.delete("/threads/never-existed").status_code == NO_CONTENT
    client.post("/pseudonymize", json={"thread_id": "t1", "text": TEXT})
    first = client.delete("/threads/t1")
    assert first.status_code == NO_CONTENT and first.content == b""
    assert client.delete("/threads/t1").status_code == NO_CONTENT


def test_after_delete_token_stays_and_numbering_restarts(client: TestClient) -> None:
    masked = client.post("/pseudonymize", json={"thread_id": "t1", "text": TEXT}).json()["text"]
    assert "[PHONE_1]" in masked
    client.delete("/threads/t1")
    restored = client.post("/restore", json={"thread_id": "t1", "text": masked}).json()["text"]
    assert restored == masked  # токен остаётся как есть, оригинала нет
    again = client.post("/pseudonymize", json={"thread_id": "t1", "text": "+7 (903) 555-44-33"})
    assert again.json()["text"] == "[PHONE_1]"  # нумерация нового треда с 1


def test_delete_with_prefixed_thread_id(client: TestClient) -> None:
    client.post("/pseudonymize", json={"thread_id": "agent:sess", "text": TEXT})
    assert client.delete("/threads/agent:sess").status_code == NO_CONTENT
    restored = client.post("/restore", json={"thread_id": "agent:sess", "text": "[PHONE_1]"})
    assert restored.json()["text"] == "[PHONE_1]"


@pytest.mark.parametrize("thread_id", ["agent/sess", "a/b/c"])
def test_delete_with_slash_in_thread_id(client: TestClient, thread_id: str) -> None:
    client.post("/pseudonymize", json={"thread_id": thread_id, "text": TEXT})
    assert client.delete(f"/threads/{thread_id}").status_code == NO_CONTENT
    restored = client.post("/restore", json={"thread_id": thread_id, "text": "[PHONE_1]"})
    assert restored.json()["text"] == "[PHONE_1]"


def test_threads_are_isolated(client: TestClient) -> None:
    masked = client.post("/pseudonymize", json={"thread_id": "A", "text": TEXT}).json()["text"]
    in_b = client.post("/restore", json={"thread_id": "B", "text": masked}).json()["text"]
    assert in_b == masked and "123-45-67" not in in_b
    in_a = client.post("/restore", json={"thread_id": "A", "text": masked}).json()["text"]
    assert "123-45-67" in in_a
    client.delete("/threads/B")  # чужое удаление не трогает тред A
    assert "123-45-67" in client.post(
        "/restore", json={"thread_id": "A", "text": masked}
    ).json()["text"]


def test_health_boot_id_is_stable_uuid(client: TestClient) -> None:
    first = client.get("/health").json()["boot_id"]
    assert client.get("/health").json()["boot_id"] == first
    assert str(uuid.UUID(first)) == first
    assert api.BOOT_ID == first


def test_idle_thread_removed_by_service_ttl(
    detector: PiiDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [START_TIME]
    mono = [0.0]
    store = MemoryReplacementStore(clock=lambda: now[0])
    monkeypatch.setattr(api.time, "monotonic", lambda: mono[0])
    client = make_client(detector, monkeypatch, store, retention_hours=TTL_HOURS)
    client.post("/pseudonymize", json={"thread_id": "old", "text": TEXT})
    now[0] += (TTL_HOURS + 1) * SECONDS_PER_HOUR
    mono[0] += api.MEMORY_RETENTION_CHECK_INTERVAL_SECONDS + 1  # пора проверять
    client.post("/pseudonymize", json={"thread_id": "other", "text": "привет"})
    assert store.count("old", "PHONE") == 0


def test_retention_zero_keeps_threads(
    detector: PiiDetector, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [START_TIME]
    store: ReplacementStore = MemoryReplacementStore(clock=lambda: now[0])
    client = make_client(detector, monkeypatch, store, retention_hours=0)
    client.post("/pseudonymize", json={"thread_id": "t", "text": TEXT})
    now[0] += 1000 * SECONDS_PER_HOUR
    client.post("/pseudonymize", json={"thread_id": "x", "text": "привет"})
    assert store.count("t", "PHONE") == 1
    assert client.delete("/threads/t", headers=AUTH_HEADERS).status_code == NO_CONTENT


def test_delete_waits_for_running_write_batch(service: Pseudonymizer) -> None:
    """DELETE ждёт конца чужой пачки записей и не попадает в её откат."""
    import threading

    service.pseudonymize("agent:b", "позвони Петрову Ивану Сергеевичу")
    started = threading.Event()
    release = threading.Event()
    store = service._store  # noqa: SLF001 - нужен перехват пачки
    original_add = store.add

    def slow_add(*args: object, **kwargs: object) -> None:
        started.set()
        release.wait(timeout=5)
        original_add(*args, **kwargs)  # type: ignore[arg-type]

    store.add = slow_add  # type: ignore[method-assign]
    writer = threading.Thread(target=service.pseudonymize, args=("agent:a", "звони Сидорову Олегу"))
    writer.start()
    assert started.wait(timeout=5)
    deleter = threading.Thread(target=service.delete_thread, args=("agent:b",))
    deleter.start()
    deleter.join(timeout=0.2)
    assert deleter.is_alive(), "удаление не должно идти посреди пачки записей"
    release.set()
    writer.join(timeout=5)
    deleter.join(timeout=5)
    store.add = original_add  # type: ignore[method-assign]
    assert service.restore("agent:b", "[PERSON_1]") == "[PERSON_1]"
