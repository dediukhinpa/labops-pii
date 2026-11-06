"""R7-03: /check с thread_id видит фамилию, восстановленную в запросе внешнего инструмента."""

from __future__ import annotations

from fastapi.testclient import TestClient

from labops_pii.service import Pseudonymizer

THREAD = "ext-thread"
CONTEXT = "Менеджер Сидоров сказал, что арматура А500 будет в четверг"
QUERY = "[PERSON_1] арматура поставщик"
RESTORED_QUERY = "Сидоров арматура поставщик"


def test_service_check_without_thread_misses_lone_surname(service: Pseudonymizer) -> None:
    """Фиксирует исходное поведение: без треда одинокая фамилия в начале фразы не видна."""
    service.pseudonymize(THREAD, CONTEXT)
    assert service.restore(THREAD, QUERY) == RESTORED_QUERY
    assert service.check(RESTORED_QUERY) == []


def test_service_check_with_thread_sees_restored_surname(service: Pseudonymizer) -> None:
    masked, _ = service.pseudonymize(THREAD, CONTEXT)
    assert "Сидоров" not in masked and "[PERSON_1]" in masked
    restored = service.restore(THREAD, QUERY)
    assert service.check(restored, THREAD) == ["PERSON"]


def test_service_check_other_thread_has_no_lemmas(service: Pseudonymizer) -> None:
    """Леммы чужого треда не используются: проверка не раскрывает чужие ПДн."""
    service.pseudonymize(THREAD, CONTEXT)
    assert service.check(RESTORED_QUERY, "another-thread") == []


def test_http_pseudonymize_restore_check_roundtrip(client: TestClient) -> None:
    """Настоящий сервис: pseudonymize -> restore -> check(thread_id) ловит фамилию."""
    masked = client.post("/pseudonymize", json={"thread_id": THREAD, "text": CONTEXT}).json()
    assert "Сидоров" not in masked["text"]
    restored = client.post("/restore", json={"thread_id": THREAD, "text": QUERY}).json()["text"]
    assert restored == RESTORED_QUERY
    plain = client.post("/check", json={"text": restored}).json()
    assert plain == {"has_pii": False, "types": []}  # обратная совместимость без thread_id
    checked = client.post("/check", json={"text": restored, "thread_id": THREAD}).json()
    assert checked == {"has_pii": True, "types": ["PERSON"]}


def test_http_check_does_not_store_or_tokenize(client: TestClient) -> None:
    client.post("/pseudonymize", json={"thread_id": THREAD, "text": CONTEXT})
    client.post("/check", json={"text": RESTORED_QUERY, "thread_id": THREAD})
    again = client.post("/pseudonymize", json={"thread_id": THREAD, "text": "Иванов Пётр"}).json()
    assert again["text"] == "[PERSON_2]"  # check не завёл токенов
