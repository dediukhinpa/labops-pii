"""R9-A2-04: пакетное маскирование /pseudonymize_batch.

Главный инвариант: пачка даёт ровно тот же результат, что N одиночных /pseudonymize подряд
в том же порядке - те же тексты, сущности, номера токенов и записи таблицы замен.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from labops_pii.api import batch_cost_chars
from labops_pii.config import (
    BATCH_ITEM_COST_CHARS,
    BATCH_ITEM_SECONDS,
    CLIENT_TIMEOUT_SECONDS,
    DEFAULT_MAX_BATCH_ITEMS,
    DEFAULT_MAX_TEXT_CHARS,
    ENV_API_TOKEN,
    ENV_KEY,
    WORST_CASE_TIMEOUT_SHARE,
    WORST_SECONDS_PER_CHAR,
    load_settings,
)
from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer
from labops_pii.store import SqliteReplacementStore
from tests.sqlite_v2_pseudonymizer import pii_corpus, recall_sets
from tests.sqlite_v2_pseudonymizer.conftest import make_client

THREAD = "t-batch"
SUPPLIERS = 50
# Длина пачки в тестах на HTTP: пачки поменьше проверяют стык нескольких запросов подряд.
HTTP_CHUNK = 37

Row = tuple[str, str, str, str, str]


def _supplier(i: int) -> dict[str, object]:
    """Карточка поставщика, как её возвращает инструмент searchSuppliers (с ПДн контактов)."""
    return {
        "id": f"s{i}",
        "name": f"ООО Поставщик {i}",
        "inn": "77" + str(i).zfill(8),
        "status": "active",
        "categories": ["кабель", "щиты"],
        "brands": ["ABB", "IEK"],
        "regions": ["Москва"],
        "website": f"https://s{i}.ru",
        "note": f"заметка {i}; менеджер Иванов И. {i} просил звонить после обеда",
        "contacts": [
            {
                "fullName": f"Иванов Иван Петрович {i}",
                "email": f"s{i}@x.ru",
                "phone": "+7 900 000 00 " + str(i % 100).zfill(2),
                "position": "менеджер",
            },
            {"fullName": "Петрова Анна Сергеевна", "phone": "8 (495) 123-45-67"},
        ],
        "terms": {"payment": "100% предоплата", "delivery": "самовывоз", "leadTime": "3 дня"},
    }


def _json_leaves(value: object) -> Iterator[str]:
    """Строки JSON в порядке обхода ядра (mapJson): ключ объекта, затем его значение."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _json_leaves(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _json_leaves(item)


def _unique(texts: list[str]) -> list[str]:
    """Уникальные тексты в порядке первого появления (повторы ядро берёт из кэша)."""
    return list(dict.fromkeys(texts))


def _corpora() -> dict[str, list[str]]:
    """Наборы текстов для сравнения пачки с одиночными вызовами."""
    tool_result = json.dumps({"suppliers": [_supplier(i) for i in range(SUPPLIERS)]})
    return {
        "pii_corpus": [text for text, _ in pii_corpus.POSITIVE] + list(pii_corpus.NEGATIVE),
        "recall_sets": [
            text
            for group in (recall_sets.EASY, recall_sets.HARD, recall_sets.FILES_PII,
                          recall_sets.CAPS_PII)
            for text, _ in group
        ]
        + list(recall_sets.FILES_CLEAN)
        + list(recall_sets.CAPS_CLEAN),
        "search_suppliers": _unique(list(_json_leaves(json.loads(tool_result)))),
    }


def _rows(store: SqliteReplacementStore) -> list[Row]:
    """Все записи таблицы замен в порядке вставки, с расшифрованными ключом и значением."""
    cursor = store._conn.execute(  # noqa: SLF001 - тест сверяет таблицу целиком
        "SELECT thread_id, token, pii_type, key_enc, value_enc FROM replacements ORDER BY rowid"
    )
    return [
        (thread, token, pii_type, store._decrypt(key, thread), store._decrypt(value, thread))  # noqa: SLF001
        for thread, token, pii_type, key, value in cursor.fetchall()
    ]


@pytest.fixture(params=sorted(_corpora()))
def corpus(request: pytest.FixtureRequest) -> list[str]:
    """Один из наборов текстов."""
    return _corpora()[request.param]


def test_batch_equals_sequential_calls_in_service(
    detector: PiiDetector, corpus: list[str]
) -> None:
    """Пачка = N одиночных вызовов: тексты, сущности, номера токенов, таблица замен."""
    key = Fernet.generate_key().decode()
    single_store = SqliteReplacementStore(":memory:", key)
    batch_store = SqliteReplacementStore(":memory:", key)
    single = Pseudonymizer(detector, single_store)
    batched = Pseudonymizer(detector, batch_store)

    expected = [single.pseudonymize(THREAD, text) for text in corpus]
    actual = batched.pseudonymize_batch(THREAD, corpus)

    assert actual == expected
    assert _rows(batch_store) == _rows(single_store)
    assert any(entities for _, entities in expected), "в наборе должны быть ПДн"


def test_batch_equals_sequential_calls_over_http(
    detector: PiiDetector, corpus: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """То же через HTTP, пачками по HTTP_CHUNK: стык пачек не сбивает нумерацию."""
    key = Fernet.generate_key().decode()
    single_store = SqliteReplacementStore(":memory:", key)
    batch_store = SqliteReplacementStore(":memory:", key)
    single = make_client(detector, monkeypatch, single_store, key=key)
    batched = make_client(detector, monkeypatch, batch_store, key=key)

    expected = [
        single.post("/pseudonymize", json={"thread_id": THREAD, "text": text}).json()
        for text in corpus
    ]
    actual: list[dict[str, object]] = []
    for start in range(0, len(corpus), HTTP_CHUNK):
        texts = corpus[start:start + HTTP_CHUNK]
        resp = batched.post("/pseudonymize_batch", json={"thread_id": THREAD, "texts": texts})
        assert resp.status_code == 200
        actual.extend(resp.json()["items"])

    assert actual == expected
    assert _rows(batch_store) == _rows(single_store)


def test_batch_continues_numbering_of_earlier_single_calls(service: Pseudonymizer) -> None:
    """Пачка после одиночного вызова продолжает нумерацию треда, а знакомые ФИО узнаёт."""
    first, _ = service.pseudonymize(THREAD, "Позвони Петрову Ивану Сергеевичу")
    assert first == "Позвони [PERSON_1]"
    items = service.pseudonymize_batch(
        THREAD, ["Петров И.С. на связи", "Сидоров Пётр Алексеевич", "Петров"]
    )
    assert [text for text, _ in items] == [
        "[PERSON_1] на связи",
        "[PERSON_2]",
        "[PERSON_1]",
    ]


def test_batch_detects_each_text_separately(service: Pseudonymizer) -> None:
    """Склейки нет: фамилия на границе двух листьев не сливается с соседним текстом."""
    texts = ["Иванов", "Иван Петрович", "+7 916 123 45 67", ""]
    batch = service.pseudonymize_batch(THREAD, texts)
    assert [text for text, _ in batch][2:] == ["[PHONE_1]", ""]
    assert len(batch) == len(texts)


def test_batch_response_shape_and_no_originals(client: TestClient) -> None:
    resp = client.post(
        "/pseudonymize_batch",
        json={"thread_id": "t1", "texts": ["Позвони Петрову", "почта petrov@firma.ru", ""]},
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "items": [
            {"text": "Позвони [PERSON_1]", "entities": [{"type": "PERSON", "token": "[PERSON_1]"}]},
            {"text": "почта [EMAIL_1]", "entities": [{"type": "EMAIL", "token": "[EMAIL_1]"}]},
            {"text": "", "entities": []},
        ]
    }
    assert "Петров" not in resp.text and "petrov@" not in resp.text
    restored = client.post("/restore", json={"thread_id": "t1", "text": "[PERSON_1] [EMAIL_1]"})
    assert restored.json()["text"] == "Петрову petrov@firma.ru"


def test_batch_empty_list(client: TestClient) -> None:
    resp = client.post("/pseudonymize_batch", json={"thread_id": "t1", "texts": []})
    assert resp.status_code == 200 and resp.json() == {"items": []}


def test_batch_requires_token(detector: PiiDetector, monkeypatch: pytest.MonkeyPatch) -> None:
    anonymous = make_client(detector, monkeypatch, headers=None)
    resp = anonymous.post("/pseudonymize_batch", json={"thread_id": "t1", "texts": ["x"]})
    assert resp.status_code == 401


def test_batch_validation_errors(client: TestClient) -> None:
    for body in ({"thread_id": "", "texts": []}, {"thread_id": "t"}):
        assert client.post("/pseudonymize_batch", json=body).status_code == 422


@pytest.mark.parametrize(
    ("overrides", "texts"),
    [
        ({"max_batch_items": 2}, ["Петров", "Сидоров", "Козлов"]),
        ({"max_text_chars": 20}, ["Звонил Петров " * 1, "Сидоров Пётр звонил"]),
    ],
)
def test_batch_over_limits_is_413_and_writes_nothing(
    detector: PiiDetector,
    store: SqliteReplacementStore,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, int],
    texts: list[str],
) -> None:
    """Пачка сверх пределов: 413 до обработки, в таблице ни одного токена, ПДн нет в ответе."""
    client = make_client(detector, monkeypatch, store, **overrides)
    resp = client.post("/pseudonymize_batch", json={"thread_id": "t1", "texts": texts})
    assert resp.status_code == 413
    assert "batch is too large" in resp.json()["detail"]
    assert "Петров" not in resp.text
    assert _rows(store) == []


def test_batch_with_too_long_text_is_422_like_single(
    detector: PiiDetector, store: SqliteReplacementStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Один слишком длинный текст: 422, как у /pseudonymize, и ничего не записано."""
    client = make_client(detector, monkeypatch, store, max_text_chars=30)
    texts = ["Петров", "Секретный текст Сидорова " * 3]
    resp = client.post("/pseudonymize_batch", json={"thread_id": "t1", "texts": texts})
    assert resp.status_code == 422 and "limit is 30" in resp.json()["detail"]
    assert "Секретный" not in resp.text
    assert _rows(store) == []


def test_batch_items_limit_from_env() -> None:
    key = Fernet.generate_key().decode()
    base = {ENV_KEY: key, ENV_API_TOKEN: "x"}
    assert load_settings(base).max_batch_items == DEFAULT_MAX_BATCH_ITEMS
    env = {**base, "PSEUDONYMIZER_MAX_BATCH_ITEMS": "10"}
    assert load_settings(env).max_batch_items == 10


def test_batch_cost_boundary(
    detector: PiiDetector, store: SqliteReplacementStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Пачка из одного текста = одиночный предел; каждый следующий текст дороже на цену текста."""
    limit = BATCH_ITEM_COST_CHARS + 10
    client = make_client(detector, monkeypatch, store, max_text_chars=limit)
    one = client.post("/pseudonymize_batch", json={"thread_id": "t", "texts": ["x" * limit]})
    assert one.status_code == 200
    fits = ["x" * 5, "x" * 5]
    assert batch_cost_chars(fits) == limit
    assert client.post(
        "/pseudonymize_batch", json={"thread_id": "t", "texts": fits}
    ).status_code == 200
    over = ["x" * 5, "x" * 6]
    assert client.post(
        "/pseudonymize_batch", json={"thread_id": "t", "texts": over}
    ).status_code == 413


def test_batch_worst_time_fits_client_timeout() -> None:
    """Худшая пачка по пределам не дольше худшего одиночного текста (та же доля таймаута)."""
    budget = WORST_CASE_TIMEOUT_SHARE * CLIENT_TIMEOUT_SECONDS
    assert DEFAULT_MAX_TEXT_CHARS * WORST_SECONDS_PER_CHAR <= budget
    # цена текста в символах переводится обратно во время не меньше замеренной
    assert BATCH_ITEM_COST_CHARS * WORST_SECONDS_PER_CHAR >= BATCH_ITEM_SECONDS * 0.99
    assert DEFAULT_MAX_BATCH_ITEMS * BATCH_ITEM_SECONDS <= budget


def test_lazy_person_index_sees_names_added_earlier_in_same_text(service: Pseudonymizer) -> None:
    """Индекс ФИО строится лениво: ФИО, заведённое раньше в том же тексте, в нём учтено."""
    text, _ = service.pseudonymize(
        THREAD, "Звонил Петров Иван Сергеевич, +7 916 123 45 67. Петров И.С. ждёт ответа"
    )
    assert text == "Звонил [PERSON_1], [PHONE_1]. [PERSON_1] ждёт ответа"
    # ветка без нечёткого поиска (точное совпадение ключа) индекс не строит, токен тот же
    again, _ = service.pseudonymize(THREAD, "Петров Иван Сергеевич")
    assert again == "[PERSON_1]"
