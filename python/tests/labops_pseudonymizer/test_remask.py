"""Второй проход маски: /remask_batch и Pseudonymizer.remask (вымышленные данные)."""

from __future__ import annotations

from collections.abc import Collection

from fastapi.testclient import TestClient

from labops_pii.detector import Detection, PiiDetector, PiiType
from labops_pii.service import REMASK_INNER_PASSES, Pseudonymizer
from labops_pii.store import MemoryReplacementStore

THREAD = "remask-thread"


class SpanDetector:
    """Детектор-заглушка: находит заданные подстроки как ФИО (ключ - сама подстрока)."""

    def __init__(self, *fragments: str, pii_type: PiiType = PiiType.PERSON) -> None:
        self._fragments = fragments
        self._type = pii_type

    def detect(self, text: str, known_lemmas: Collection[str] = ()) -> list[Detection]:
        found: list[Detection] = []
        for fragment in self._fragments:
            start = text.find(fragment)
            if start >= 0:
                found.append(Detection(
                    start, start + len(fragment), self._type, fragment.casefold(), 8
                ))
        return sorted(found, key=lambda d: d.start)


def test_remask_uses_same_numbering_and_table(service: Pseudonymizer) -> None:
    masked, _ = service.pseudonymize(THREAD, "Позвони Петрову")
    assert masked == "Позвони [PERSON_1]"
    # Второй проход: новое ФИО получает следующий номер, старое - прежний токен
    again, entities = service.remask(THREAD, "[PERSON_1] и Менеджер Сидоров сказал")
    assert again == "[PERSON_1] и Менеджер [PERSON_2] сказал"
    assert [e.token for e in entities] == ["[PERSON_2]"]
    # Оба токена восстанавливаются из одной таблицы
    assert service.restore(THREAD, again) == "Петрову и Менеджер Сидоров сказал"


def test_remask_is_idempotent(service: Pseudonymizer) -> None:
    once, _ = service.remask(THREAD, "Менеджер Сидоров сказал, +7 (902) 123-45-67")
    twice, entities = service.remask(THREAD, once)
    assert twice == once
    assert entities == []


def test_remask_keeps_case_labelled_tokens(service: Pseudonymizer) -> None:
    """В отличие от pseudonymize метка падежа во входе второго прохода не экранируется."""
    service.pseudonymize(THREAD, "Позвони Петрову")
    text = "Привет, [PERSON_1|datv], вот [PHONE_9] и Сидоров Пётр"
    out, _ = service.remask(THREAD, text)
    assert out.startswith("Привет, [PERSON_1|datv], вот [PHONE_9] и [PERSON_")
    assert "\u200b" not in out
    # Метка продолжает склонять токен при восстановлении
    assert service.restore(THREAD, out).startswith("Привет, Петрову, вот [PHONE_9] и ")


def test_remask_case_labels_for_new_tokens(service: Pseudonymizer) -> None:
    out, _ = service.remask(THREAD, "Передай Сидорову Петру привет", case_labels=True)
    assert out.startswith("Передай [PERSON_1|datv] привет")


def test_remask_swallowed_token_stores_original_not_token(store: MemoryReplacementStore) -> None:
    """Находка с токеном внутри: в таблицу идёт восстановленный оригинал, а не метка."""
    first = Pseudonymizer(SpanDetector("Петров"), store)
    masked, _ = first.pseudonymize(THREAD, "пришёл Петров Иван")
    assert masked == "пришёл [PERSON_1] Иван"
    second = Pseudonymizer(SpanDetector("[PERSON_1] Иван", pii_type=PiiType.CONTACT), store)
    out, _ = second.remask(THREAD, masked)
    restored = second.restore(THREAD, out)
    assert restored == "пришёл Петров Иван"
    assert "[PERSON_" not in restored


def test_remask_batch_matches_sequence(detector: PiiDetector) -> None:
    texts = ["Менеджер Сидоров сказал", "ещё раз Сидоров", "тел +7 (902) 123-45-67"]
    one = Pseudonymizer(detector, MemoryReplacementStore())
    many = Pseudonymizer(detector, MemoryReplacementStore())
    assert many.remask_batch(THREAD, texts) == [one.remask(THREAD, t) for t in texts]


def test_http_remask_batch(client: TestClient) -> None:
    resp = client.post(
        "/remask_batch",
        json={"thread_id": THREAD, "texts": ["Менеджер Сидоров сказал", "чисто"]},
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert items[0]["text"] == "Менеджер [PERSON_1] сказал"
    assert items[1] == {"text": "чисто", "entities": []}
    assert "Сидоров" not in resp.text


def test_http_remask_batch_requires_token(client: TestClient) -> None:
    resp = client.post(
        "/remask_batch",
        json={"thread_id": THREAD, "texts": ["x"]},
        headers={"Authorization": "Bearer wrong"},
    )
    assert resp.status_code == 401


def test_http_remask_batch_limits(client: TestClient) -> None:
    too_long = "а" * 200_000
    resp = client.post("/remask_batch", json={"thread_id": THREAD, "texts": [too_long]})
    assert resp.status_code in (413, 422)


class CascadeDetector:
    """Детектор-заглушка: за один вызов находит только первое из ещё не замаскированных слов."""

    def __init__(self, *words: str) -> None:
        self._words = words

    def detect(self, text: str, known_lemmas: Collection[str] = ()) -> list[Detection]:
        for word in self._words:
            start = text.find(word)
            if start >= 0:
                return [Detection(start, start + len(word), PiiType.CONTACT, word, 7)]
        return []


def test_remask_repeats_until_detector_is_quiet(store: MemoryReplacementStore) -> None:
    """Каждая замена открывает следующую находку: проход повторяется внутри одного вызова."""
    service = Pseudonymizer(CascadeDetector("Альфа", "Бета", "Гамма"), store)
    out, entities = service.remask(THREAD, "Альфа Бета Гамма")
    assert out == "[CONTACT_1] [CONTACT_2] [CONTACT_3]"
    assert len(entities) == 3


def test_remask_cascade_is_bounded(store: MemoryReplacementStore) -> None:
    words = tuple(f"Слово{chr(0x430 + i)}" for i in range(REMASK_INNER_PASSES + 2))
    service = Pseudonymizer(CascadeDetector(*words), store)
    out, entities = service.remask(THREAD, " ".join(words))
    assert len(entities) == REMASK_INNER_PASSES
    assert out.count("[CONTACT_") == REMASK_INNER_PASSES
