"""Тесты пределов /restore, пакетного чтения таблицы замен и времени худшего запроса."""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from labops_pii.config import (
    CLIENT_TIMEOUT_SECONDS,
    DEFAULT_MAX_RESTORE_TOKENS,
    DEFAULT_MAX_TEXT_CHARS,
    ENV_API_TOKEN,
    ENV_KEY,
    ENV_MAX_RESTORE_TOKENS,
    WORST_CASE_TIMEOUT_SHARE,
    WORST_SECONDS_PER_CHAR,
    ConfigError,
    load_settings,
)
from labops_pii.detector import PiiDetector
from labops_pii.service import Pseudonymizer, TooManyTokensError
from labops_pii.store import SqliteReplacementStore
from tests.sqlite_v2_pseudonymizer.conftest import API_TOKEN, make_client

FIRST_NAMES = ("Иван", "Пётр", "Сергей", "Алексей", "Николай", "Дмитрий")
SYLLABLES = ("ва", "ко", "ри", "но", "се", "ми", "ла", "ту", "бе", "зо")
SAMPLE_CHARS = 10_000
# Допуск теста на времени: замер на образце шумит, поэтому граница мягче расчётной доли.
MEASURED_TIMEOUT_SHARE = 0.85


def _many_people(chars: int) -> str:
    """Плотный поток разных ФИО: худший для сервиса текст (каждое ФИО это новый токен)."""
    rnd = random.Random(7)
    parts: list[str] = []
    size = 0
    while size < chars:
        surname = "".join(rnd.choice(SYLLABLES) for _ in range(3)).capitalize() + "ов"
        parts.append(f"{surname} {rnd.choice(FIRST_NAMES)} Петрович, ")
        size += len(parts[-1])
    return "".join(parts)[:chars]


def _statements(store: SqliteReplacementStore) -> list[str]:
    """Включает запись выполняемых SQL-операторов хранилища."""
    seen: list[str] = []
    store._conn.set_trace_callback(seen.append)  # noqa: SLF001
    return seen


def test_restore_rejects_too_long_text_without_echo(
    detector: PiiDetector, store: SqliteReplacementStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client(detector, monkeypatch, store, max_text_chars=50)
    resp = client.post("/restore", json={"thread_id": "t", "text": "Секретный текст " * 10})
    assert resp.status_code == 422
    assert "limit is 50" in resp.json()["detail"]
    assert "Секретный" not in resp.text
    assert client.post("/restore", json={"thread_id": "t", "text": "x" * 50}).status_code == 200


def test_restore_rejects_too_many_tokens(
    detector: PiiDetector, store: SqliteReplacementStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client(detector, monkeypatch, store, max_restore_tokens=3)
    many = " ".join(f"[PERSON_{i}]" for i in range(1, 5))
    resp = client.post("/restore", json={"thread_id": "t", "text": many})
    assert resp.status_code == 422 and "limit is 3" in resp.json()["detail"]
    # повторы одного токена лимит не расходуют: запрос к таблице по нему один
    same = " ".join(["[PERSON_1]"] * 50 + ["[PHONE_1]", "[EMAIL_1]"])
    assert client.post("/restore", json={"thread_id": "t", "text": same}).status_code == 200


def test_restore_service_raises_on_token_flood(service: Pseudonymizer) -> None:
    flood = "".join(f"[X_{i}]" for i in range(DEFAULT_MAX_RESTORE_TOKENS + 1))
    with pytest.raises(TooManyTokensError):
        service.restore("t", flood)


def test_restore_reads_table_in_one_query(
    service: Pseudonymizer, store: SqliteReplacementStore
) -> None:
    """Все токены текста читаются одним запросом, а не запросом под блокировкой на каждый."""
    people = ", ".join(f"Иван {name}" for name in ("Петров", "Сидоров", "Козлов", "Орлов"))
    text = f"{people}; +7 (902) 123-45-67; a@x.ru; b@x.ru"
    masked, entities = service.pseudonymize("t1", text)
    assert len(entities) >= 6
    foreign = " ".join(f"[ORG_{i}]" for i in range(1, 200))  # похожи на токены, в треде их нет
    seen = _statements(store)
    assert service.restore("t1", f"{masked} {foreign}") == f"{text} {foreign}"
    assert len([s for s in seen if s.lstrip().upper().startswith("SELECT")]) == 1


def test_restore_batches_above_sql_parameter_limit(store: SqliteReplacementStore) -> None:
    from labops_pii.store import LOOKUP_BATCH

    count = LOOKUP_BATCH + 10
    with store.batch():
        for i in range(count):
            store.add("t", f"[EMAIL_{i}]", "EMAIL", f"k{i}", f"v{i}@x.ru")
    tokens = [f"[EMAIL_{i}]" for i in range(count)] + ["[EMAIL_999999]"]
    seen = _statements(store)
    found = store.get_originals("t", tokens)
    assert len(found) == count and found["[EMAIL_7]"] == "v7@x.ru"
    assert len(seen) == 2
    assert store.get_originals("other", tokens) == {}
    assert store.get_originals("t", []) == {}


def test_pseudonymize_commits_once_and_rolls_back_on_failure(
    service: Pseudonymizer, store: SqliteReplacementStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _statements(store)
    service.pseudonymize("t1", "Иван Петров, Олег Сидоров, a@x.ru, b@x.ru, c@x.ru")
    assert len([s for s in seen if s.strip().upper() == "COMMIT"]) == 1
    assert store.count("t1", "EMAIL") == 3

    calls = {"n": 0}
    real_add = store.add

    def failing_add(*args: str) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("сбой записи")
        real_add(*args)

    monkeypatch.setattr(store, "add", failing_add)
    with pytest.raises(RuntimeError):
        service.pseudonymize("t2", "d@x.ru, e@x.ru, f@x.ru")
    # запрос не удался целиком: ни один его токен не остался в таблице
    assert store.count("t2", "EMAIL") == 0


def test_person_matching_unchanged_by_index(service: Pseudonymizer) -> None:
    """Сопоставление форм ФИО через индекс по словам даёт те же токены, что полный перебор."""
    out, _ = service.pseudonymize("t1", "Иванов Пётр и Иванов Олег приехали, Сидоров А.В. тоже")
    assert out.count("[PERSON_") == 3
    again, _ = service.pseudonymize("t1", "Иванову Петру передали, Сидорову тоже")
    assert "[PERSON_1]" in again and "[PERSON_3]" in again
    # одиночная фамилия с двумя кандидатами неоднозначна: существующий токен не выбирается
    ambiguous, entities = service.pseudonymize("t1", "Письмо от Иванова Игоря получено")
    assert [e.token for e in entities] == ["[PERSON_4]"]
    assert ambiguous.startswith("Письмо от [PERSON_4]")


def _initials(chars: int) -> str:
    """Текст из одних инициалов: самый медленный для детектора из найденных."""
    return ("А. Б. В. Г. " * (chars // 12 + 1))[:chars]


@pytest.mark.parametrize("make_text", [_many_people, _initials])
def test_worst_case_request_fits_client_timeout(
    detector: PiiDetector, fernet_key: str, tmp_path: Path, make_text: Callable[[int], str]
) -> None:
    """Худшие тексты на базе в файле: время на предельную длину меньше таймаута клиента.

    Замеряется образец в 10 тыс. символов и пересчитывается на предел по умолчанию
    (после перехода на один коммит и индекс ФИО время линейно по длине).
    """
    store = SqliteReplacementStore(tmp_path / "w.sqlite3", fernet_key)
    service = Pseudonymizer(detector, store)
    text = make_text(SAMPLE_CHARS)
    start = time.perf_counter()
    service.pseudonymize("t", text)
    elapsed = time.perf_counter() - start
    store.close()
    projected = elapsed / SAMPLE_CHARS * DEFAULT_MAX_TEXT_CHARS
    assert projected < CLIENT_TIMEOUT_SECONDS * MEASURED_TIMEOUT_SHARE


def test_default_text_limit_follows_measured_worst_case() -> None:
    """Умолчание выведено из замера: худший случай занимает заданную долю таймаута."""
    worst = DEFAULT_MAX_TEXT_CHARS * WORST_SECONDS_PER_CHAR
    assert worst <= CLIENT_TIMEOUT_SECONDS * WORST_CASE_TIMEOUT_SHARE
    assert DEFAULT_MAX_TEXT_CHARS >= 60_000  # страница прайса, которую ядро шлёт целиком


def test_max_restore_tokens_config(fernet_key: str) -> None:
    base = {ENV_KEY: fernet_key, ENV_API_TOKEN: API_TOKEN}
    assert load_settings(base).max_restore_tokens == DEFAULT_MAX_RESTORE_TOKENS
    custom = load_settings({**base, ENV_MAX_RESTORE_TOKENS: "7"})
    assert custom.max_restore_tokens == 7
    with pytest.raises(ConfigError):
        load_settings({**base, ENV_MAX_RESTORE_TOKENS: "0"})
