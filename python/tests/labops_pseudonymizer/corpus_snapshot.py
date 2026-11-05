"""Снимок ответов /pseudonymize и /pseudonymize_batch на всём корпусе (эталон без падежных меток).

Эталон `fixtures/corpus_baseline.json` снят на коде до появления поля `case_labels`:
запрос без поля и с `case_labels=false` обязан давать побайтно тот же ответ.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from tests.labops_pseudonymizer import pii_corpus, recall_sets

BASELINE_PATH = Path(__file__).parent / "fixtures" / "corpus_baseline.json"
BATCH_THREAD = "corpus-batch"


def corpus_texts() -> list[str]:
    """Все тексты корпуса и наборов полноты в стабильном порядке."""
    texts = [text for text, _ in pii_corpus.POSITIVE] + list(pii_corpus.NEGATIVE)
    for name in ("EASY", "HARD", "FILES_PII", "CAPS_PII"):
        texts += [text for text, _ in getattr(recall_sets, name)]
    for name in ("FILES_CLEAN", "CAPS_CLEAN"):
        texts += list(getattr(recall_sets, name))
    return texts


def take_snapshot(client: TestClient, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Ответы сервиса: каждый текст в своём треде (одиночно) и все разом одной пачкой.

    Args:
        client: HTTP-клиент поверх приложения.
        extra: Дополнительные поля тела запроса (например, `{"case_labels": False}`).
    """
    extra = extra or {}
    texts = corpus_texts()
    single = [
        client.post("/pseudonymize", json={"thread_id": f"t{i}", "text": text, **extra}).json()
        for i, text in enumerate(texts)
    ]
    batch = client.post(
        "/pseudonymize_batch", json={"thread_id": BATCH_THREAD, "texts": texts, **extra}
    ).json()
    return {"single": single, "batch": batch}


def dump(snapshot: dict[str, Any]) -> str:
    """Каноническая JSON-запись снимка."""
    return json.dumps(snapshot, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def write_baseline() -> None:
    """Перезаписывает эталон текущим кодом библиотеки (после осознанного изменения поведения).

    Исходный эталон labops e271609 хранится рядом (`corpus_baseline_e271609.json`): расхождения
    между ними разобраны в tests/fixtures/accepted_divergences.json и CHANGELOG.
    """
    import pytest

    from labops_pii.detector import PiiDetector
    from tests.env_sets import apply_env_set
    from tests.labops_pseudonymizer.conftest import make_client

    apply_env_set("labops")
    client = make_client(PiiDetector(), pytest.MonkeyPatch())
    BASELINE_PATH.write_text(dump(take_snapshot(client)), encoding="utf-8")


if __name__ == "__main__":
    write_baseline()
