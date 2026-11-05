"""Без `case_labels` (и при false) ответы побайтно как до появления поля: эталон по корпусу."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from labops_pii.detector import PiiDetector
from tests.labops_pseudonymizer.conftest import make_client
from tests.labops_pseudonymizer.corpus_snapshot import BASELINE_PATH, dump, take_snapshot


@pytest.fixture
def corpus_client(detector: PiiDetector, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Клиент с настоящим детектором и свежим хранилищем."""
    return make_client(detector, monkeypatch)


@pytest.mark.parametrize("extra", [{}, {"case_labels": False}], ids=["no_field", "false"])
def test_corpus_matches_baseline(corpus_client: TestClient, extra: dict[str, bool]) -> None:
    baseline = BASELINE_PATH.read_text(encoding="utf-8")
    assert dump(take_snapshot(corpus_client, extra)) == baseline
