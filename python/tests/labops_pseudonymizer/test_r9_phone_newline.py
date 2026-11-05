"""Ревью-9: телефон, у которого ключевое слово стоит на предыдущей строке (R9-A4-05)."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from labops_pii.detector import PiiDetector, PiiType
from labops_pii.service import Pseudonymizer

ROOT = Path(__file__).resolve().parents[3]
GUARD_ROOT = ROOT / "gateway" / "pii-guard"


def _phones(detector: PiiDetector, text: str) -> list[str]:
    """Фрагменты текста, найденные как телефон."""
    return [text[d.start:d.end] for d in detector.detect(text) if d.pii_type is PiiType.PHONE]


def _import_guard() -> ModuleType:
    """Детектор guard из того же пакета (раньше лежал в соседнем каталоге репозитория)."""
    return importlib.import_module("labops_pii.guard.detector")


# --- R9-A4-05: ключевое слово и номер на разных строках --------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "С уважением, Ольга\nмоб.\n9165550123",
        "Телефон:\n9165550123",
        "моб.\r\n9165550123",
        "phone:\n 9165550123",
    ],
)
def test_bare_phone_after_line_break_is_masked(detector: PiiDetector, text: str) -> None:
    assert _phones(detector, text) == ["9165550123"]


@pytest.mark.parametrize(
    "text",
    [
        "Телефон:\n\n9165550123",  # пустая строка разрывает связь метки и числа
        "тел " + "x" * 30 + "\n9165550123",  # промежуток длиннее BARE_PHONE_GAP
        "факс\nИНН 7707083893",  # верный ИНН телефоном не считается
    ],
)
def test_bare_phone_line_break_limits(detector: PiiDetector, text: str) -> None:
    assert _phones(detector, text) == []


@pytest.mark.parametrize(
    "text", ["С уважением, Ольга\nмоб.\n9165550123", "Телефон:\n9165550123"]
)
def test_bare_phone_line_break_parity_with_guard(service: Pseudonymizer, text: str) -> None:
    """Шлюз не видит телефона в замаскированном тексте и видит его в исходном."""
    guard = _import_guard()

    def body(content: str) -> bytes:
        message = {"messages": [{"role": "user", "content": content}]}
        return json.dumps(message, ensure_ascii=False).encode()

    masked, _ = service.pseudonymize("t-a405", text)
    assert "phone" in guard.scan_body(body(text), require_json=True)
    assert "phone" not in guard.scan_body(body(masked), require_json=True)
