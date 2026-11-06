"""Собирает общий корпус текстов из наборов тестов всех трёх копий в один JSON.

Запускается один раз при изменении наборов: результат лежит в
python/tests/fixtures/common_corpus.json и читается и эталонными снимками исходных копий
(там библиотеки нет), и сверкой библиотеки.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "python" / "tests" / "fixtures" / "common_corpus.json"
TEXT_MODULES = (
    ("labops_pseudonymizer.pii_corpus", ("POSITIVE", "NEGATIVE")),
    ("sqlite_v2_pseudonymizer.pii_corpus", ("POSITIVE", "NEGATIVE")),
    ("edge_guard.pii_corpus", ("POSITIVE", "NEGATIVE")),
    ("labops_pseudonymizer.recall_sets", ("EASY", "HARD", "FILES_PII", "CAPS_PII",
                                          "FILES_CLEAN", "CAPS_CLEAN")),
    ("sqlite_v2_pseudonymizer.test_address_patterns", ("POSITIVE", "NEGATIVE")),
    ("sqlite_v2_pseudonymizer.test_address_detector", ("MASKED", "CLEAN")),
    ("sqlite_v2_pseudonymizer.test_card_price_row", ("PRICE_ROWS", "CARDS")),
    ("sqlite_v2_guard.test_names", ("POSITIVE", "NEGATIVE")),
    ("edge_guard.test_intl_phones", ("PHONES", "NOT_PHONES")),
)


def first_text(item: object) -> str | None:
    """Текст из элемента набора: сама строка или первый элемент кортежа."""
    if isinstance(item, str):
        return item
    if isinstance(item, (tuple, list)) and item and isinstance(item[0], str):
        return item[0]
    return None


def main() -> None:
    """Импортирует наборы, склеивает без повторов (порядок стабилен) и пишет JSON."""
    sys.path.insert(0, str(ROOT / "python" / "tests"))
    texts: list[str] = []
    seen: set[str] = set()
    for module_name, attrs in TEXT_MODULES:
        module = importlib.import_module(module_name)
        for attr in attrs:
            for item in getattr(module, attr):
                text = first_text(item)
                if text and text not in seen:
                    seen.add(text)
                    texts.append(text)
    OUT.write_text(json.dumps(texts, ensure_ascii=False, indent=0) + "\n", encoding="utf-8")
    print(f"{len(texts)} текстов -> {OUT}")


if __name__ == "__main__":
    main()
