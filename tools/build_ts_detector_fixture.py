"""Эталон для TS-детектора: Python-детектор (Natasha + правила) на общих корпусах.

Прогоняет `PiiDetector` профиля pragmatika (адреса включены, юрлица нет) на корпусах из
`python/tests/fixtures` и тестов, сохраняет найденные спаны ФИО (PERSON) и адресов (ADDRESS)
в `ts/tests/fixtures/detector_parity.json`. TS-тест сравнивает свой детектор с этим эталоном
по перекрытию спанов и проверяет пороги полноты и ложных срабатываний.

Запуск: .venv/bin/python tools/build_ts_detector_fixture.py
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
from pathlib import Path
from types import ModuleType

logger = logging.getLogger("build_ts_detector_fixture")

ROOT = Path(__file__).resolve().parents[1]
PY_DIR = ROOT / "python"
FIXTURES = PY_DIR / "tests" / "fixtures"
TS_FIXTURES = ROOT / "ts" / "tests" / "fixtures"
OUT = TS_FIXTURES / "detector_parity.json"
# Настройка, с которой снят паритет (бывший профиль pragmatika): адреса ищутся, «прагматик» в
# белом списке; те же значения тесты TS-части передают параметрами детектора
DETECTOR_ENV = {"PSEUDONYMIZER_ADDRESS_MASK": "on", "PII_ALLOWED_WORDS": "прагматик"}
KINDS = {"PERSON": "person", "ADDRESS": "address"}
# Символы вне BMP: позиции в UTF-16 и в кодовых точках Python разошлись бы
BMP_MAX = 0xFFFF


def load_module(path: Path, name: str) -> ModuleType:
    """Загружает модуль по пути файла (наборы тестов не оформлены как пакет)."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect_corpora() -> list[dict[str, object]]:
    """Собирает тексты всех корпусов с пометкой источника."""
    items: list[dict[str, object]] = []

    def add(source: str, texts: list[str]) -> None:
        items.extend({"source": source, "text": text} for text in texts)

    labels = json.loads((FIXTURES / "names_labels.json").read_text(encoding="utf-8"))
    add("names_negative", labels["negative"])
    add("names_positive", labels["positive"])
    recall = load_module(PY_DIR / "tests" / "pragmatika_pseudonymizer" / "recall_sets.py", "rs")
    add("recall_easy", [t for t, _ in recall.EASY])
    add("recall_hard", [t for t, _ in recall.HARD])
    add("caps_pii", [t for t, _ in recall.CAPS_PII])
    add("caps_clean", list(recall.CAPS_CLEAN))
    addr = load_module(PY_DIR / "tests" / "pragmatika_pseudonymizer" / "test_address_patterns.py", "ap")
    add("address_positive", [t for t, _ in addr.POSITIVE])
    add("address_negative", list(addr.NEGATIVE))
    det = load_module(PY_DIR / "tests" / "pragmatika_pseudonymizer" / "test_address_detector.py", "ad")
    add("address_masked", [t for t, _ in det.MASKED])
    add("address_clean", list(det.CLEAN))
    pages = json.loads((TS_FIXTURES / "web_page_fragments.json").read_text(encoding="utf-8"))
    add("page_negative", pages["negative"])
    add("page_positive", pages["positive"])
    return items


def main() -> None:
    """Строит фикстуру паритета."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    os.environ.update(DETECTOR_ENV)
    sys.path.insert(0, str(PY_DIR))
    from labops_pii.detector import PiiDetector  # noqa: PLC0415 (окружение задано выше)

    detector = PiiDetector()
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in collect_corpora():
        text = str(item["text"])
        if text in seen or any(ord(ch) > BMP_MAX for ch in text):
            continue
        seen.add(text)
        spans: dict[str, list[list[int]]] = {"person": [], "address": []}
        for found in detector.detect(text):
            kind = KINDS.get(found.pii_type.value)
            if kind is not None:
                spans[kind].append([found.start, found.end])
        result.append({"source": item["source"], "text": text, **spans})
    OUT.write_text(json.dumps({"env": DETECTOR_ENV, "items": result}, ensure_ascii=False,
                              indent=1) + "\n", encoding="utf-8")
    logger.info("записано %d текстов в %s", len(result), OUT)


if __name__ == "__main__":
    main()
