"""Делает файлы SQLite исходными копиями (Прагматика: v2, labops: v3) для теста совместимости.

Запуск на коде исходной копии: `make_store_fixtures.py --src <каталог с пакетом pseudonymizer>
--name pragmatika`. Ключ Fernet здесь фиксированный тестовый (не секрет): файлы лежат в репо.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "python" / "tests" / "fixtures" / "stores"
# Тестовый ключ Fernet (32 нулевых байта в urlsafe base64); настоящих ключей в репо нет
TEST_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ROWS = [
    ("agent:7", "[PERSON_1]", "PERSON", "иванов иван", "Иванов Иван"),
    ("agent:7", "[PHONE_1]", "PHONE", "79161234567", "+7 916 123-45-67"),
    ("plain-thread", "[EMAIL_1]", "EMAIL", "a@b.ru", "a@b.ru"),
]


def main() -> None:
    """Пишет базу и ожидаемые значения слепых индексов."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--src", type=Path, required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.src))
    from pseudonymizer.store import SqliteReplacementStore

    OUT.mkdir(parents=True, exist_ok=True)
    db = OUT / f"{args.name}.sqlite3"
    db.unlink(missing_ok=True)
    store = SqliteReplacementStore(db, TEST_KEY)
    for row in ROWS:
        store.add(*row)
    hashes = {f"{t}|{k}": store._hash(t, k) if args.name == "labops" else store._hash(k)
              for t, _tok, _ty, k, _o in ROWS}
    store.close()
    (OUT / f"{args.name}.hashes.json").write_text(
        json.dumps({"key": TEST_KEY, "rows": ROWS, "hashes": hashes},
                   ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{db}")


if __name__ == "__main__":
    main()
