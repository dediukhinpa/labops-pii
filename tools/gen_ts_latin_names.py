"""Генерация данных латинских ФИО для TS-детектора из Python-части (`labops_pii/latin_names.py`).

Словарь латинских имён (транслит русских имён и международные), суффиксы фамилий и отчеств
и слова, которые имя не продолжают, живут в Python. TS-детектор берёт их отсюда, а не из своей
копии: иначе списки разойдутся при первой правке.

Запуск: .venv/bin/python tools/gen_ts_latin_names.py
Результат: ts/src/detector/dictionary/latin-names-data.ts (не править руками).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "ts" / "src" / "detector" / "dictionary" / "latin-names-data.ts"
sys.path.insert(0, str(ROOT / "python"))

from labops_pii import latin_names  # noqa: E402

logger = logging.getLogger("gen_ts_latin_names")


def _js_array(items: list[str]) -> str:
    """Литерал массива строк для TS (по одной строке на элемент).

    Args:
        items: Строки массива.

    Returns:
        Текст литерала.
    """
    escaped = [item.replace("\\", "\\\\").replace("'", "\\'") for item in items]
    return "[\n" + "".join(f"  '{item}',\n" for item in escaped) + "]"


def render() -> str:
    """Текст модуля данных.

    Returns:
        Содержимое latin-names-data.ts.
    """
    body = [
        "// Сгенерировано tools/gen_ts_latin_names.py из python/labops_pii/latin_names.py.",
        "// Не править руками.",
        "",
        "/** Латинские имена: транслит русских имён и международные (строчными, ASCII). */",
        "export const LATIN_FIRST_NAMES: readonly string[] = "
        + _js_array(sorted(latin_names.LATIN_FIRST_NAMES)) + ";",
        "",
        "/** Окончания транслитерированных фамилий (строчными). */",
        "export const LATIN_SURNAME_SUFFIXES: readonly string[] = "
        + _js_array(list(latin_names.SURNAME_SUFFIXES)) + ";",
        "",
        "/** Окончания отчеств в транслите. */",
        "export const LATIN_PATRONYMIC_SUFFIXES: readonly string[] = "
        + _js_array(list(latin_names.PATRONYMIC_SUFFIXES)) + ";",
        "",
        "/** Слова, которые имя не продолжают: должности, технологии, приветствия. */",
        "export const LATIN_NOT_NAME_WORDS: readonly string[] = "
        + _js_array(sorted(latin_names.NOT_A_NAME_WORDS)) + ";",
        "",
        "/** Минимальная длина фамилии по суффиксу. */",
        f"export const LATIN_MIN_SURNAME_LEN = {latin_names.MIN_SURNAME_LEN};",
        "/** Минимальная длина отчества по суффиксу. */",
        f"export const LATIN_MIN_PATRONYMIC_LEN = {latin_names.MIN_PATRONYMIC_LEN};",
        "/** Неизвестное слово перед именем считается фамилией не короче этого. */",
        f"export const LATIN_MIN_UNKNOWN_SURNAME_LEN = {latin_names.MIN_UNKNOWN_SURNAME_LEN};",
        "/** Окно слов одной находки. */",
        f"export const LATIN_MAX_WORDS = {latin_names.LATIN_MAX_WORDS};",
        "/** Заглавные латинские буквы (с диакритикой), как в Python. */",
        f"export const LATIN_UPPER = '{latin_names.LATIN_UPPER}';",
        "/** Строчные латинские буквы (с диакритикой), как в Python. */",
        f"export const LATIN_LOWER = '{latin_names.LATIN_LOWER}';",
        "",
    ]
    return "\n".join(body)


def main() -> None:
    """Пишет модуль данных."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8")
    logger.info("записано %s (%d КБ)", OUT, OUT.stat().st_size // 1024)


if __name__ == "__main__":
    main()
