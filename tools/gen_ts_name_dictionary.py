"""Генерация словаря имён и фамилий для TS-детектора из словаря pymorphy3 (OpenCorpora).

TS-детектор работает без NLP-зависимостей, поэтому морфологию Python-части (pymorphy3)
сворачиваем в данные: парадигмы (окончания с ролью формы) и основы слов. Проверка слова в
TS: перебрать разбиение «основа + окончание» и сверить с парадигмой. Это точно повторяет
словарные формы pymorphy и в десятки раз компактнее списка всех форм.

Отчества в данные не входят: они однозначно распознаются по суффиксам (правило в TS).
Множественное число не входит (фамилии во мн. ч. ловит суффиксное правило в контексте).

Запуск: .venv/bin/python tools/gen_ts_name_dictionary.py
Результат: ts/src/detector/dictionary/name-dictionary-data.ts (не править руками).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

import pymorphy3

logger = logging.getLogger("gen_ts_name_dictionary")

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "ts" / "src" / "detector" / "dictionary" / "name-dictionary-data.ts"

# Битовые роли формы (те же значения в TS: см. name-dictionary.ts)
ROLE_SURNAME = 1
ROLE_NAME = 2
GRAMME_ROLES = (("Surn", ROLE_SURNAME), ("Name", ROLE_NAME))
# Слабое слово: главный разбор леммы не имя/фамилия (Вера, Роман, Мельник). Одно такое
# слово без соседей-имён ФИО не доказывает.
FLAG_WEAK = 4


def form_role(tag: object) -> int:
    """Роль формы по тегу pymorphy: 0, если это не единственное число имени/фамилии."""
    text = str(tag)
    if "plur" in text:
        return 0
    role = 0
    for gramme, bit in GRAMME_ROLES:
        if gramme in text.replace(",", " ").split():
            role |= bit
    return role


def main() -> None:
    """Собирает парадигмы и основы и пишет TS-файл с данными."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    morph = pymorphy3.MorphAnalyzer()
    dic = morph.dictionary
    paradigms: dict[int, list[tuple[str, int]]] = {}
    for pid in range(len(dic.paradigms)):
        info = dic.build_paradigm_info(pid)
        forms = [(suffix, form_role(tag)) for prefix, tag, suffix in info if prefix == ""]
        if any(role for _, role in forms):
            paradigms[pid] = forms
    logger.info("парадигм с именами/фамилиями: %d", len(paradigms))

    stems: dict[int, set[str]] = defaultdict(set)
    for word, (pid, idx) in dic.words.items():
        if idx != 0 or pid not in paradigms:
            continue
        suffix0 = paradigms[pid][0][0]
        if suffix0 and not word.endswith(suffix0):
            continue
        stems[pid].add(word[: len(word) - len(suffix0)].replace("ё", "е"))
    logger.info("лексем: %d", sum(len(s) for s in stems.values()))

    # Нумерация парадигм по порядку, окончания без ё; пустые роли отбрасываются
    lines_paradigms: list[str] = []
    lines_strong: list[str] = []
    lines_weak: list[str] = []
    weak_forms: set[str] = set()
    forms_of = {pid: [(s.replace("ё", "е"), r) for s, r in f] for pid, f in paradigms.items()}
    for new_id, pid in enumerate(sorted(stems)):
        forms = {}
        for suffix, role in paradigms[pid]:
            if role:
                forms[suffix.replace("ё", "е")] = forms.get(suffix.replace("ё", "е"), 0) | role
        lines_paradigms.append(",".join(f"{s}:{r}" for s, r in sorted(forms.items())))
        suffix0 = paradigms[pid][0][0].replace("ё", "е")
        strong: list[str] = []
        weak: list[str] = []
        for stem in sorted(stems[pid]):
            lemma = stem + suffix0
            parses = morph.parse(lemma)
            primary = parses[0] if parses else None
            is_name = primary is not None and form_role(primary.tag) != 0
            (strong if is_name else weak).append(stem)
            if not is_name:
                continue
            # Отдельная форма сильной лексемы может быть обычным словом («Машина» от
            # фамилии «Машин»): такие формы перечисляем явно, чтобы они считались слабыми
            for suffix, role in forms_of[pid]:
                if not role or not suffix:
                    continue
                form = stem + suffix
                best = morph.parse(form)[0]
                if form_role(best.tag) == 0:
                    weak_forms.add(form)
        lines_strong.append(" ".join(strong))
        lines_weak.append(" ".join(weak))
        _ = new_id
    body = [
        "// Сгенерировано tools/gen_ts_name_dictionary.py из словаря pymorphy3. Не править руками.",
        "",
        "/** Парадигмы: «окончание:роль» через запятую; роль: 1 фамилия, 2 имя (битовая маска). */",
        "export const NAME_PARADIGMS: readonly string[] = " + _js_array(lines_paradigms) + ";",
        "",
        "/** Основы «сильных» слов по номеру парадигмы (через пробел). */",
        "export const NAME_STEMS_STRONG: readonly string[] = " + _js_array(lines_strong) + ";",
        "",
        "/** Основы «слабых» слов (главный разбор леммы не имя): Вера, Роман, Мельник. */",
        "export const NAME_STEMS_WEAK: readonly string[] = " + _js_array(lines_weak) + ";",
        "",
        "/** Отдельные формы сильных слов, которые в тексте обычно обычные слова. */",
        "export const NAME_WEAK_FORMS: readonly string[] = "
        + _js_array(sorted(weak_forms)) + ";",
        "",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(body), encoding="utf-8")
    logger.info("записано %s (%d КБ)", OUT, OUT.stat().st_size // 1024)


def _js_array(items: list[str]) -> str:
    """Литерал массива строк для TS (по одной строке на элемент)."""
    escaped = [item.replace("\\", "\\\\").replace("'", "\\'") for item in items]
    return "[\n" + "".join(f"  '{item}',\n" for item in escaped) + "]"


if __name__ == "__main__":
    main()
