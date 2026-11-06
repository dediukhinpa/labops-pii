#!/usr/bin/env python3
"""Кладёт версию labops-pii в vendor/labops-pii/ проекта и пишет VERSION с хешами файлов.

Проект зовёт эту команду из своего скрипта (scripts/update-pii-lib.sh <тег>); сеть при сборке
образов не нужна: библиотека лежит в репозитории проекта. Содержимое берётся из git по ссылке
(тег или коммит), а не из рабочей папки, поэтому незакоммиченные правки не попадут.

Части (--parts, через запятую):
  guard    режим «только проверка»: labops_pii/{__init__,errors,pii_patterns,allowlist}.py и
           guard/ (без natasha и pymorphy: образ шлюза остаётся лёгким);
К каждой части добавляются все модули пакета, которые она импортирует (транзитивно).
  service  ядро и HTTP-сервис псевдонимизации (всё, кроме guard/ и media/);
  media    labops_pii/media/ (extras: Pillow, OpenCV, pypdfium2);
  ts       TS-пакет @labops/pii: ts/src, ts/package.json, ts/bun.lock, ts/LICENSE
           (в vendor/labops-pii/ts/; зависимости ставит проект: bun install --production там же).
По умолчанию: guard,service,media (ts берётся только по явной просьбе: нужен лишь TS-проектам).

Пример:
  tools/vendor.py --dest ~/project --ref v0.1.0 --parts guard
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import logging
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = "python/labops_pii"
VENDOR_SUBDIR = Path("vendor") / "labops-pii"
VERSION_FILE = "VERSION"
DEFAULT_REF = "origin/prod"
ALL_PARTS = ("guard", "service", "media", "ts")
DEFAULT_PARTS = ("guard", "service", "media")
TS_DIR = "ts"
# Из ts/ вендорятся исходники, манифест и lock: тесты и node_modules остаются в библиотеке.
# Lock нужен проекту, чтобы `bun install --frozen-lockfile` в vendor/labops-pii/ts ставил zod
# той же версии: без node_modules рядом вендоренный код не находит zod.
TS_FILES = ("ts/package.json", "ts/bun.lock")
TS_SRC_PREFIX = "ts/src/"
# Файлы верхнего уровня пакета, нужные guard без морфологии
GUARD_TOP_FILES = frozenset({"__init__.py", "errors.py", "pii_patterns.py"})
EXTRA_FILES = ("LICENSE",)
HASH_ALGORITHM = "sha256"
PACKAGE_NAME = "labops_pii"
logger = logging.getLogger("vendor")
HEADER = (
    "# labops-pii: вендоренная копия. Не править руками — тест проекта сверяет хеши.\n"
    "# Обновление: tools/vendor.py из репозитория labops-pii (новый тег -> PR в проекте).\n"
)


def run_git(*args: str) -> bytes:
    """Выполняет git в репозитории библиотеки и возвращает stdout."""
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], check=True, capture_output=True
    ).stdout


def wanted(relative: PurePosixPath, parts: set[str]) -> bool:
    """Входит ли файл пакета в выбранные части."""
    if "__pycache__" in relative.parts or relative.suffix == ".pyc":
        return False
    head = relative.parts[0]
    if head == "guard":
        return "guard" in parts
    if head == "media":
        return "media" in parts
    if len(relative.parts) == 1:
        # Верхний уровень: guard берёт только свои файлы, service — остальное
        return ("guard" in parts and relative.name in GUARD_TOP_FILES) or "service" in parts
    return "service" in parts


def collect_ts(ref: str) -> dict[str, bytes]:
    """Файлы TS-части из git: ts/src/**, package.json, bun.lock и копия LICENSE как ts/LICENSE."""
    archive = run_git("archive", "--format=tar", ref, TS_DIR, *EXTRA_FILES)
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read()
            if member.name in EXTRA_FILES:
                # Каталог ts/ должен быть самодостаточным (лицензия рядом с кодом)
                files[f"{TS_DIR}/{member.name}"] = data
            elif member.name in TS_FILES or member.name.startswith(TS_SRC_PREFIX):
                files[member.name] = data
    return files


def imported_modules(source: bytes, module: str) -> set[str]:
    """Модули пакета labops_pii, которые импортирует файл (абсолютные и относительные импорты).

    Args:
        source: Текст файла.
        module: Полное имя модуля файла (для `__init__.py` - `<пакет>.__init__`), нужно для
            относительных импортов.
    """
    found: set[str] = set()
    package = module.rsplit(".", 1)[0]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - node.level + 1]
                name = ".".join([*base, node.module] if node.module else base)
            else:
                name = node.module or ""
            found.add(name)
            # `from labops_pii import allowlist` импортирует подмодуль
            found.update(f"{name}.{a.name}" for a in node.names)
    return {m for m in found if m == PACKAGE_NAME or m.startswith(f"{PACKAGE_NAME}.")}


def module_files(module: str) -> tuple[str, str]:
    """Возможные файлы модуля внутри vendor: `a/b.py` и `a/b/__init__.py`."""
    path = module.replace(".", "/")
    return f"{path}.py", f"{path}/__init__.py"


def file_module(name: str) -> str:
    """Имя модуля по пути файла в vendor (`labops_pii/guard/__init__.py` -> `labops_pii.guard`)."""
    stem = name[: -len(".py")]
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    return stem.replace("/", ".")


def add_import_closure(files: dict[str, bytes], available: dict[str, bytes]) -> list[str]:
    """Дополняет выбранные файлы всеми модулями пакета, которые они импортируют (транзитивно).

    Без этого часть guard ссылалась на allowlist.py, а media - на config/detector, которых в
    этих частях не было, и вендоренный код падал на импорте (в dev-venv ошибку прятала
    editable-установка библиотеки). Добавляются и `__init__.py` родительских пакетов.

    Returns:
        Добавленные пути (для журнала).
    """
    added: list[str] = []
    queue = [n for n in files if n.endswith(".py")]
    while queue:
        name = queue.pop()
        module = file_module(name)
        # Для пакета относительные импорты считаются от него самого, для модуля - от родителя
        context = f"{module}.__init__" if name.endswith("/__init__.py") else module
        wanted_modules = imported_modules(files[name], context)
        parents = module.split(".")
        wanted_modules.update(".".join(parents[:i]) for i in range(1, len(parents)))
        for dep in wanted_modules:
            for candidate in module_files(dep):
                if candidate in available and candidate not in files:
                    files[candidate] = available[candidate]
                    added.append(candidate)
                    queue.append(candidate)
    return sorted(added)


def collect(ref: str, parts: set[str]) -> dict[str, bytes]:
    """Файлы выбранных частей из git по ссылке: путь внутри vendor/labops-pii -> байты."""
    files: dict[str, bytes] = collect_ts(ref) if "ts" in parts else {}
    if not parts - {"ts"}:
        return files
    available: dict[str, bytes] = {}
    archive = run_git("archive", "--format=tar", ref, PACKAGE_DIR, *EXTRA_FILES)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            path = PurePosixPath(member.name)
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read()
            if member.name in EXTRA_FILES:
                files[member.name] = data
                continue
            relative = path.relative_to(PACKAGE_DIR)
            if "__pycache__" in relative.parts or relative.suffix == ".pyc":
                continue
            available[f"labops_pii/{relative}"] = data
            if wanted(relative, parts):
                files[f"labops_pii/{relative}"] = data
    for name in add_import_closure(files, available):
        logger.info("добавлено по импорту: %s", name)
    return files


def sha256_hex(data: bytes) -> str:
    """Хеш содержимого."""
    return hashlib.new(HASH_ALGORITHM, data).hexdigest()


def render_version(ref: str, commit: str, parts: set[str], files: dict[str, bytes]) -> str:
    """Текст VERSION: ссылка, коммит, части и хеш каждого файла."""
    try:
        described = run_git("describe", "--tags", "--exact-match", ref).decode().strip()
    except subprocess.CalledProcessError:
        described = "(без тега)"
    lines = [
        HEADER.rstrip("\n"),
        f"ref: {ref}",
        f"tag: {described}",
        f"commit: {commit}",
        f"parts: {','.join(sorted(parts))}",
        f"vendored_at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"hash_algorithm: {HASH_ALGORITHM}",
        "files:",
    ]
    lines += [f"  {sha256_hex(data)}  {name}" for name, data in sorted(files.items())]
    return "\n".join(lines) + "\n"


def main() -> int:
    """Точка входа."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, required=True, help="корень проекта-потребителя")
    # Базовая ветка репозитория - prod (main нет): по умолчанию вендорится она
    parser.add_argument("--ref", default=DEFAULT_REF, help="тег или коммит библиотеки")
    parser.add_argument("--parts", default=",".join(DEFAULT_PARTS))
    args = parser.parse_args()
    parts = {p.strip() for p in args.parts.split(",") if p.strip()}
    unknown = parts - set(ALL_PARTS)
    if unknown:
        logger.error("неизвестные части: %s", sorted(unknown))
        return 2
    if not args.dest.is_dir():
        logger.error("нет каталога проекта: %s", args.dest)
        return 2
    # ^{commit}: у аннотированного тега rev-parse без суффикса даёт хеш объекта тега, а в
    # VERSION нужен коммит (до 0.8.0 туда попадал хеш тега, и сверка с git log не сходилась)
    commit = run_git("rev-parse", f"{args.ref}^{{commit}}").decode().strip()
    files = collect(args.ref, parts)
    if not files:
        logger.error("нечего вендорить: проверьте --ref и --parts")
        return 1
    target = args.dest / VENDOR_SUBDIR
    if target.exists():
        shutil.rmtree(target)  # старые файлы не должны переживать обновление
    for name, data in files.items():
        out = target / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    (target / VERSION_FILE).write_text(
        render_version(args.ref, commit, parts, files), encoding="utf-8"
    )
    logger.info("%d файлов -> %s (коммит %s)", len(files), target, commit[:8])
    return 0


if __name__ == "__main__":
    sys.exit(main())
