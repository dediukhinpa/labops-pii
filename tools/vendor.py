#!/usr/bin/env python3
"""Кладёт версию labops-pii в vendor/labops-pii/ проекта и пишет VERSION с хешами файлов.

Проект зовёт эту команду из своего скрипта (scripts/update-pii-lib.sh <тег>); сеть при сборке
образов не нужна: библиотека лежит в репозитории проекта. Содержимое берётся из git по ссылке
(тег или коммит), а не из рабочей папки, поэтому незакоммиченные правки не попадут.

Части (--parts, через запятую):
  guard    режим «только проверка»: labops_pii/{__init__,errors,pii_patterns}.py и guard/
           (без natasha и pymorphy: образ шлюза остаётся лёгким);
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
import hashlib
import io
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


def collect(ref: str, parts: set[str]) -> dict[str, bytes]:
    """Файлы выбранных частей из git по ссылке: путь внутри vendor/labops-pii -> байты."""
    files: dict[str, bytes] = collect_ts(ref) if "ts" in parts else {}
    if not parts - {"ts"}:
        return files
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
            if wanted(relative, parts):
                files[f"labops_pii/{relative}"] = data
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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, required=True, help="корень проекта-потребителя")
    # Базовая ветка репозитория - prod (main нет): по умолчанию вендорится она
    parser.add_argument("--ref", default=DEFAULT_REF, help="тег или коммит библиотеки")
    parser.add_argument("--parts", default=",".join(DEFAULT_PARTS))
    args = parser.parse_args()
    parts = {p.strip() for p in args.parts.split(",") if p.strip()}
    unknown = parts - set(ALL_PARTS)
    if unknown:
        print(f"неизвестные части: {sorted(unknown)}", file=sys.stderr)
        return 2
    if not args.dest.is_dir():
        print(f"нет каталога проекта: {args.dest}", file=sys.stderr)
        return 2
    # ^{commit}: у аннотированного тега rev-parse без суффикса даёт хеш объекта тега, а в
    # VERSION нужен коммит (до 0.8.0 туда попадал хеш тега, и сверка с git log не сходилась)
    commit = run_git("rev-parse", f"{args.ref}^{{commit}}").decode().strip()
    files = collect(args.ref, parts)
    if not files:
        print("нечего вендорить: проверьте --ref и --parts", file=sys.stderr)
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
    print(f"{len(files)} файлов -> {target} (коммит {commit[:8]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
