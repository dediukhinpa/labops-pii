"""Перешифрование таблицы замен со схемы ключей v1 на v2 (S-02).

Запуск: `python -m labops_pii.rekey --dry-run`, затем без `--dry-run`. Ключ берётся
из PSEUDONYMIZER_KEY (в аргументах и логах не передаётся). Сервис на время операции
остановить: запись в таблицу во время перешифрования недопустима.

Выбран явный идемпотентный скрипт, а не ленивое перешифрование при чтении: сервис не меняет
данные молча, операция выполняется одной транзакцией после бэкапа под контролем оператора,
а чтение старых строк до запуска продолжает работать (двойное чтение v2/v1 в хранилище).
"""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from cryptography.fernet import InvalidToken

from labops_pii.config import (
    DEFAULT_DB,
    ENV_DB,
    ENV_KEY,
    ENV_KEY_SCHEME,
    ENV_STORE,
    STORE_SQLITE,
    ConfigError,
    load_settings,
)
from labops_pii.store import SqliteReplacementStore

logger = logging.getLogger("pseudonymizer.rekey")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
BACKUP_FILE_MODE = 0o600


def _copy_database(source: Path, target: Path) -> None:
    """Копирует базу средствами SQLite (согласованный снимок) в уже созданный файл."""
    src = sqlite3.connect(str(source))
    try:
        dst = sqlite3.connect(str(target))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def make_backup(db_path: Path) -> Path:
    """Снимает согласованную копию SQLite-файла рядом с оригиналом (права 600).

    Файл создаётся пустым сразу с правами 600 и только потом заполняется: в копии вся
    таблица замен, и создавать её с правами по umask, исправляя их после записи, значит
    оставить окно, в котором файл читают другие пользователи. O_EXCL не даёт писать в
    чужой или подложенный файл с тем же именем.

    Args:
        db_path: Путь к базе.

    Returns:
        Путь к копии.

    Raises:
        FileExistsError: Файл с таким именем уже есть (копия в ту же секунду).
        OSError: Копирование не удалось; недописанный файл удалён.
        sqlite3.Error: То же, сбой на стороне SQLite.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = db_path.with_name(f"{db_path.name}.bak-{stamp}")
    os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, BACKUP_FILE_MODE))
    try:
        _copy_database(db_path, target)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="labops_pii.rekey",
        description="Перешифровать таблицу замен на раздельные ключи (HKDF, схема v2).",
    )
    parser.add_argument(
        "--db", type=Path, default=None,
        help=f"путь к SQLite (по умолчанию ${ENV_DB} или {DEFAULT_DB})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="только проверить расшифровку и посчитать строки, ничего не записывать",
    )
    parser.add_argument(
        "--no-backup", action="store_true",
        help="не делать копию файла перед записью (только если бэкап уже снят снаружи)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа. Код возврата: 0 успех, 1 ошибка (база не изменена), 2 неверный запуск."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _parse(argv)
    try:
        settings = load_settings(
            {
                ENV_KEY: os.environ.get(ENV_KEY, ""),
                ENV_STORE: STORE_SQLITE,
                ENV_KEY_SCHEME: os.environ.get(ENV_KEY_SCHEME, ""),
            },
            require_api_token=False
        )
    except ConfigError as exc:
        logger.error("%s", exc)
        return EXIT_USAGE
    db_path = args.db or Path(os.environ.get(ENV_DB, str(DEFAULT_DB)))
    if not db_path.is_file():
        logger.error("файл базы не найден: %s", db_path)
        return EXIT_USAGE
    logger.warning(
        "ВНИМАНИЕ: перед перешифрованием должен быть снят бэкап (scripts/backup.sh), "
        "запись в сервис остановлена."
    )
    store = SqliteReplacementStore(
        db_path, settings.key, key_scheme=settings.key_scheme
    )
    try:
        # Пробная расшифровка всех строк ДО копии: с неверным ключом копия не создаётся
        # (иначе каждая неудачная попытка оставляла бы ещё один файл с таблицей замен).
        report = store.rekey_legacy(dry_run=True)
        if not args.dry_run:
            if not args.no_backup:
                logger.info("копия файла базы: %s", make_backup(db_path))
            report = store.rekey_legacy()
        left = store.legacy_row_count()
    except InvalidToken:
        # Значения не печатаем: только факт отказа
        logger.error("расшифровка не удалась: неверный PSEUDONYMIZER_KEY или повреждённые данные;"
                     " база не изменена")
        return EXIT_FAILED
    except (OSError, sqlite3.Error) as exc:
        logger.error("копия файла базы не создана (%s); база не изменена", type(exc).__name__)
        return EXIT_FAILED
    finally:
        store.close()
    logger.info(
        "всего строк: %d, на схеме v1 было: %d, переведено: %d, осталось на v1: %d%s",
        report.total, report.legacy, report.migrated, left,
        " (dry-run, запись не выполнялась)" if report.dry_run else "",
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
