"""Точка входа: `python -m labops_pii` (сервис псевдонимизации)."""

from __future__ import annotations

import logging
import sys

import uvicorn

from labops_pii.api import create_app
from labops_pii.config import ConfigError, load_settings
from labops_pii.jsonlog import configure_logging

logger = logging.getLogger("pseudonymizer")


def main() -> int:
    """Запускает сервис; без валидного ключа выходит с кодом 1."""
    configure_logging(logging.INFO)
    try:
        settings = load_settings()
    except ConfigError as exc:
        logger.error("Старт отменён: неверная конфигурация", extra={"code": type(exc).__name__})
        return 1
    app = create_app(settings)
    # log_config=None: uvicorn не переустанавливает логирование, всё идёт через JSON-обработчик;
    # access_log=False: запрос логирует middleware (в access-логе uvicorn был бы сырой путь)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        log_config=None,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
