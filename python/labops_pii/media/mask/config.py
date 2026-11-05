"""Конфигурация сервиса из переменных окружения и общие пределы."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from labops_pii.config import ENV_ADDRESS_MASK as ENV_SERVICE_ADDRESS_MASK
from labops_pii.config import ConfigError as _ServiceConfigError
from labops_pii.config import _strict_bool_env, load_contacts
from labops_pii.errors import reject_legacy_profile

ENV_API_TOKEN = "MEDIA_MASKER_API_TOKEN"
ENV_HOST = "MEDIA_MASKER_HOST"
ENV_PORT = "MEDIA_MASKER_PORT"
ENV_TESSERACT_CMD = "MEDIA_MASKER_TESSERACT_CMD"
ENV_TESSDATA = "TESSDATA_PREFIX"
ENV_LANGS = "MEDIA_MASKER_OCR_LANGS"
ENV_MAX_PDF_PAGES = "MEDIA_MASKER_MAX_PDF_PAGES"
ENV_MAX_CONCURRENCY = "MEDIA_MASKER_MAX_CONCURRENCY"
ENV_OCR_TIMEOUT = "MEDIA_MASKER_OCR_TIMEOUT_S"
ENV_MASK_LEGAL = "MEDIA_MASKER_MASK_LEGAL_ENTITY"
ENV_CONTACTS = "MEDIA_MASKER_CONTACTS_FILE"
ENV_HIDE_UNREADABLE = "MEDIA_MASKER_HIDE_UNREADABLE"
# Адреса на картинках: свой флаг, иначе флаг сервиса псевдонимизации, иначе выкл.
# Без этого при PSEUDONYMIZER_ADDRESS_MASK=on адрес становился токеном в тексте, но
# оставался видимым на самой картинке (найдено при переходе labops на библиотеку).
ENV_ADDRESS_MASK = "MEDIA_MASKER_ADDRESS_MASK"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8320
DEFAULT_TESSERACT_CMD = "tesseract"
DEFAULT_LANGS = "rus+eng"
# Предел страниц PDF: сверх него 413 (OCR одной страницы - секунды, запрос ограничен таймаутом)
DEFAULT_MAX_PDF_PAGES = 20
# OCR и растеризация жрут CPU и память: одновременно обрабатывается немного запросов
DEFAULT_MAX_CONCURRENCY = 2
DEFAULT_OCR_TIMEOUT_S = 60.0

# Предел декодированного файла (картинка или PDF), байт; API модели принимает PDF до 32 МБ
MAX_FILE_BYTES = 32 * 1024 * 1024
# base64 раздувает данные на 4/3; запас на JSON-обвязку
BASE64_RATIO_NUM = 4
BASE64_RATIO_DEN = 3
JSON_OVERHEAD_BYTES = 4096
MAX_BODY_BYTES = MAX_FILE_BYTES * BASE64_RATIO_NUM // BASE64_RATIO_DEN + JSON_OVERHEAD_BYTES
# Предел пикселей картинки (защита от «бомбы расжатия»): ~50 Мп, RGB ~150 МБ в памяти
MAX_IMAGE_PIXELS = 50_000_000

IMAGE_MEDIA_TYPES = ("image/jpeg", "image/png", "image/gif", "image/webp")
PDF_MEDIA_TYPE = "application/pdf"


class ConfigError(Exception):
    """Неверная конфигурация сервиса."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Настройки сервиса.

    Attributes:
        api_token: Общий Bearer-секрет.
        host: Адрес прослушивания.
        port: Порт.
        tesseract_cmd: Путь к бинарю tesseract (или имя в PATH).
        tessdata: Каталог языковых данных или None (по умолчанию Tesseract).
        langs: Языки OCR через «+».
        max_pdf_pages: Предел страниц PDF.
        max_concurrency: Сколько запросов обрабатывается одновременно.
        ocr_timeout_s: Предел времени одного запуска tesseract.
        mask_legal_entity: Закрашивать ли названия организаций (как в pseudonymizer).
        contacts: Словарь контактов для детектора.
        hide_unreadable: Закрашивать ли области с признаками письма, которые OCR не
            распознал (рукопись, подпись).
        mask_addresses: Закрашивать ли адреса; None - из PSEUDONYMIZER_ADDRESS_MASK
            (по умолчанию выкл.).
    """

    api_token: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    tesseract_cmd: str = DEFAULT_TESSERACT_CMD
    tessdata: str | None = None
    langs: str = DEFAULT_LANGS
    max_pdf_pages: int = DEFAULT_MAX_PDF_PAGES
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY
    ocr_timeout_s: float = DEFAULT_OCR_TIMEOUT_S
    mask_legal_entity: bool = True
    contacts: tuple[str, ...] = ()
    hide_unreadable: bool = True
    mask_addresses: bool | None = None


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    """Читает положительное целое из окружения."""
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}: нужно целое число") from exc
    if value <= 0:
        raise ConfigError(f"{name}: нужно положительное число")
    return value


def _address_flag(env: Mapping[str, str]) -> bool | None:
    """Флаг адресов: MEDIA_MASKER_ADDRESS_MASK, затем PSEUDONYMIZER_ADDRESS_MASK, иначе None.

    Raises:
        ConfigError: Значение не on/off (опечатка не должна молча выключить маскирование).
    """
    for name in (ENV_ADDRESS_MASK, ENV_SERVICE_ADDRESS_MASK):
        if env.get(name, "").strip():
            try:
                return _strict_bool_env(env, name, default=False)
            except _ServiceConfigError as exc:
                raise ConfigError(str(exc)) from exc
    return None


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Собирает настройки из окружения.

    Args:
        env: Окружение; по умолчанию os.environ.

    Raises:
        ConfigError: Нет токена или значение неверно.
    """
    source = os.environ if env is None else env
    try:
        reject_legacy_profile(source)
    except _ServiceConfigError as exc:
        raise ConfigError(str(exc)) from exc
    token = source.get(ENV_API_TOKEN, "").strip()
    if not token:
        # Fail closed: без секрета сервис не поднимается
        raise ConfigError(f"Не задан токен API ({ENV_API_TOKEN}): сервис не стартует")
    timeout_raw = source.get(ENV_OCR_TIMEOUT, "").strip()
    try:
        timeout = float(timeout_raw) if timeout_raw else DEFAULT_OCR_TIMEOUT_S
    except ValueError as exc:
        raise ConfigError(f"{ENV_OCR_TIMEOUT}: нужно число") from exc
    if timeout <= 0:
        raise ConfigError(f"{ENV_OCR_TIMEOUT}: нужно положительное число")
    contacts_file = source.get(ENV_CONTACTS, "").strip()
    contacts: tuple[str, ...] = ()
    if contacts_file:
        contacts = load_contacts(Path(contacts_file))
    mask_legal = source.get(ENV_MASK_LEGAL, "true").strip().lower() not in ("0", "false", "no")
    hide_unreadable = (
        source.get(ENV_HIDE_UNREADABLE, "true").strip().lower() not in ("0", "false", "no")
    )
    mask_addresses = _address_flag(source)
    return Settings(
        mask_addresses=mask_addresses,
        api_token=token,
        host=source.get(ENV_HOST, DEFAULT_HOST).strip() or DEFAULT_HOST,
        port=_positive_int(source, ENV_PORT, DEFAULT_PORT),
        tesseract_cmd=source.get(ENV_TESSERACT_CMD, "").strip() or DEFAULT_TESSERACT_CMD,
        tessdata=source.get(ENV_TESSDATA, "").strip() or None,
        langs=source.get(ENV_LANGS, "").strip() or DEFAULT_LANGS,
        max_pdf_pages=_positive_int(source, ENV_MAX_PDF_PAGES, DEFAULT_MAX_PDF_PAGES),
        max_concurrency=_positive_int(source, ENV_MAX_CONCURRENCY, DEFAULT_MAX_CONCURRENCY),
        ocr_timeout_s=timeout,
        mask_legal_entity=mask_legal,
        contacts=contacts,
        hide_unreadable=hide_unreadable,
    )
