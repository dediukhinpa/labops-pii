"""Конфигурация сервиса из переменных окружения."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet

from labops_pii.errors import ConfigError, reject_legacy_profile
from labops_pii.store import ENV_KEY_SCHEME, resolve_key_scheme

__all__ = ["ConfigError", "Settings", "env_mask_addresses", "load_settings"]

HOURS_PER_DAY = 24
STORE_MEMORY = "memory"
STORE_SQLITE = "sqlite"

ENV_KEY = "PSEUDONYMIZER_KEY"
ENV_API_TOKEN = "PSEUDONYMIZER_API_TOKEN"
ENV_STORE = "PSEUDONYMIZER_STORE"
ENV_RETENTION_HOURS = "PSEUDONYMIZER_RETENTION_HOURS"
# Устаревшая переменная: учитывается, только если не задана RETENTION_HOURS
ENV_RETENTION_DAYS = "PSEUDONYMIZER_RETENTION_DAYS"
ENV_DB = "PSEUDONYMIZER_DB"
ENV_MASK_LEGAL = "PSEUDONYMIZER_MASK_LEGAL_ENTITY"
ENV_ADDRESS_MASK = "PSEUDONYMIZER_ADDRESS_MASK"
# Флаги маршрутов и полей API: по умолчанию все выключены (включает потребитель)
ENV_ENABLE_INFLECT_SIGNATORY = "PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY"
ENV_ENABLE_DELETE_THREADS = "PSEUDONYMIZER_ENABLE_DELETE_THREADS"
ENV_ENABLE_EXPOSE_BOOT_ID = "PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID"
ENV_ENABLE_CASE_LABELS = "PSEUDONYMIZER_ENABLE_CASE_LABELS"
ENV_CONTACTS = "PSEUDONYMIZER_CONTACTS_FILE"
ENV_HOST = "PSEUDONYMIZER_HOST"
ENV_PORT = "PSEUDONYMIZER_PORT"
ENV_MAX_TEXT = "PSEUDONYMIZER_MAX_TEXT_CHARS"
ENV_MAX_RESTORE_TOKENS = "PSEUDONYMIZER_MAX_RESTORE_TOKENS"
ENV_MAX_CONCURRENCY = "PSEUDONYMIZER_MAX_CONCURRENCY"
ENV_MAX_BATCH_ITEMS = "PSEUDONYMIZER_MAX_BATCH_ITEMS"

DEFAULT_DB = Path("data/pseudonymizer.sqlite3")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8300
# Таймаут клиента (pii-proxy, 10 000 мс): запрос, который
# обрабатывается дольше, для клиента всё равно потерян, а процесс при этом занят.
CLIENT_TIMEOUT_SECONDS = 10.0
# Худшее измеренное время на символ (README, «Пределы и время»; ВМ 2 vCPU): текст из
# одних инициалов «А. Б. В. », 80 мкс на символ; обычная проза 16 мкс.
WORST_SECONDS_PER_CHAR = 80e-6
# Какую долю таймаута клиента может занять худший запрос предельной длины.
WORST_CASE_TIMEOUT_SHARE = 0.6
# Предел длины текста запроса (S-03): 70 000 x 80 мкс = 5,6 с, запас до таймаута 1,8 раза.
# Меньше нельзя: клиент шлёт длинный результат инструмента до 60 000 символов одним текстом.
# Больше -> 422.
DEFAULT_MAX_TEXT_CHARS = 70_000
# Пакетное маскирование /pseudonymize_batch (R9-A2-04). Каждый текст пачки обрабатывается
# как отдельный /pseudonymize (детект, леммы ФИО треда, коммит), поэтому у текста есть
# постоянная цена сверх длины: замер на 2 vCPU под нагрузкой (README, «Пакетное
# маскирование») - до 6,4 мс на короткий лист JSON в треде с сотнями ФИО. Берём 8 мс.
BATCH_ITEM_SECONDS = 8e-3
# Та же цена в «символах худшего текста»: каждый текст пачки, кроме первого, считается
# длиннее на столько символов. Сумма с поправкой ограничена max_text_chars, поэтому худшее
# время пачки то же, что у одного текста предельной длины (5,6 с), и слот конкуренции она
# держит не дольше. Пачка из одного текста проверяется ровно как /pseudonymize.
BATCH_ITEM_COST_CHARS = round(BATCH_ITEM_SECONDS / WORST_SECONDS_PER_CHAR)
# Предел числа текстов в пачке: 500 x 8 мс = 4 с постоянной цены. Больше -> 413.
DEFAULT_MAX_BATCH_ITEMS = 500
# Тело запроса читается до проверки текста, поэтому предел байт нужен отдельно от предела
# символов. Худший JSON-байтов на символ текста: `\uXXXX` на каждую половину суррогатной
# пары, то есть 12 байт на символ вне BMP (клиент с ensure_ascii).
JSON_BYTES_PER_CHAR = 12
# Накладные расходы JSON на один текст пачки: кавычки, запятая, пробел.
JSON_BYTES_PER_BATCH_ITEM = 8
# Запас на поля вокруг текста (thread_id, имена ключей, фигурные скобки).
JSON_ENVELOPE_BYTES = 64 * 1024
# Предел числа разных токенов в тексте для /restore: каждый найденный расшифровывается.
DEFAULT_MAX_RESTORE_TOKENS = 5_000
# Сколько запросов обрабатывается одновременно (R3-MEM-14). Разбор текста грузит процессор
# и память (хост 2 vCPU), а Python держит GIL: больше запросов только растягивает каждый
# и накапливает память. Лишние ждут очереди.
DEFAULT_MAX_CONCURRENCY = 2
# Сколько запрос ждёт свободного слота, прежде чем получить 503. Ожидание и обработка идут
# в одном таймауте клиента: ждать + работать должно укладываться в CLIENT_TIMEOUT_SECONDS,
# иначе клиент бросает запрос и повторяет его, а синхронный обработчик на сервере доходит до
# конца, и работа множится. Худшая обработка занимает WORST_CASE_TIMEOUT_SHARE таймаута,
# значит на ожидание остаётся CLIENT_TIMEOUT_SECONDS * (1 - WORST_CASE_TIMEOUT_SHARE) =
# 10 * 0,4 = 4 с; 4 с + 5,6 с = 9,6 с < 10 с. Источник правды один: оба числа выводятся из
# CLIENT_TIMEOUT_SECONDS и WORST_CASE_TIMEOUT_SHARE (сверка в тестах).
MAX_BUSY_TIMEOUT_SECONDS = 4.0
BUSY_TIMEOUT_SECONDS = min(
    CLIENT_TIMEOUT_SECONDS * (1 - WORST_CASE_TIMEOUT_SHARE), MAX_BUSY_TIMEOUT_SECONDS
)
# Где хранится таблица замен: в памяти процесса (по умолчанию, на диск ничего не пишется)
# или в зашифрованном SQLite-файле.
STORE_BACKENDS = frozenset({STORE_MEMORY, STORE_SQLITE})
# Сколько часов хранится таблица замен треда без обращений. Через столько часов после
# последней записи/восстановления тред удаляется целиком. 0 в окружении — не удалять.
DEFAULT_RETENTION_HOURS = 24
TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def max_body_bytes(max_text_chars: int, max_batch_items: int) -> int:
    """Предел тела запроса в байтах: самый большой допустимый запрос плюс запас на JSON.

    Допустимы текст в `max_text_chars` символов или пачка, у которой сумма длин (с ценой
    каждого текста) не больше `max_text_chars`. Всё сверх этого - 413 без чтения тела.
    """
    return (
        max_text_chars * JSON_BYTES_PER_CHAR
        + max_batch_items * JSON_BYTES_PER_BATCH_ITEM
        + JSON_ENVELOPE_BYTES
    )


@dataclass(frozen=True, slots=True)
class Settings:
    """Настройки сервиса.

    Attributes:
        key: Ключ Fernet (в логи и repr не попадает); нужен только для store_backend=sqlite.
        key_scheme: Схема ключей SQLite при записи ("v2" или "v3"); обязательна при sqlite.
        store_backend: Хранилище замен: "memory" (по умолчанию) или "sqlite".
        api_token: Общий секрет клиентов (Authorization: Bearer ...); в repr не попадает.
        retention_hours: Срок хранения замен треда без обращений, часов (0 — без удаления).
        db_path: Путь к SQLite-файлу таблицы замен.
        mask_legal_entity_requisites: Маскировать ли названия организаций (реквизиты — всегда).
        mask_addresses: Маскировать ли адреса (улица + дом, индекс); город остаётся открытым.
        contacts: Словарь контактов.
        host: Адрес прослушивания.
        port: Порт.
        max_text_chars: Предел длины текста в /pseudonymize, /check и /restore (символы).
        max_restore_tokens: Предел числа разных токенов в тексте для /restore.
        max_concurrency: Предел одновременно обрабатываемых запросов.
        max_batch_items: Предел числа текстов в одном /pseudonymize_batch.
        busy_timeout_seconds: Ожидание слота до ответа 503.
        enable_inflect_signatory: Есть ли маршрут POST /inflect_signatory.
        enable_delete_threads: Есть ли маршрут DELETE /threads/{id}.
        enable_expose_boot_id: Отдавать ли boot_id в /health.
        enable_case_labels: Принимает ли /pseudonymize флаг case_labels (падежные метки).

    Значения по умолчанию полей, которые задаются переменными окружения, читаются из окружения
    процесса в момент создания (так набор тестов задаёт конфигурацию одним блоком переменных).
    """

    key: str = field(default="", repr=False)
    key_scheme: str = field(default_factory=lambda: _env_key_scheme(os.environ))
    store_backend: str = field(default_factory=lambda: _env_store(os.environ))
    api_token: str = field(default="", repr=False)
    retention_hours: int = field(default_factory=lambda: _retention_hours(os.environ))
    db_path: Path = DEFAULT_DB
    mask_legal_entity_requisites: bool = field(
        default_factory=lambda: _bool_env(os.environ, ENV_MASK_LEGAL, default=True)
    )
    mask_addresses: bool = field(
        default_factory=lambda: _strict_bool_env(os.environ, ENV_ADDRESS_MASK, default=False)
    )
    contacts: tuple[str, ...] = ()
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS
    max_restore_tokens: int = DEFAULT_MAX_RESTORE_TOKENS
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY
    max_batch_items: int = DEFAULT_MAX_BATCH_ITEMS
    busy_timeout_seconds: float = BUSY_TIMEOUT_SECONDS
    enable_inflect_signatory: bool = field(
        default_factory=lambda: _strict_bool_env(os.environ, ENV_ENABLE_INFLECT_SIGNATORY,
                                                 default=False)
    )
    enable_delete_threads: bool = field(
        default_factory=lambda: _strict_bool_env(os.environ, ENV_ENABLE_DELETE_THREADS,
                                                 default=False)
    )
    enable_expose_boot_id: bool = field(
        default_factory=lambda: _strict_bool_env(os.environ, ENV_ENABLE_EXPOSE_BOOT_ID,
                                                 default=False)
    )
    enable_case_labels: bool = field(
        default_factory=lambda: _strict_bool_env(os.environ, ENV_ENABLE_CASE_LABELS,
                                                 default=False)
    )

    @property
    def retention_days(self) -> int:
        """Срок хранения в целых сутках (для настроек, заданных в днях, как в Прагматике)."""
        return self.retention_hours // HOURS_PER_DAY


def load_contacts(path: Path) -> tuple[str, ...]:
    """Читает словарь контактов: одна строка — один контакт, # — комментарий."""
    if not path.is_file():
        raise ConfigError(f"Файл словаря контактов не найден: {path}")
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return tuple(line for line in lines if line and not line.startswith("#"))


def _int_env(env: Mapping[str, str], name: str, default: int, *, allow_zero: bool = False) -> int:
    """Читает целое из окружения: больше нуля, а с allow_zero — не меньше нуля.

    Raises:
        ConfigError: Значение не число или меньше допустимого.
    """
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} должна быть целым числом") from exc
    if value < 0 or (value == 0 and not allow_zero):
        raise ConfigError(
            f"{name} не может быть отрицательной" if allow_zero
            else f"{name} должна быть больше нуля"
        )
    return value


def _bool_env(env: Mapping[str, str], name: str, *, default: bool) -> bool:
    """Читает флаг из окружения; пусто — значение по умолчанию."""
    raw = env.get(name, "").strip().lower()
    return default if not raw else raw in TRUE_VALUES


def _strict_bool_env(env: Mapping[str, str], name: str, *, default: bool) -> bool:
    """Читает флаг on/off строго: неизвестное значение - ошибка, а не молчаливый откат.

    Raises:
        ConfigError: Значение не из on/off, true/false, yes/no, 1/0. Опечатка в «off» иначе
            оставила бы маскирование включённым (или наоборот) без ведома владельца.
    """
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    raise ConfigError(f"{name} должна быть on/off (true/false, 1/0, yes/no)")


def _retention_hours(env: Mapping[str, str]) -> int:
    """Срок ретенции в часах: HOURS главнее устаревшей DAYS (она переводится в часы).

    Raises:
        ConfigError: Значение не число или отрицательное.
    """
    if env.get(ENV_RETENTION_HOURS, "").strip():
        return _int_env(env, ENV_RETENTION_HOURS, DEFAULT_RETENTION_HOURS, allow_zero=True)
    if env.get(ENV_RETENTION_DAYS, "").strip():
        return HOURS_PER_DAY * _int_env(env, ENV_RETENTION_DAYS, 1, allow_zero=True)
    return DEFAULT_RETENTION_HOURS


def env_mask_addresses(env: Mapping[str, str] | None = None) -> bool:
    """Маскировать ли адреса: PSEUDONYMIZER_ADDRESS_MASK (по умолчанию выключено).

    Raises:
        ConfigError: Значение не on/off.
    """
    return _strict_bool_env(os.environ if env is None else env, ENV_ADDRESS_MASK, default=False)


def _env_store(env: Mapping[str, str]) -> str:
    """Хранилище из PSEUDONYMIZER_STORE (по умолчанию memory).

    Raises:
        ConfigError: Значение не из memory/sqlite.
    """
    backend = env.get(ENV_STORE, "").strip().lower() or STORE_MEMORY
    if backend not in STORE_BACKENDS:
        raise ConfigError(f"{ENV_STORE} должна быть одной из: {', '.join(sorted(STORE_BACKENDS))}")
    return backend


def _env_key_scheme(env: Mapping[str, str]) -> str:
    """Схема ключей SQLite из PSEUDONYMIZER_KEY_SCHEME; пусто, если хранилище не sqlite.

    Raises:
        ConfigError: Хранилище sqlite, а схема не задана или неверна.
    """
    raw = env.get(ENV_KEY_SCHEME, "")
    if _env_store(env) != STORE_SQLITE:
        return raw.strip().lower()
    return resolve_key_scheme(raw)


def load_settings(
    env: Mapping[str, str] | None = None,
    require_api_token: bool = True,
) -> Settings:
    """Собирает настройки из окружения.

    Args:
        env: Окружение (по умолчанию os.environ).
        require_api_token: Требовать PSEUDONYMIZER_API_TOKEN (fail closed). Только для
            автономных утилит без HTTP (rekey.py), которым API-секрет не нужен.

    Raises:
        ConfigError: Задана прежняя LABOPS_PII_PROFILE; нет ключа, схемы ключей (при sqlite) или
            токена API; ключ невалиден; не найден файл контактов.
    """
    env = os.environ if env is None else env
    reject_legacy_profile(env)
    backend = _env_store(env)
    key_scheme = _env_key_scheme(env)
    key = env.get(ENV_KEY, "").strip()
    # Ключ нужен только SQLite (шифрование на диске); в памяти шифровать нечего
    if backend == STORE_SQLITE:
        if not key:
            raise ConfigError(f"Не задана переменная {ENV_KEY}: сервис не стартует без ключа")
        try:
            Fernet(key.encode())
        except (ValueError, TypeError) as exc:
            # Значение ключа в сообщение не включаем.
            raise ConfigError(f"{ENV_KEY} не является валидным ключом Fernet") from exc
    api_token = env.get(ENV_API_TOKEN, "").strip()
    if require_api_token and not api_token:
        raise ConfigError(f"Не задана переменная {ENV_API_TOKEN}: сервис не стартует без токена")
    contacts_file = env.get(ENV_CONTACTS, "").strip()
    return Settings(
        key=key,
        key_scheme=key_scheme,
        store_backend=backend,
        api_token=api_token,
        retention_hours=_retention_hours(env),
        db_path=Path(env.get(ENV_DB, str(DEFAULT_DB))),
        mask_legal_entity_requisites=_bool_env(env, ENV_MASK_LEGAL, default=True),
        mask_addresses=_strict_bool_env(env, ENV_ADDRESS_MASK, default=False),
        contacts=load_contacts(Path(contacts_file)) if contacts_file else (),
        host=env.get(ENV_HOST, DEFAULT_HOST),
        port=int(env.get(ENV_PORT, str(DEFAULT_PORT))),
        max_text_chars=_int_env(env, ENV_MAX_TEXT, DEFAULT_MAX_TEXT_CHARS),
        max_restore_tokens=_int_env(env, ENV_MAX_RESTORE_TOKENS, DEFAULT_MAX_RESTORE_TOKENS),
        max_concurrency=_int_env(env, ENV_MAX_CONCURRENCY, DEFAULT_MAX_CONCURRENCY),
        max_batch_items=_int_env(env, ENV_MAX_BATCH_ITEMS, DEFAULT_MAX_BATCH_ITEMS),
        enable_inflect_signatory=_strict_bool_env(
            env, ENV_ENABLE_INFLECT_SIGNATORY, default=False
        ),
        enable_delete_threads=_strict_bool_env(env, ENV_ENABLE_DELETE_THREADS, default=False),
        enable_expose_boot_id=_strict_bool_env(env, ENV_ENABLE_EXPOSE_BOOT_ID, default=False),
        enable_case_labels=_strict_bool_env(env, ENV_ENABLE_CASE_LABELS, default=False),
    )
