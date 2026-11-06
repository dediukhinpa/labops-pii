"""Хранилище таблицы замен: интерфейс, реализация в памяти и SQLite с шифрованием Fernet."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import logging
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Collection, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from labops_pii.errors import ConfigError

ENV_KEY_SCHEME = "PSEUDONYMIZER_KEY_SCHEME"
# Схема шифрования строк SQLite при записи. v2: ключи не зависят от префикса треда, файл
# читается и прежним кодом исходных копий. v3: ключи выводятся по префиксу треда (labops).
KEY_SCHEME_V2 = "v2"
KEY_SCHEME_V3 = "v3"
KEY_SCHEMES = (KEY_SCHEME_V2, KEY_SCHEME_V3)


def resolve_key_scheme(raw: str | None) -> str:
    """Схема ключей записи из значения PSEUDONYMIZER_KEY_SCHEME.

    Args:
        raw: Значение переменной (None или пусто - не задана).

    Returns:
        "v2" или "v3".

    Raises:
        ConfigError: Не задана или не из v2/v3. Умолчания нет намеренно: молчаливая запись в
            формате, который другая версия кода не прочтёт, необратима без перешифрования.
    """
    value = (raw or "").strip().lower()
    if value not in KEY_SCHEMES:
        raise ConfigError(
            f"Не задана или неверна переменная {ENV_KEY_SCHEME} (нужна одна из: "
            f"{', '.join(KEY_SCHEMES)}): при store=sqlite сервис не стартует без схемы ключей"
        )
    return value

logger = logging.getLogger(__name__)

# Схема ключей (S-02). v1 (прежняя): мастер-ключ напрямую и для Fernet, и для HMAC-индекса.
# v2: два независимых ключа через HKDF-SHA256 с разными метками info. Версия записана в
# самих данных: шифртекст v2 = b"v2:" + токен Fernet (в base64 нет «:», путаницы с v1 нет),
# индекс v2 = "v2:" + hex. Схему SQLite менять не нужно, старые файлы читаются как есть.
V2_PREFIX = "v2:"
V2_PREFIX_BYTES = V2_PREFIX.encode()
# v3: те же два ключа, но выводятся отдельно для каждого префикса треда (часть thread_id до
# первого «:»; нет двоеточия - префикс весь id). info = метка v2 + "/" + префикс. Так клиенты
# с разными префиксами (агенты, приложения) не читают строки друг друга на уровне шифрования.
# Новые строки пишутся в v3; строки v2 и v1 читаются как раньше.
V3_PREFIX = "v3:"
V3_PREFIX_BYTES = V3_PREFIX.encode()
THREAD_PREFIX_SEPARATOR = ":"
# Сколько производных наборов ключей (по префиксам) держим; префиксов обычно единицы
MAX_PREFIX_KEYSETS = 1_024
HKDF_INFO_FERNET = b"pseudonymizer/replacements/fernet/v2"
HKDF_INFO_INDEX = b"pseudonymizer/replacements/index-hmac/v2"
DERIVED_KEY_LEN = 32
# Сколько токенов читается одним запросом (предел числа параметров SQLite не меньше 999).
LOOKUP_BATCH = 500

SECONDS_PER_DAY = 86_400
# Метку последнего обращения к треду пишем не чаще раза в этот интервал: запись на диск
# на каждый запрос не нужна, а точность до часа для ретенции в днях достаточна.
ACTIVITY_TOUCH_INTERVAL_SECONDS = 3_600
# Метка отстаёт от настоящего обращения не больше интервала записи, поэтому интервал не должен
# быть сравним со сроком хранения: при сроке 1 ч активный тред с меткой часовой давности
# удалялся посреди разговора. purge_idle сжимает интервал до доли срока и прибавляет его к сроку.
ACTIVITY_TOUCH_RETENTION_SHARE = 4
ACTIVITY_TOUCH_MIN_SECONDS = 60
# Сколько пар (тред, тип) держит кэш расшифрованных ключей list_keys. Кэш только ускоряет
# повторные чтения и перестраивается из таблицы; хранит нормализованные ключи в памяти
# процесса так же, как их держит сам запрос при разборе текста.
DEFAULT_KEY_CACHE_ENTRIES = 256
# Верхняя граница словаря «когда последний раз писали метку»: при превышении сбрасывается.
TOUCHED_MAP_LIMIT = 100_000
# Сколько пар (тред, тип) держит кэш счётчиков count(): запись это ключ и число, кэш
# только убирает SELECT COUNT(*) на каждый новый токен и при вытеснении пересчитывается.
COUNT_CACHE_ENTRIES = 4096

SECONDS_PER_HOUR = 3_600

# Последнее обращение к треду (запись/чтение замен) для ретенции. Отдельная таблица:
# формат replacements и rekey.py не меняются, старые файлы открываются как есть.
ACTIVITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS thread_activity (
    thread_id TEXT PRIMARY KEY,
    last_seen INTEGER NOT NULL
)
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS replacements (
    thread_id TEXT NOT NULL,
    token TEXT NOT NULL,
    pii_type TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_enc BLOB NOT NULL,
    value_enc BLOB NOT NULL,
    PRIMARY KEY (thread_id, token),
    UNIQUE (thread_id, pii_type, key_hash)
)
"""


@dataclass(frozen=True, slots=True)
class RekeyReport:
    """Итог перешифрования таблицы замен.

    Attributes:
        total: Всего строк.
        legacy: Строк, где остались данные схемы v1 (до операции).
        migrated: Строк переведено на v2 (0 при dry-run).
        dry_run: Ничего не записывалось.
    """

    total: int
    legacy: int
    migrated: int
    dry_run: bool


@dataclass(frozen=True, slots=True)
class _PrefixKeys:
    """Ключи схемы v3 одного префикса треда."""

    fernet: Fernet
    index_secret: bytes


def thread_prefix(thread_id: str) -> str:
    """Префикс треда: часть id до первого «:» (нет двоеточия — весь id)."""
    return thread_id.split(THREAD_PREFIX_SEPARATOR, 1)[0]


def _hkdf(master: bytes, info: bytes) -> bytes:
    """Выводит подключ из мастер-ключа (HKDF-SHA256, без соли: мастер-ключ уже случайный)."""
    return HKDF(algorithm=hashes.SHA256(), length=DERIVED_KEY_LEN, salt=None, info=info).derive(
        master
    )


class ReplacementStore(Protocol):
    """Интерфейс таблицы замен «токен <-> оригинал» в пределах треда."""

    def find_token(self, thread_id: str, pii_type: str, key: str) -> str | None:
        """Токен для нормализованного ключа или None."""
        ...

    def list_keys(self, thread_id: str, pii_type: str) -> list[tuple[str, str]]:
        """Все пары (ключ, токен) данного типа в треде."""
        ...

    def count(self, thread_id: str, pii_type: str) -> int:
        """Сколько токенов данного типа уже выдано в треде."""
        ...

    def add(self, thread_id: str, token: str, pii_type: str, key: str, original: str) -> None:
        """Сохраняет замену."""
        ...

    def get_original(self, thread_id: str, token: str) -> str | None:
        """Оригинал по токену треда или None."""
        ...

    def get_originals(self, thread_id: str, tokens: Collection[str]) -> dict[str, str]:
        """Оригиналы для тех токенов из набора, которые есть в треде."""
        ...

    def batch(self) -> contextlib.AbstractContextManager[None]:
        """Пачка записей: фиксируется целиком при выходе, при ошибке отменяется."""
        ...

    def purge_idle(self, max_idle_seconds: float) -> int:
        """Удаляет замены тредов без обращений дольше max_idle_seconds; число тредов."""
        ...

    def purge_expired(self, retention_days: int) -> int:
        """То же, что purge_idle, со сроком в днях (совместимость)."""
        ...

    def delete_thread(self, thread_id: str) -> bool:
        """Удаляет все замены треда; True, если тред был. Нет треда — не ошибка."""
        ...


class SqliteReplacementStore:
    """SQLite-хранилище для разработки. Ключи и значения шифруются Fernet."""

    def __init__(
        self,
        path: Path | str,
        fernet_key: str,
        clock: Callable[[], float] = time.time,
        key_cache_entries: int = DEFAULT_KEY_CACHE_ENTRIES,
        key_scheme: str | None = None,
    ) -> None:
        """Открывает (создаёт) базу.

        Args:
            path: Путь к файлу SQLite или ":memory:".
            fernet_key: Ключ Fernet (urlsafe base64, 32 байта).
            clock: Источник времени в секундах (подменяется в тестах).
            key_cache_entries: Размер кэша расшифрованных ключей list_keys.
            key_scheme: Схема ключей при ЗАПИСИ: "v3" (ключи по префиксу треда, labops) или
                "v2" (общий ключ, прежний формат: файл читается и прежним кодом).
                По умолчанию из PSEUDONYMIZER_KEY_SCHEME (нет переменной - ConfigError).
                Читаются всегда все схемы (v3, v2, v1).

        Raises:
            ConfigError: Схема не задана ни аргументом, ни окружением.
            ValueError: Схема не из v2/v3.
        """
        if key_scheme is None:
            scheme = resolve_key_scheme(os.environ.get(ENV_KEY_SCHEME))
        else:
            scheme = key_scheme
        if scheme not in KEY_SCHEMES:
            raise ValueError(f"key_scheme должна быть v2 или v3, получено {scheme!r}")
        self._write_v2 = scheme == KEY_SCHEME_V2
        master = base64.urlsafe_b64decode(fernet_key.encode())
        # v1 (только для чтения старых данных и перешифрования): мастер-ключ напрямую
        self._legacy_fernet = Fernet(fernet_key.encode())
        self._legacy_index_secret = master
        # v2: раздельные ключи шифрования и слепого индекса (HMAC от ключа записи)
        self._fernet = Fernet(base64.urlsafe_b64encode(_hkdf(master, HKDF_INFO_FERNET)))
        self._index_secret = _hkdf(master, HKDF_INFO_INDEX)
        # v3: наборы ключей по префиксам тредов, выводятся лениво
        self._master = master
        self._prefix_keys: dict[str, _PrefixKeys] = {}
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._in_batch = False
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._clock = clock
        self._key_cache_entries = max(1, key_cache_entries)
        self._key_cache: OrderedDict[tuple[str, str], list[tuple[str, str]]] = OrderedDict()
        self._touched: dict[str, int] = {}
        # Интервал записи метки активности; purge_idle сжимает его под срок хранения
        self._touch_interval = ACTIVITY_TOUCH_INTERVAL_SECONDS
        # Счётчики строк по (тред, тип); значение всегда равно COUNT(*) либо записи нет.
        # Версия файла нужна, чтобы увидеть запись другим соединением/процессом.
        self._counts: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._counts_version: int | None = None
        self._conn.execute(SCHEMA)
        self._conn.execute(ACTIVITY_SCHEMA)
        # Удалённые строки с ПДн затираются на странице, а не остаются в свободном месте
        self._conn.execute("PRAGMA secure_delete=ON")
        # Файл, созданный до этапа 26, не знает дат: треды получают дату запуска (удалены
        # будут не раньше чем через срок ретенции после первого запуска новой версии)
        self._conn.execute(
            "INSERT OR IGNORE INTO thread_activity "
            "SELECT DISTINCT thread_id, ? FROM replacements",
            (int(self._clock()),),
        )
        self._conn.commit()
        legacy = self.legacy_row_count()
        if legacy:
            logger.warning(
                "в таблице замен %d строк со старой схемой ключей (v1); "
                "выполните перешифрование: python -m labops_pii.rekey (см. RUNBOOK)",
                legacy,
            )

    def _keys_for(self, thread_id: str) -> _PrefixKeys:
        """Ключи v3 для префикса треда (HKDF от мастер-ключа, кэш по префиксу)."""
        prefix = thread_prefix(thread_id)
        keys = self._prefix_keys.get(prefix)
        if keys is None:
            suffix = b"/" + prefix.encode()
            keys = _PrefixKeys(
                fernet=Fernet(
                    base64.urlsafe_b64encode(_hkdf(self._master, HKDF_INFO_FERNET + suffix))
                ),
                index_secret=_hkdf(self._master, HKDF_INFO_INDEX + suffix),
            )
            if len(self._prefix_keys) >= MAX_PREFIX_KEYSETS:
                self._prefix_keys.clear()
            self._prefix_keys[prefix] = keys
        return keys

    def _hash(self, thread_id: str, key: str) -> str:
        """Слепой индекс схемы записи (v2 или v3 по настройке хранилища)."""
        return self._v2_hash(key) if self._write_v2 else self._v3_hash(thread_id, key)

    def _v3_hash(self, thread_id: str, key: str) -> str:
        """Слепой индекс схемы v3 (ключ зависит от префикса треда)."""
        secret = self._keys_for(thread_id).index_secret
        return V3_PREFIX + hmac.new(secret, key.encode(), hashlib.sha256).hexdigest()

    def _v2_hash(self, key: str) -> str:
        """Слепой индекс схемы v2 (для чтения строк, записанных до v3)."""
        digest = hmac.new(self._index_secret, key.encode(), hashlib.sha256).hexdigest()
        return V2_PREFIX + digest

    def _legacy_hash(self, key: str) -> str:
        """Слепой индекс схемы v1 (HMAC мастер-ключом)."""
        return hmac.new(self._legacy_index_secret, key.encode(), hashlib.sha256).hexdigest()

    def _encrypt(self, thread_id: str, plain: str) -> bytes:
        """Шифрует по схеме записи с меткой версии (v3: ключ зависит от префикса треда)."""
        if self._write_v2:
            return V2_PREFIX_BYTES + self._fernet.encrypt(plain.encode())
        return V3_PREFIX_BYTES + self._keys_for(thread_id).fernet.encrypt(plain.encode())

    def _decrypt(self, blob: bytes, thread_id: str) -> str:
        """Расшифровывает данные v3, v2 и v1 (по метке версии).

        Raises:
            cryptography.fernet.InvalidToken: Неверный ключ или повреждённые данные.
        """
        raw = bytes(blob)
        if raw.startswith(V3_PREFIX_BYTES):
            return self._keys_for(thread_id).fernet.decrypt(raw[len(V3_PREFIX_BYTES):]).decode()
        if raw.startswith(V2_PREFIX_BYTES):
            return self._fernet.decrypt(raw[len(V2_PREFIX_BYTES):]).decode()
        return self._legacy_fernet.decrypt(raw).decode()

    def _touch_locked(self, thread_id: str) -> None:
        """Отмечает обращение к треду (не чаще интервала); вызывать под self._lock."""
        now = int(self._clock())
        last = self._touched.get(thread_id)
        if last is not None and now - last < self._touch_interval:
            return
        if len(self._touched) >= TOUCHED_MAP_LIMIT:
            self._touched.clear()
        self._conn.execute(
            "INSERT INTO thread_activity VALUES (?, ?) "
            "ON CONFLICT(thread_id) DO UPDATE SET last_seen=excluded.last_seen",
            (thread_id, now),
        )
        self._touched[thread_id] = now
        if not self._in_batch:
            self._conn.commit()

    def find_token(self, thread_id: str, pii_type: str, key: str) -> str | None:
        with self._lock:
            # Сначала индекс схемы записи, затем остальные (v3, v2, v1): строки, ещё не прошедшие
            # rekey, и файлы другой схемы ключей остаются находимыми
            for key_hash in dict.fromkeys((
                self._hash(thread_id, key),
                self._v3_hash(thread_id, key),
                self._v2_hash(key),
                self._legacy_hash(key),
            )):
                row = self._conn.execute(
                    "SELECT token FROM replacements "
                    "WHERE thread_id=? AND pii_type=? AND key_hash=?",
                    (thread_id, pii_type, key_hash),
                ).fetchone()
                if row:
                    self._touch_locked(thread_id)
                    return str(row[0])
        return None

    def list_keys(self, thread_id: str, pii_type: str) -> list[tuple[str, str]]:
        """Пары (ключ, токен) типа в треде; расшифровка один раз, дальше из кэша.

        Кэш по (тред, тип) ведётся в add() и сбрасывается при откате/ретенции/перешифровании.
        Совпадение числа строк в базе с длиной кэша проверяется на каждом чтении: запись
        другим процессом в тот же файл приводит к перечитыванию, а не к устаревшему ответу.
        """
        cache_key = (thread_id, pii_type)
        with self._lock:
            total = self._row_count_locked(cache_key)
            cached = self._key_cache.get(cache_key)
            if cached is not None and len(cached) == total:
                self._key_cache.move_to_end(cache_key)
                return list(cached)
            rows = self._conn.execute(
                "SELECT key_enc, token FROM replacements WHERE thread_id=? AND pii_type=?",
                cache_key,
            ).fetchall()
            keys = [(self._decrypt(enc, thread_id), str(token)) for enc, token in rows]
            self._key_cache[cache_key] = keys
            self._key_cache.move_to_end(cache_key)
            while len(self._key_cache) > self._key_cache_entries:
                self._key_cache.popitem(last=False)
            return list(keys)

    def _row_count_locked(self, cache_key: tuple[str, str]) -> int:
        """COUNT(*) строк пары (тред, тип) прямо из таблицы; под self._lock."""
        return int(self._conn.execute(
            "SELECT COUNT(*) FROM replacements WHERE thread_id=? AND pii_type=?", cache_key
        ).fetchone()[0])

    def _sync_counts_locked(self) -> None:
        """Сбрасывает счётчики, если файл менялся не этим соединением; под self._lock.

        PRAGMA data_version не сканирует таблицу: значение растёт только от записей других
        соединений, поэтому свои add() кэш не обнуляют, а чужая запись (другой процесс,
        rekey) приводит к честному пересчёту.
        """
        version = int(self._conn.execute("PRAGMA data_version").fetchone()[0])
        if version != self._counts_version:
            self._counts.clear()
            self._counts_version = version

    def count(self, thread_id: str, pii_type: str) -> int:
        """Сколько токенов типа выдано в треде; из кэша, при промахе один COUNT(*)."""
        cache_key = (thread_id, pii_type)
        with self._lock:
            self._sync_counts_locked()
            cached = self._counts.get(cache_key)
            if cached is not None:
                self._counts.move_to_end(cache_key)
                return cached
            total = self._row_count_locked(cache_key)
            self._counts[cache_key] = total
            while len(self._counts) > COUNT_CACHE_ENTRIES:
                self._counts.popitem(last=False)
            return total

    def add(self, thread_id: str, token: str, pii_type: str, key: str, original: str) -> None:
        with self._lock:
            self._sync_counts_locked()
            count_key = (thread_id, pii_type)
            try:
                self._conn.execute(
                    "INSERT INTO replacements VALUES (?,?,?,?,?,?)",
                    (
                        thread_id,
                        token,
                        pii_type,
                        self._hash(thread_id, key),
                        self._encrypt(thread_id, key),
                        self._encrypt(thread_id, original),
                    ),
                )
                self._touch_locked(thread_id)
                cached = self._key_cache.get((thread_id, pii_type))
                if cached is not None:
                    cached.append((key, token))
                if not self._in_batch:
                    self._conn.commit()
            except BaseException:
                # Дубль (UNIQUE), сбой диска: состояние строки неясно, счётчик пересчитается
                # из таблицы при следующем обращении
                self._counts.pop(count_key, None)
                raise
            cached_count = self._counts.get(count_key)
            if cached_count is not None:
                self._counts[count_key] = cached_count + 1

    @contextlib.contextmanager
    def batch(self) -> Iterator[None]:
        """Откладывает фиксацию записей до выхода из блока.

        Один коммит на запрос вместо коммита на каждый токен: на файловой базе каждый
        коммит это запись на диск, и текст с тысячей новых ФИО обрабатывался секундами.
        При исключении всё записанное в блоке отменяется. Блоки не вкладываются; вызывающий
        сам не пускает в блок другие потоки (сервис держит свою блокировку).
        """
        with self._lock:
            self._in_batch = True
        try:
            yield
        except BaseException:
            with self._lock:
                self._in_batch = False
                self._conn.rollback()
                # Кэш и метки времени могли включить откатанные записи
                self._key_cache.clear()
                self._counts.clear()
                self._touched.clear()
            raise
        with self._lock:
            self._in_batch = False
            self._conn.commit()

    def get_original(self, thread_id: str, token: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value_enc FROM replacements WHERE thread_id=? AND token=?",
                (thread_id, token),
            ).fetchone()
            if row:
                self._touch_locked(thread_id)
        return self._decrypt(row[0], thread_id) if row else None

    def get_originals(self, thread_id: str, tokens: Collection[str]) -> dict[str, str]:
        """Читает оригиналы пачкой: один запрос на LOOKUP_BATCH токенов."""
        wanted = sorted(set(tokens))
        rows: list[tuple[str, bytes]] = []
        with self._lock:
            for start in range(0, len(wanted), LOOKUP_BATCH):
                chunk = wanted[start:start + LOOKUP_BATCH]
                marks = ",".join("?" * len(chunk))
                rows.extend(
                    self._conn.execute(
                        "SELECT token, value_enc FROM replacements "
                        f"WHERE thread_id=? AND token IN ({marks})",
                        (thread_id, *chunk),
                    ).fetchall()
                )
            if rows:
                self._touch_locked(thread_id)
        return {str(token): self._decrypt(value, thread_id) for token, value in rows}

    def purge_expired(self, retention_days: int) -> int:
        """Удаляет треды без обращений дольше retention_days дней; см. purge_idle."""
        return self.purge_idle(retention_days * SECONDS_PER_DAY)

    def purge_idle(self, max_idle_seconds: float) -> int:
        """Удаляет замены тредов, к которым не обращались дольше max_idle_seconds.

        Тред удаляется целиком (токены нельзя рвать: остальные ссылки в нём перестали бы
        восстанавливаться вразнобой). Во время пачки записей ничего не делает: коммит
        захватил бы чужие незавершённые записи, вызвать можно позже.

        Args:
            max_idle_seconds: Срок в секундах; 0 и меньше — ретенция выключена.

        Returns:
            Сколько тредов удалено.
        """
        if max_idle_seconds <= 0:
            return 0
        with self._lock:
            if self._in_batch:
                return 0
            # Интервал записи метки - не больше доли срока; к сроку прибавляется сам интервал,
            # на который метка может отставать от последнего обращения
            self._touch_interval = max(
                ACTIVITY_TOUCH_MIN_SECONDS,
                min(
                    ACTIVITY_TOUCH_INTERVAL_SECONDS,
                    int(max_idle_seconds) // ACTIVITY_TOUCH_RETENTION_SHARE,
                ),
            )
            cutoff = int(self._clock() - max_idle_seconds - self._touch_interval)
            expired = [
                str(row[0]) for row in self._conn.execute(
                    "SELECT thread_id FROM thread_activity WHERE last_seen < ?", (cutoff,)
                ).fetchall()
            ]
            for start in range(0, len(expired), LOOKUP_BATCH):
                chunk = expired[start:start + LOOKUP_BATCH]
                marks = ",".join("?" * len(chunk))
                self._conn.execute(
                    f"DELETE FROM replacements WHERE thread_id IN ({marks})", chunk
                )
                self._conn.execute(
                    f"DELETE FROM thread_activity WHERE thread_id IN ({marks})", chunk
                )
            self._conn.commit()
            if expired:
                self._key_cache.clear()
                self._counts.clear()
                self._touched.clear()
        return len(expired)

    def delete_thread(self, thread_id: str) -> bool:
        """Удаляет все замены треда и отметку его активности.

        Идемпотентно. Во время пачки записей не вызывать: удаление войдёт в её фиксацию.

        Args:
            thread_id: Идентификатор треда.

        Returns:
            True, если у треда были замены.
        """
        with self._lock:
            deleted = self._conn.execute(
                "DELETE FROM replacements WHERE thread_id=?", (thread_id,)
            ).rowcount
            self._conn.execute("DELETE FROM thread_activity WHERE thread_id=?", (thread_id,))
            if not self._in_batch:
                self._conn.commit()
            self._key_cache.clear()
            self._counts.clear()
            self._touched.pop(thread_id, None)
        return deleted > 0

    def legacy_row_count(self) -> int:
        """Сколько строк ещё в схеме v1 (индекс без метки v2 или шифртекст без метки v2)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM replacements WHERE "
                "(key_hash NOT LIKE ? AND key_hash NOT LIKE ?) "
                "OR substr(key_enc,1,3) NOT IN (?, ?) OR substr(value_enc,1,3) NOT IN (?, ?)",
                (V2_PREFIX + "%", V3_PREFIX + "%", V2_PREFIX_BYTES, V3_PREFIX_BYTES,
                 V2_PREFIX_BYTES, V3_PREFIX_BYTES),
            ).fetchone()
        return int(row[0])

    def rekey_legacy(self, dry_run: bool = False) -> RekeyReport:
        """Переводит все строки схемы v1 на v2 одной транзакцией (всё или ничего).

        Идемпотентна: строки v2 не трогаются, повторный запуск ничего не меняет. Все строки
        сначала расшифровываются и проверяются, и только потом пишутся: неверный ключ
        прерывает операцию до первой записи. Запись в сервис на время операции остановить.

        Args:
            dry_run: Только проверить расшифровку и посчитать, ничего не записывать.

        Returns:
            Отчёт со счётчиками.

        Raises:
            cryptography.fernet.InvalidToken: Неверный ключ или повреждённая строка
                (база не изменена).
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT thread_id, token, key_hash, key_enc, value_enc FROM replacements"
            ).fetchall()
            updates: list[tuple[str, bytes, bytes, str, str]] = []
            for thread_id, token, key_hash, key_enc, value_enc in rows:
                is_current = (
                    str(key_hash).startswith((V2_PREFIX, V3_PREFIX))
                    and bytes(key_enc).startswith((V2_PREFIX_BYTES, V3_PREFIX_BYTES))
                    and bytes(value_enc).startswith((V2_PREFIX_BYTES, V3_PREFIX_BYTES))
                )
                tid = str(thread_id)
                key = self._decrypt(key_enc, tid)  # проверка ключа касается и строк v2/v3
                original = self._decrypt(value_enc, tid)
                if is_current:
                    continue
                updates.append(
                    (self._hash(tid, key), self._encrypt(tid, key), self._encrypt(tid, original),
                     str(thread_id), str(token))
                )
            if dry_run or not updates:
                return RekeyReport(len(rows), len(updates), 0, dry_run)
            try:
                self._conn.executemany(
                    "UPDATE replacements SET key_hash=?, key_enc=?, value_enc=? "
                    "WHERE thread_id=? AND token=?",
                    updates,
                )
                self._conn.commit()
                self._key_cache.clear()
                self._counts.clear()
            except Exception:
                self._conn.rollback()
                self._counts.clear()
                raise
        return RekeyReport(len(rows), len(updates), len(updates), False)

    def close(self) -> None:
        """Закрывает соединение."""
        with self._lock:
            self._conn.close()


class ReplacementConflictError(ValueError):
    """Замена с тем же токеном или тем же ключом (в пределах типа) в треде уже есть."""


@dataclass(slots=True)
class _MemoryThread:
    """Замены одного треда в памяти.

    Attributes:
        originals: Токен -> оригинал.
        by_key: (тип, нормализованный ключ) -> токен.
        keys: Тип -> пары (ключ, токен) в порядке добавления.
        last_seen: Время последнего обращения (секунды часов хранилища).
    """

    originals: dict[str, str] = field(default_factory=dict)
    by_key: dict[tuple[str, str], str] = field(default_factory=dict)
    keys: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    last_seen: float = 0.0


class MemoryReplacementStore:
    """Хранилище замен только в памяти процесса: на диск ничего не пишется.

    Оригиналы не шифруются: они живут ровно столько же, сколько сам процесс (при
    перезапуске таблица теряется, клиент замечает это по смене boot_id в /health).
    Семантика та же, что у SqliteReplacementStore.
    """

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        """Создаёт пустое хранилище.

        Args:
            clock: Источник времени в секундах (подменяется в тестах).
        """
        self._clock = clock
        self._lock = threading.RLock()
        self._threads: dict[str, _MemoryThread] = {}
        # Журнал пачки: (тред, токен) в порядке добавления; None — пачки нет
        self._journal: list[tuple[str, str]] | None = None

    def _touch_locked(self, thread: _MemoryThread) -> None:
        """Отмечает обращение к треду; под self._lock."""
        thread.last_seen = self._clock()

    def find_token(self, thread_id: str, pii_type: str, key: str) -> str | None:
        with self._lock:
            thread = self._threads.get(thread_id)
            token = thread.by_key.get((pii_type, key)) if thread else None
            if thread is not None and token is not None:
                self._touch_locked(thread)
            return token

    def list_keys(self, thread_id: str, pii_type: str) -> list[tuple[str, str]]:
        with self._lock:
            thread = self._threads.get(thread_id)
            return list(thread.keys.get(pii_type, ())) if thread else []

    def count(self, thread_id: str, pii_type: str) -> int:
        with self._lock:
            thread = self._threads.get(thread_id)
            return len(thread.keys.get(pii_type, ())) if thread else 0

    def add(self, thread_id: str, token: str, pii_type: str, key: str, original: str) -> None:
        """Сохраняет замену.

        Raises:
            ReplacementConflictError: Такой токен или такой ключ типа в треде уже есть.
        """
        with self._lock:
            thread = self._threads.setdefault(thread_id, _MemoryThread())
            if token in thread.originals or (pii_type, key) in thread.by_key:
                raise ReplacementConflictError("замена уже есть в треде")
            thread.originals[token] = original
            thread.by_key[(pii_type, key)] = token
            thread.keys.setdefault(pii_type, []).append((key, token))
            self._touch_locked(thread)
            if self._journal is not None:
                self._journal.append((thread_id, token))

    def get_original(self, thread_id: str, token: str) -> str | None:
        with self._lock:
            thread = self._threads.get(thread_id)
            original = thread.originals.get(token) if thread else None
            if thread is not None and original is not None:
                self._touch_locked(thread)
            return original

    def get_originals(self, thread_id: str, tokens: Collection[str]) -> dict[str, str]:
        with self._lock:
            thread = self._threads.get(thread_id)
            if thread is None:
                return {}
            found = {t: thread.originals[t] for t in set(tokens) if t in thread.originals}
            if found:
                self._touch_locked(thread)
            return found

    @contextlib.contextmanager
    def batch(self) -> Iterator[None]:
        """Пачка записей: при исключении всё добавленное в блоке откатывается.

        Блоки не вкладываются; вызывающий не пускает в блок другие потоки записи.
        """
        with self._lock:
            self._journal = []
        try:
            yield
        except BaseException:
            with self._lock:
                self._rollback_locked()
            raise
        with self._lock:
            self._journal = None

    def _rollback_locked(self) -> None:
        """Убирает записи, добавленные в пачке (с конца); под self._lock."""
        for thread_id, token in reversed(self._journal or []):
            thread = self._threads.get(thread_id)
            if thread is None or token not in thread.originals:
                continue
            del thread.originals[token]
            for pii_type, pairs in thread.keys.items():
                if pairs and pairs[-1][1] == token:
                    key = pairs.pop()[0]
                    thread.by_key.pop((pii_type, key), None)
                    break
            if not thread.originals:
                del self._threads[thread_id]
        self._journal = None

    def purge_idle(self, max_idle_seconds: float) -> int:
        """Удаляет треды без обращений дольше max_idle_seconds целиком.

        Во время пачки ничего не делает (как SQLite). Нулевой и отрицательный срок — выкл.

        Returns:
            Сколько тредов удалено.
        """
        if max_idle_seconds <= 0:
            return 0
        cutoff = self._clock() - max_idle_seconds
        with self._lock:
            if self._journal is not None:
                return 0
            expired = [tid for tid, t in self._threads.items() if t.last_seen < cutoff]
            for thread_id in expired:
                del self._threads[thread_id]
        return len(expired)

    def purge_expired(self, retention_days: int) -> int:
        """Совместимость с протоколом: срок в днях; см. purge_idle."""
        return self.purge_idle(retention_days * SECONDS_PER_DAY)

    def delete_thread(self, thread_id: str) -> bool:
        """Удаляет все замены треда; True, если тред был. Идемпотентно."""
        with self._lock:
            return self._threads.pop(thread_id, None) is not None

    def close(self) -> None:
        """Освобождает память (для симметрии с SQLite)."""
        with self._lock:
            self._threads.clear()
