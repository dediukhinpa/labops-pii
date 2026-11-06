# Миграция данных и совместимость форматов

## Базы SQLite

Формат строк не менялся ни в одной из копий; версия схемы записана в самих данных
(`v1` без метки, `v2:`, `v3:`). Библиотека читает все три всегда.

| Источник | Что в файле | Что делать |
|---|---|---|
| копия с Fernet v2 (`services/pseudonymizer`, `PSEUDONYMIZER_DB`) | v2 (и остатки v1 до `rekey`) | **Ничего.** С `PSEUDONYMIZER_KEY_SCHEME=v2` сервис пишет v2, файл остаётся читаемым прежним кодом (откат возможен). Тот же `PSEUDONYMIZER_KEY` |
| labops (режим `sqlite`) | v3 | С `PSEUDONYMIZER_KEY_SCHEME=v3` сервис пишет v3. Ничего |
| labops (режим `memory`) | нет файла | Таблицы замен в памяти не переносятся (24 ч, и так теряются при рестарте) |

Остатки v1: `python -m labops_pii.rekey --dry-run`, затем без `--dry-run` (остановите запись
в сервис на время операции). Схема записи при перешифровании — из `PSEUDONYMIZER_KEY_SCHEME` (для `rekey` она тоже обязательна).
Переключать базу v2 на v3 не нужно и не рекомендуется: ключи v3 зависят от префикса
треда, а прежний код их не прочтёт. Поэтому у схемы **нет значения по умолчанию**:
при `PSEUDONYMIZER_STORE=sqlite` без `PSEUDONYMIZER_KEY_SCHEME=v2|v3` (или с другим
значением) сервис не стартует и пишет, какой переменной не хватает. Читаются всегда обе
схемы и остатки v1; выбор определяет только формат новых записей.

Совместимость проверяют `python/tests/core/test_store_compat.py` (базы, записанные кодом
исходных копий: `python/tests/fixtures/stores/`, слепые индексы побайтно равны исходным).

## От профилей к переменным окружения (1.0.0)

**Ломающее изменение.** Профили (`LABOPS_PII_PROFILE=labops|edge|<третий профиль>`,
`labops_pii/profiles.py`, `ts/src/detector/profiles.ts`) удалены. Вся настройка — переменные
окружения с нейтральными значениями по умолчанию. Если задана `LABOPS_PII_PROFILE`, сервисы
(псевдонимизатор, оба guard, media) не стартуют и ссылаются на этот файл: молча игнорировать
переменную нельзя, сервис поднялся бы с другим маскированием и другой схемой ключей.
В TS параметр `profile` в настройках детектора тоже ошибка (`LegacyProfileError`).

### Таблица: бывший профиль → переменные

| Поле профиля | Переменная | По умолчанию (нейтрально) | labops | edge | sqlite_v2 (третий профиль) |
|---|---|---|---|---|---|
| хранилище | `PSEUDONYMIZER_STORE` | `memory` | `memory` | `memory` | `sqlite` |
| схема ключей SQLite при записи | `PSEUDONYMIZER_KEY_SCHEME` | **нет, обязательна при sqlite** | `v3` | `v3` | `v2` |
| срок хранения, часов | `PSEUDONYMIZER_RETENTION_HOURS` | `24` | `24` | `24` | `2160` (90 суток) |
| названия организаций | `PSEUDONYMIZER_MASK_LEGAL_ENTITY` | `on` | `on` | `on` | `off` |
| адреса (город остаётся) | `PSEUDONYMIZER_ADDRESS_MASK` | **`on`** | `off` | `off` | `on` |
| `POST /inflect_signatory` | `PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY` | `off` | `off` | `off` | `on` |
| `DELETE /threads/{id}` | `PSEUDONYMIZER_ENABLE_DELETE_THREADS` | `off` | `on` | `on` | `off` |
| `boot_id` в `/health` | `PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID` | `off` | `on` | `on` | `off` |
| флаг `case_labels` в `/pseudonymize` | `PSEUDONYMIZER_ENABLE_CASE_LABELS` | `off` | `on` | `on` | `off` |
| guard: ФИО | `PII_GUARD_NAMES_MODE` | `off` | `off` | `off` | `log_only` |
| guard: адреса | `PII_GUARD_ADDRESS_MODE` | `off` | `off` | `off` | `log_only` |
| слова-исключения | `PII_ALLOWED_WORDS` | пусто | название продукта | название продукта | название продукта и марка |
| словарь контактов | `PSEUDONYMIZER_CONTACTS_FILE` | нет | нет | нет | нет |

Что изменилось по умолчанию относительно прежнего профиля `labops` (он был умолчанием):
четыре флага маршрутов теперь выключены (раньше `DELETE /threads`, `boot_id` и `case_labels`
были включены), список слов-исключений пуст (раньше название продукта было зашито в код),
адреса маскируются (раньше не маскировались: наборы labops и edge задают `off` явно, если
хотят прежнее поведение). Значения
`on|true|yes|1` и `off|false|no|0` равнозначны; флаги и `PSEUDONYMIZER_ADDRESS_MASK` строгие:
опечатка (`enabled`, `of`) — ошибка старта, а не молчаливое значение по умолчанию.
`PSEUDONYMIZER_RETENTION_DAYS` по-прежнему работает (в часы; `RETENTION_HOURS` главнее).
Media: `MEDIA_MASKER_ADDRESS_MASK`, иначе `PSEUDONYMIZER_ADDRESS_MASK`, иначе вкл.

Название продукта и торговые марки потребителя в код библиотеки больше не входят: потребитель
задаёт их основы в `PII_ALLOWED_WORDS` (как было у его профиля).

TS-детектор (`@labops/pii`) не читает окружение: режимы и слова приходят параметрами вызова
`{ maskAddresses, allowedWords }`; значения берите из тех же переменных потребителя.
`maskAddresses` по умолчанию `true` (с 1.0.0).

| Бывший `{ profile }` | Теперь |
|---|---|
| `labops`, `edge` | `{ maskAddresses: false, allowedWords: ['<основа названия>'] }` |
| третий профиль | `{ allowedWords: ['<основа названия>'] }` (адреса ищутся по умолчанию) |

### Готовые блоки env для потребителей

Токены и ключи ниже — заглушки; настоящие остаются в секретах потребителя и в этот файл
не попадают.

**labops (сервис с хранилищем в памяти и TS-прокси):**

```env
PSEUDONYMIZER_API_TOKEN=<секрет>
PSEUDONYMIZER_STORE=memory
PSEUDONYMIZER_RETENTION_HOURS=24
PSEUDONYMIZER_MASK_LEGAL_ENTITY=on
PSEUDONYMIZER_ADDRESS_MASK=off
PSEUDONYMIZER_ENABLE_DELETE_THREADS=on
PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID=on
PSEUDONYMIZER_ENABLE_CASE_LABELS=on
PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY=off
PII_GUARD_NAMES_MODE=off
PII_GUARD_ADDRESS_MODE=off
PII_ALLOWED_WORDS=<основа названия продукта>
# Если хранилище sqlite: PSEUDONYMIZER_STORE=sqlite, PSEUDONYMIZER_KEY=<ключ Fernet>,
# PSEUDONYMIZER_KEY_SCHEME=v3 (схема обязательна)
```

**edge (тот же сервис + guard на edge-узле):**

```env
PSEUDONYMIZER_API_TOKEN=<секрет>
PSEUDONYMIZER_STORE=memory
PSEUDONYMIZER_RETENTION_HOURS=24
PSEUDONYMIZER_MASK_LEGAL_ENTITY=on
PSEUDONYMIZER_ADDRESS_MASK=off
PSEUDONYMIZER_ENABLE_DELETE_THREADS=on
PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID=on
PSEUDONYMIZER_ENABLE_CASE_LABELS=on
PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY=off
PII_GUARD_NAMES_MODE=off
PII_GUARD_ADDRESS_MODE=off
PII_ALLOWED_WORDS=<основа названия продукта>
```

**sqlite_v2, третий профиль (псевдонимизатор, guard litellm, media gate):**

Обе переменные `PII_GUARD_*_MODE` обязательно перенести в env потребителя: с 1.0.0 их
умолчание `off`, и без них проверки guard молча выключатся. Если включён маршрут поиска
(`SEARCH_ROUTE_ENABLED=1`), задайте и `SEARCH_ALLOWED_MODELS`, иначе guard не стартует.

```env
PSEUDONYMIZER_API_TOKEN=<секрет>
PSEUDONYMIZER_STORE=sqlite
PSEUDONYMIZER_KEY=<ключ Fernet, тот же, что был>
PSEUDONYMIZER_KEY_SCHEME=v2
PSEUDONYMIZER_DB=<прежний путь к базе>
PSEUDONYMIZER_RETENTION_HOURS=2160
PSEUDONYMIZER_MASK_LEGAL_ENTITY=off
PSEUDONYMIZER_ADDRESS_MASK=on
PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY=on
PSEUDONYMIZER_ENABLE_DELETE_THREADS=off
PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID=off
PSEUDONYMIZER_ENABLE_CASE_LABELS=off
PII_GUARD_NAMES_MODE=log_only
PII_GUARD_ADDRESS_MODE=log_only
PII_ALLOWED_WORDS=<основа названия продукта>,<основа марки>
# при SEARCH_ROUTE_ENABLED=1:
SEARCH_ALLOWED_MODELS=<модели через запятую>
```

Проверка перехода: после правки env запустите набор сверки из репозитория библиотеки
(`python/tests/test_profile_snapshots.py`): он сравнивает ответы сервиса и guard на общем
корпусе, заданные теми же переменными (`python/tests/env_sets.py`), с эталоном, снятым с
каждого профиля до удаления (`python/tests/fixtures/profiles/`). Побайтное совпадение —
поведение прежнее.

### Прочие переменные

Имена `PSEUDONYMIZER_*` и `PII_GUARD_*` сохранены. Новые в 1.0.0: `PSEUDONYMIZER_KEY_SCHEME`
и четыре `PSEUDONYMIZER_ENABLE_*`. Удалены: `LABOPS_PII_PROFILE` (ошибка старта),
`PII_GUARD_NAMES_MORPH` (удалена в 0.7.0: задана — guard пишет предупреждение и не включает
ничего). Умолчание `PII_GUARD_NAMES_MODE` и `PII_GUARD_ADDRESS_MODE` теперь `off`
(у третьего профиля было `log_only`: если guard работает без явной переменной, задайте её).
Новое в 1.0.0: `PSEUDONYMIZER_ADDRESS_MASK` по умолчанию `on`; при `SEARCH_ROUTE_ENABLED=1`
без `SEARCH_ALLOWED_MODELS` guard.litellm не стартует (раньше пропускал любую модель).

## Модули

| Было | Стало |
|---|---|
| `pseudonymizer.*` | `labops_pii.*` |
| `pii_guard.*` (gateway перед LiteLLM) | `labops_pii.guard.*`, маршруты — `labops_pii.guard.litellm.*` |
| `pii_guard.*` (edge-guard) | `labops_pii.guard.*`, прокси и конфиг — `labops_pii.guard.edge.*` |
| `shared/pii_patterns.py`, копии, `sync-shared.sh` | `labops_pii/pii_patterns.py` (копий нет) |
| `media_masker.*` | `labops_pii.media.mask.*` |
| `documents.ocr_detect`, `documents.image_normalize` | `labops_pii.media.gate.*` |

Имена логгеров, `SERVICE_NAME` и имена событий JSON-журнала сохранены.
