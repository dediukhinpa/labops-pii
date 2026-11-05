# Миграция данных и совместимость форматов

## Базы SQLite

Формат строк не менялся ни в одной из копий; версия схемы записана в самих данных
(`v1` без метки, `v2:`, `v3:`). Библиотека читает все три всегда.

| Источник | Что в файле | Что делать |
|---|---|---|
| Прагматика (`services/pseudonymizer`, `PSEUDONYMIZER_DB`) | v2 (и остатки v1 до `rekey`) | **Ничего.** Профиль `pragmatika` пишет v2, файл остаётся читаемым прежним кодом (откат возможен). Тот же `PSEUDONYMIZER_KEY` |
| labops (режим `sqlite`) | v3 | Профиль `labops`/`webapp_v2` пишет v3. Ничего |
| labops (режим `memory`) | нет файла | Таблицы замен в памяти не переносятся (24 ч, и так теряются при рестарте) |

Остатки v1: `python -m labops_pii.rekey --dry-run`, затем без `--dry-run` (остановите запись
в сервис на время операции). Схема записи при перешифровании — по профилю.
Переключить Прагматику на v3 не нужно и не рекомендуется: ключи v3 зависят от префикса
треда, а прежний код их не прочтёт.

Совместимость проверяют `python/tests/core/test_store_compat.py` (базы, записанные кодом
исходных копий: `python/tests/fixtures/stores/`, слепые индексы побайтно равны исходным).

## Переменные окружения

Имена `PSEUDONYMIZER_*` и `PII_GUARD_*` сохранены. Новые: `LABOPS_PII_PROFILE`,
`PII_GUARD_NAMES_MORPH`. Прагматика: `PSEUDONYMIZER_RETENTION_DAYS` по-прежнему работает
(переводится в часы; `PSEUDONYMIZER_RETENTION_HOURS` главнее).

## Модули

| Было | Стало |
|---|---|
| `pseudonymizer.*` | `labops_pii.*` |
| `pii_guard.*` (Прагматика) | `labops_pii.guard.*`, маршруты — `labops_pii.guard.litellm.*` |
| `pii_guard.*` (web-app-v2) | `labops_pii.guard.*`, прокси и конфиг — `labops_pii.guard.edge.*` |
| `shared/pii_patterns.py`, копии, `sync-shared.sh` | `labops_pii/pii_patterns.py` (копий нет) |
| `media_masker.*` | `labops_pii.media.mask.*` |
| `documents.ocr_detect`, `documents.image_normalize` | `labops_pii.media.gate.*` |

Имена логгеров, `SERVICE_NAME` и имена событий JSON-журнала сохранены.
