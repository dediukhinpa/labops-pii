# labops-pii

Общая библиотека маскирования персональных данных (ПДн) для нескольких
проектов. Один код вместо трёх расходящихся копий; различия проектов
задаются переменными окружения (профилей нет с 1.0.0), а не форками. Версии: semver-теги и [CHANGELOG](CHANGELOG.md).

## Состав (фаза 1, Python)

| Часть | Что внутри |
|---|---|
| `labops_pii` (ядро) | шаблоны ПДн (`pii_patterns`, единственный канон), детектор всех типов включая `ADDRESS`, морфология и склонение (`morph`, `inflect`), падежные метки, экранирование меток, `tech_tokens`, `checksums` |
| хранилища | `memory`, `sqlite` с HKDF v3 (labops), `sqlite` + Fernet v2 (прежний формат, набор `sqlite_v2`); схема записи и срок хранения — настройками |
| сервис | FastAPI: `/pseudonymize`, `/pseudonymize_batch`, `/restore`, `/check`, `DELETE /threads/{id}`, `/inflect_signatory`, `/health` |
| `labops_pii.guard` | режим «только проверка»: ФИО, адреса, телефоны и др.; `off / log_only / enforce`; метрики с закрытым списком меток. Две поверхности: `guard.litellm` (бывший gateway/pii-guard перед LiteLLM) и `guard.edge` (бывший отдельный services/pii-guard на edge-узле) |
| `labops_pii.media` | `mask` (закраска ПДн на фото и PDF) и `gate` (есть ли текст на картинке). Чистый Python API без FastAPI; HTTP-обёртки отдельно. Extras `media` |
| `ts/` | фаза 2 (клиент, SSE, обход тела запроса к модели) — см. `ts/README.md` |

## Настройка: переменные окружения

С 1.0.0 профилей нет: каждое различие между проектами — переменная окружения с нейтральным
значением по умолчанию. Если задана прежняя `LABOPS_PII_PROFILE`, сервисы не стартуют и
указывают на [docs/MIGRATION.md](docs/MIGRATION.md) (там же таблица «бывший профиль → набор
переменных» и готовые блоки env для наборов `labops`, `edge` и `sqlite_v2`).

| Переменная | По умолчанию | Что задаёт |
|---|---|---|
| `PSEUDONYMIZER_STORE` | `memory` | хранилище замен: `memory` или `sqlite` |
| `PSEUDONYMIZER_KEY_SCHEME` | нет | схема ключей SQLite при записи, `v2` или `v3`; **обязательна при `sqlite`**, без неё (или с иным значением) сервис не стартует |
| `PSEUDONYMIZER_KEY` | нет | ключ Fernet (нужен только для `sqlite`) |
| `PSEUDONYMIZER_RETENTION_HOURS` | `24` | срок хранения замен треда без обращений, часов (0 — не удалять) |
| `PSEUDONYMIZER_MASK_LEGAL_ENTITY` | `on` | маскировать названия организаций (реквизиты — всегда) |
| `PSEUDONYMIZER_ADDRESS_MASK` | `on` | маскировать адреса (город остаётся); выключается явно `off` |
| `PSEUDONYMIZER_ENABLE_INFLECT_SIGNATORY` | `off` | маршрут `POST /inflect_signatory` |
| `PSEUDONYMIZER_ENABLE_DELETE_THREADS` | `off` | маршрут `DELETE /threads/{id}` |
| `PSEUDONYMIZER_ENABLE_EXPOSE_BOOT_ID` | `off` | `boot_id` в `/health` |
| `PSEUDONYMIZER_ENABLE_CASE_LABELS` | `off` | флаг `case_labels` в `/pseudonymize` |
| `PII_GUARD_NAMES_MODE`, `PII_GUARD_ADDRESS_MODE` | `off` | режим guard для ФИО и адресов: `off`, `log_only`, `enforce` |
| `PII_ALLOWED_WORDS` | пусто | основы слов-исключений через запятую |
| `SEARCH_ROUTE_ENABLED`, `SEARCH_ALLOWED_MODELS` | `0`, нет | маршрут поиска guard.litellm; при `1` список моделей **обязателен**, без него guard не стартует |
| `PSEUDONYMIZER_CONTACTS_FILE` | нет | словарь контактов сервиса |

Флаги и режимы строгие: опечатка — ошибка старта, а не молчаливое значение по умолчанию.
TS-детектор окружения не читает: `maskAddresses` и `allowedWords` передаёт вызывающий код.

ФИО guard ищет только эвристикой (`guard/names.py`); морфология из guard удалена в 0.7.0
(на реальных названиях давала лишь ложные), `PII_GUARD_NAMES_MORPH` ничего не включает.
ИНН любой длины (организации и физлица) — ПДн при любых настройках: guard блокирует, сервис
маскирует. Белый список слов (`labops_pii/allowlist.py`) по умолчанию пуст: название продукта
(все падежи, с кавычками и без) не маскируется как ФИО или организация ни в сервисе, ни в
guard, только если его основа задана в `PII_ALLOWED_WORDS` (например `вектрик`). Имена людей
и агентов в список не входят.

## Установка и запуск

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e "python[dev]"            # ядро и сервис
pip install -e "python[dev,guard,media]"  # + guard и медиа
PSEUDONYMIZER_API_TOKEN=... python -m labops_pii   # память; sqlite — см. настройку выше
uvicorn labops_pii.guard.litellm.app:app   # guard перед LiteLLM
uvicorn labops_pii.guard.edge.app:build_app --factory   # guard на edge-узле
python -m labops_pii.media.mask          # маска фото и PDF
```

## Тесты

`tools/run_tests.sh` — каждый набор отдельным процессом с собственным набором переменных
окружения (бывшие профили записаны в `python/tests/env_sets.py`; раннер передаёт их через `env`).
Для медиа нужен Tesseract (`MEDIA_MASKER_TESSERACT_CMD`, `PATH`, `TESSDATA_PREFIX`).
Главный критерий: `tests/test_reference_snapshots.py` сверяет ответы библиотеки (с набором
переменных бывшего профиля) с эталонными снимками кода исходных копий на общем корпусе;
расхождения (осознанные фиксы) перечислены в `python/tests/fixtures/accepted_divergences.json`
и CHANGELOG. Переснять эталоны: `tools/reference_snapshot.py --impl original --src <копия>`.
`tests/test_profile_snapshots.py` сверяет побайтно те же наборы переменных со снимками,
снятыми с профилей перед их удалением (`python/tests/fixtures/profiles/`).

## Медиа: распознанный текст, QR и рукопись

`labops_pii.media.mask` кроме закраски отдаёт распознанное, одинаково при любых настройках:

- `ImageMasker.mask(...)` и страницы-растры `/extract_document` возвращают `recognized`:
  `{text, codes: [{kind: "qr"|"barcode", text}], hidden_text}`. Это настоящие значения (сервис
  локальный); ПДн в них заменяет вызывающая сторона токенами. Поле необязательное: старые
  клиенты его не читают, форма остальных ответов не менялась. `stats` дополнилось числами
  `codes` и `unreadable_boxes`.
- QR и штрихкоды ищет и расшифровывает OpenCV (`codes.py`); область закрашивается всегда.
  vCard и MECARD разбираются по полям с подписями (иначе `N:Иванов;Пётр` не виден детектору
  имён), из Wi-Fi-кода пароль и имя сети вырезаются.
- Нераспознанная рукопись закрашивается эвристикой (`unreadable.py`,
  `MEDIA_MASKER_HIDE_UNREADABLE`, по умолчанию `true`); если кандидаты занимают более 20 %
  площади, это фото или текстура, и ничего не закрашивается.
- Новые коды отказа (500): `code_detection_failed`, `unreadable_scan_failed`.
- Потребитель набора `sqlite_v2` использует только `gate`; его поведение и эталонные снимки
  не менялись.

Остаточные риски:

- рукопись, которую OCR прочитал как слово с уверенностью не ниже 40, не закрашивается и
  уходит текстом (после детектора ПДн);
- содержимое кода не в формате vCard/MECARD (ссылка, свободный текст) уходит текстом как есть:
  токенами становится только то, что нашёл детектор, то есть ссылка с ПДн внутри токенизируется
  лишь если детектор её распознал;
- эвристика пропускает письмо без контраста с фоном и всё на кадрах, где кандидатов > 20 %;
- адреса маскируются только при `PSEUDONYMIZER_ADDRESS_MASK=on` (или `MEDIA_MASKER_ADDRESS_MASK`).

## Вендоринг в проекты

```bash
tools/vendor.sh /путь/к/проекту v1.0.2 guard        # тег или коммит; части: guard, service, media, ts
```

Файлы попадают в `vendor/labops-pii/` вместе с `VERSION` (тег, коммит, sha256 каждого файла).
Тест проекта (`examples/test_vendored_unchanged.py`) падает, если файлы правили руками.
Базовая ветка репозитория — `prod`. Правки — только здесь: PR в `prod`, тег, затем `vendor.sh` в проектах. Миграция баз —
[docs/MIGRATION.md](docs/MIGRATION.md).

## English summary

Shared PII-masking library for three LabOps projects. `labops_pii` provides the detector
(single pattern canon, morphology, address detection), replacement stores (memory, SQLite
with HKDF v3 or Fernet v2, configurable retention), the FastAPI pseudonymization service,
a check-only guard (off / log_only / enforce) with two HTTP surfaces, and the `media`
subpackage (image/PDF masking and a "has text" gate) behind the `media` extra. Project
differences are plain environment variables with neutral defaults (profiles were removed in
1.0.0; setting the old `LABOPS_PII_PROFILE` is a startup error, see `docs/MIGRATION.md`). Projects consume it by vendoring (`tools/vendor.sh`), which writes a
`VERSION` file with sha256 hashes that a project test verifies.

## Лицензия

Proprietary, © 2026 LabOps.ai. All rights reserved. См. [LICENSE](LICENSE).
