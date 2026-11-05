# labops-pii

Общая библиотека маскирования персональных данных (ПДн) для labops-ai-assistant,
web-app-v2 и pragmatica-ai. Один код вместо трёх расходящихся копий; различия проектов
задаются профилями настроек, а не форками. Версии: semver-теги и [CHANGELOG](CHANGELOG.md).

## Состав (фаза 1, Python)

| Часть | Что внутри |
|---|---|
| `labops_pii` (ядро) | шаблоны ПДн (`pii_patterns`, единственный канон), детектор всех типов включая `ADDRESS`, морфология и склонение (`morph`, `inflect`), падежные метки, экранирование меток, `tech_tokens`, `checksums` |
| хранилища | `memory`, `sqlite` с HKDF v3 (labops), `sqlite` + Fernet v2 (Прагматика); схема записи и срок хранения — настройками |
| сервис | FastAPI: `/pseudonymize`, `/pseudonymize_batch`, `/restore`, `/check`, `DELETE /threads/{id}`, `/inflect_signatory`, `/health` |
| `labops_pii.guard` | режим «только проверка»: ФИО, адреса, телефоны и др.; `off / log_only / enforce`; метрики с закрытым списком меток. Две поверхности: `guard.litellm` (бывший gateway/pii-guard Прагматики) и `guard.edge` (бывший services/pii-guard web-app-v2) |
| `labops_pii.media` | `mask` (закраска ПДн на фото и PDF) и `gate` (есть ли текст на картинке). Чистый Python API без FastAPI; HTTP-обёртки отдельно. Extras `media` |
| `ts/` | фаза 2 (клиент, SSE, обход тела запроса к модели) — см. `ts/README.md` |

## Профили

`LABOPS_PII_PROFILE=labops|pragmatika|webapp_v2` задаёт значения по умолчанию
(`labops_pii/profiles.py`); явные переменные `PSEUDONYMIZER_*` и `PII_GUARD_*` главнее.

| | labops | pragmatika | webapp_v2 |
|---|---|---|---|
| хранилище | память | SQLite + Fernet | память |
| схема ключей SQLite при записи | v3 | v2 (читается прежним кодом) | v3 |
| срок хранения | 24 ч | 90 суток | 24 ч |
| юрлица (`MASK_LEGAL_ENTITY`) | маскируются | нет | маскируются |
| адреса (`ADDRESS_MASK`) | выкл. | вкл. (город остаётся) | выкл. |
| `/health` с `boot_id`, `DELETE /threads` | да | нет | да |
| `/inflect_signatory` | нет | да | нет |
| guard: ФИО и адреса | off | log_only | off |

ФИО guard ищет только эвристикой (`guard/names.py`); морфология из guard удалена в 0.7.0
(на реальных названиях давала лишь ложные), `PII_GUARD_NAMES_MORPH` ничего не включает.
10-значный ИНН организации guard блокирует по полю профиля `guard_block_org_inn` (в pragmatika
выключено); сервис маскирует ИНН любой длины во всех профилях. Белый список слов (`labops_pii/allowlist.py`): «Прагматика» (название проекта, все падежи,
с кавычками и без) не маскируется как ФИО или организация ни в сервисе, ни в guard, во всех
профилях; список — `Profile.allowed_words` плюс `PII_ALLOWED_WORDS` (основы через запятую).
Имена агентов (Tony, Carmella) в список не входят. Словарь контактов сервиса —
`PSEUDONYMIZER_CONTACTS_FILE` либо `Profile.contacts`.

## Установка и запуск

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e "python[dev]"            # ядро и сервис
pip install -e "python[dev,guard,media]"  # + guard и медиа
LABOPS_PII_PROFILE=labops PSEUDONYMIZER_API_TOKEN=... python -m labops_pii
uvicorn labops_pii.guard.litellm.app:app   # guard Прагматики
uvicorn labops_pii.guard.edge.app:build_app --factory   # guard web-app-v2
python -m labops_pii.media.mask          # маска фото и PDF
```

## Тесты

`tools/run_tests.sh` — каждый набор отдельным процессом (профиль задаётся окружением).
Для медиа нужен Tesseract (`MEDIA_MASKER_TESSERACT_CMD`, `PATH`, `TESSDATA_PREFIX`).
Главный критерий: `tests/test_reference_snapshots.py` сверяет ответы библиотеки по профилям
с эталонными снимками кода исходных копий на общем корпусе; расхождения (осознанные фиксы)
перечислены в `python/tests/fixtures/accepted_divergences.json` и CHANGELOG.
Переснять эталоны: `tools/reference_snapshot.py --impl original --src <копия>`.

## Медиа: распознанный текст, QR и рукопись (0.2.0, не выпущено)

`labops_pii.media.mask` кроме закраски отдаёт распознанное, одинаково для всех профилей:

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
- Профиль `pragmatika` использует только `gate`; его поведение и эталонные снимки не менялись.

Остаточные риски:

- рукопись, которую OCR прочитал как слово с уверенностью не ниже 40, не закрашивается и
  уходит текстом (после детектора ПДн);
- содержимое кода не в формате vCard/MECARD (ссылка, свободный текст) уходит текстом как есть:
  токенами становится только то, что нашёл детектор, то есть ссылка с ПДн внутри токенизируется
  лишь если детектор её распознал;
- эвристика пропускает письмо без контраста с фоном и всё на кадрах, где кандидатов > 20 %;
- адреса маскируются только там, где профиль включает `ADDRESS` (сейчас `pragmatika`).

## Вендоринг в проекты

```bash
tools/vendor.sh /путь/к/проекту v0.1.0 guard        # части: guard, service, media
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
differences live in profiles (`labops`, `pragmatika`, `webapp_v2`), selected with
`LABOPS_PII_PROFILE`. Projects consume it by vendoring (`tools/vendor.sh`), which writes a
`VERSION` file with sha256 hashes that a project test verifies.

## Лицензия

Proprietary, © 2026 LabOps.ai. All rights reserved. См. [LICENSE](LICENSE).
