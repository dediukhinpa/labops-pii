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
| `ts/` | фаза 2 (клиент, SSE, обход тела запроса Anthropic) — см. `ts/README.md` |

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

Морфология ФИО в guard — опция (`PII_GUARD_NAMES_MORPH=on`, нужны natasha и pymorphy3);
выключена во всех профилях. Белые списки имён (агенты, названия) — файл контактов сервиса
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

## Вендоринг в проекты

```bash
tools/vendor.sh /путь/к/проекту v0.1.0 guard        # части: guard, service, media
```

Файлы попадают в `vendor/labops-pii/` вместе с `VERSION` (тег, коммит, sha256 каждого файла).
Тест проекта (`examples/test_vendored_unchanged.py`) падает, если файлы правили руками.
Правки — только здесь: PR, тег, затем `vendor.sh` в проектах. Миграция баз —
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
