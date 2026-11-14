# @labops/pii (фаза 2)

Перенесено: пункты 1–4 плана ниже, ядро TS-прокси маскирования; пункт 5 (детектор) ведётся отдельно.
Библиотека не читает окружение: настройки (URL, токены, политика вложений) передаёт проект.
Вендоринг: `tools/vendor.sh <проект> <тег> service,media,ts`. План:

1. Клиент HTTP-сервиса: `pseudonymize`, `pseudonymizeBatch`, `restore`, `check`, `deleteThread`,
   разбор `boot_id` (потеря таблицы в памяти), таймауты и повторы.
2. Буфер границы токена и восстановление SSE (токен, разорванный между чанками).
3. Обход тела запроса к модели: листья, `tool_use`, служебные блоки; пачки по формуле
   `batch_cost_chars`.
4. Кэш масок и память восстановлений.
5. Детектор ФИО и адресов на TS (по запросу потребителя: `web-page-sanitize.ts` не ловит
   «Иванов Иван»); шаблоны берутся из `python/labops_pii/pii_patterns.py`, паритет проверяется
   общим корпусом `python/tests/fixtures/common_corpus.json`.

Из этого проекты собирают свои прокси и шлюзы модели.

## Остаток ПДн после маски (с 1.1.0)

`RequestMasker.mask` при находке `/check` в замаскированном листе вызывает
`Pseudonymizer.remaskBatch` (`POST /remask_batch`), проверяет результат снова и после
`REMASK_MAX_PASSES` проходов заменяет лист на `PII_HIDDEN_TEXT`; запрос не отклоняется.
`MaskStats.remaskedLeaves` / `hiddenLeaves` и событие журнала `pii_after_mask_fixed` дают
счётчики без текстов. Подмена `Pseudonymizer` без `remaskBatch` (и старый сервис с 404) даёт
заглушку. `onResidualPii: 'reject'` возвращает отказ `422 pii_after_mask` (откат).

## Детектор ФИО и адресов (`src/detector/`)

```ts
import { detectNamesAndAddresses, replaceSpans } from '@labops/pii';

const spans = detectNamesAndAddresses(text, { allowedWords: ['вектрик'] });
const clean = replaceSpans(text, spans, (s) => (s.kind === 'person' ? '[ФИО]' : '[адрес]'));
```

Адреса ищутся по умолчанию (с 1.0.0); выключаются явно `{ maskAddresses: false }`.
Синхронно, без сети. Словарь имён генерируется `tools/gen_ts_name_dictionary.py`, эталон для
паритета — `tools/build_ts_detector_fixture.py` (оба запускаются в `.venv` репозитория).
