# @labops/pii (фаза 2, не реализовано)

Каталог зарезервирован. План (из /home/labops/reports/pii-shared-library-plan.md):

1. Клиент HTTP-сервиса: `pseudonymize`, `pseudonymizeBatch`, `restore`, `check`, `deleteThread`,
   разбор `boot_id` (потеря таблицы в памяти), таймауты и повторы.
2. Буфер границы токена и восстановление SSE (токен, разорванный между чанками).
3. Обход тела запроса к модели: листья, `tool_use`, служебные блоки; пачки по формуле
   `batch_cost_chars`.
4. Кэш масок и память восстановлений.
5. Детектор ФИО и адресов на TS (по запросу Прагматики: `web-page-sanitize.ts` не ловит
   «Иванов Иван»); шаблоны берутся из `python/labops_pii/pii_patterns.py`, паритет проверяется
   общим корпусом `python/tests/fixtures/common_corpus.json`.

Из этого собираются pii-proxy (labops), `PseudonymizingModelGateway` (Прагматика), turn-pii (v2).

## Детектор ФИО и адресов (`src/detector/`)

```ts
import { detectNamesAndAddresses, replaceSpans } from '@labops/pii';

const spans = detectNamesAndAddresses(text, { profile: 'pragmatika' });
const clean = replaceSpans(text, spans, (s) => (s.kind === 'person' ? '[ФИО]' : '[адрес]'));
```

Синхронно, без сети. Словарь имён генерируется `tools/gen_ts_name_dictionary.py`, эталон для
паритета — `tools/build_ts_detector_fixture.py` (оба запускаются в `.venv` репозитория).
