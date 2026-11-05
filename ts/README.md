# @labops/pii (фаза 2)

Перенесено (0.4.0): пункты 1–4 плана ниже, ядро pii-proxy; пункт 5 (детектор) ведётся отдельно.
Библиотека не читает окружение: настройки (URL, токены, политика вложений) передаёт проект.
Вендоринг: `tools/vendor.sh <проект> <тег> service,media,ts`. План (из /home/labops/reports/pii-shared-library-plan.md):

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
