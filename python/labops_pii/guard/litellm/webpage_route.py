"""Маршрут страниц сайтов: запрос с текстом ПУБЛИЧНОЙ страницы поставщика, проверка формы.

Решение владельца (этап 121): текст публичных страниц сайтов поставщиков - общедоступные данные,
поэтому ФИО, телефоны и почта на страницах контактов не должны отклонять запрос извлечения
фактов. Вариант «вырезать имена» отвергнут, выбран отдельный узкий маршрут.

Что маршрут НЕ отклоняет и почему (детектор шлюза ищет только цифровые и почтовые виды):
  * `phone` и `email` - обычное содержимое страниц контактов, это и есть то, что извлекаем;
  * ФИО (PERSON) и адреса детектор шлюза находит лишь эвристикой (режимы
    PII_GUARD_NAMES_MODE и PII_GUARD_ADDRESS_MODE), а здесь они не отклоняют ни в каком режиме;
    NER живёт в сервисе псевдонимизации у ядра;
    отдельный маршрут нужен, чтобы ядро могло не считать PERSON остаточной находкой
    (WEB_PAGE_MODEL_ROUTE).
Что по-прежнему отклоняется (422, как на основном маршруте): `inn`, `snils`, `card`, `account`.
Это идентификаторы, которые на странице поставщика не нужны для извлечения город/контакты/
цена/срок, а их утечка вреднее всего (реквизиты физлица, карта, счёт). Ослабление минимально:
ровно два вида из шести.

Форма запроса жёсткая: один user-текст, необязательный system, только model/max_tokens/
system/messages/temperature, `tools`/`tool_choice`/`stream` запрещены, модель только из списка,
тело до WEBPAGE_MAX_BODY_BYTES. Модуль не делает ввода-вывода и не логирует тела.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from labops_pii.guard.detector import BodyNotJsonError, BodyTooLargeError, scan_body
from labops_pii.guard.litellm.search_route import (
    REASON_ENCODING,
    REASON_KEYS,
    REASON_MESSAGES,
    REASON_METHOD,
    REASON_NOT_JSON,
    REASON_PARAMS,
    REASON_QUERY,
    REASON_SIZE,
    REASON_STREAM,
    REASON_TOOL_CHOICE,
    REASON_TOOLS,
    _params_ok,
    first_path_segment,
    parse_allowed_models,
)

# Единственный путь маршрута и пространство имён под ним (всё, кроме точного пути, - 403).
WEBPAGE_ROUTE_PATH = "/webpage/v1/messages"
WEBPAGE_NAMESPACE_SEGMENT = "webpage"
# Путь в апстриме: запрос уходит в обычный /v1/messages.
WEBPAGE_UPSTREAM_PATH = "/v1/messages"
WEBPAGE_FORM_CODE = "webpage_route_form"
WEBPAGE_ENABLED_ENV = "WEBPAGE_ROUTE_ENABLED"
WEBPAGE_ALLOWED_MODELS_ENV = "WEBPAGE_ALLOWED_MODELS"
# Пустой WEBPAGE_ALLOWED_MODELS не снимает ограничение, а даёт этот алиас (как на маршруте зрения).
DEFAULT_WEBPAGE_MODEL = "agent-main"
# Предел тела: инструкция + название + тексты нескольких страниц (кириллица - 2 байта на знак).
WEBPAGE_MAX_BODY_BYTES = 262144


ALLOWED_TOP_KEYS = frozenset({"model", "max_tokens", "system", "messages", "temperature"})
ALLOWED_TEXT_BLOCK_KEYS = frozenset({"type", "text", "cache_control"})
# Ядро помечает последний блок system и сообщения кэшем промпта (общий клиент модели); без этой
# метки в форме все запросы маршрута получали 403. Пропускается только точное значение.
EPHEMERAL_CACHE_CONTROL = {"type": "ephemeral"}
TEXT_BLOCK_TYPE = "text"
USER_ROLE = "user"
WEBPAGE_MAX_TEXT_BLOCKS = 32



@dataclass
class WebpageVerdict:
    """Итог проверки: причина отказа (или None) и виды найденных ПДн (только имена).

    На этом маршруте ПДн не причина отказа (решение владельца 28.10: текст публичных страниц
    сайтов - общедоступные данные), поэтому `pii_types` только для журнала.
    """

    reason: str | None = None
    pii_types: frozenset[str] = frozenset()


def parse_webpage_models(raw: str | None) -> frozenset[str]:
    """Допустимые model маршрута; пусто - только алиас агентов `agent-main`."""
    return parse_allowed_models(raw) or frozenset({DEFAULT_WEBPAGE_MODEL})


def is_webpage_namespace(path: str) -> bool:
    """Относится ли путь к пространству /webpage/ (без учёта регистра, %-кодирования, `//`)."""
    return first_path_segment(path) == WEBPAGE_NAMESPACE_SEGMENT


def check_webpage_head(method: str, query: str, content_encoding: str) -> str | None:
    """Проверка до чтения тела: метод, query-строка, кодирование.

    Returns:
        None или код причины отказа.
    """
    if method.upper() != "POST":
        return REASON_METHOD
    if query:
        return REASON_QUERY
    if content_encoding.strip().lower() not in ("", "identity"):
        return REASON_ENCODING
    return None


def _text_parts(content: Any) -> list[str] | None:
    """Тексты: строка либо непустой список блоков {type: text, text: str[, cache_control]}."""
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list) or not content or len(content) > WEBPAGE_MAX_TEXT_BLOCKS:
        return None
    out: list[str] = []
    for block in content:
        if not isinstance(block, dict) or set(block) - ALLOWED_TEXT_BLOCK_KEYS:
            return None
        if block.get("type") != TEXT_BLOCK_TYPE or not isinstance(block.get("text"), str):
            return None
        if "cache_control" in block and block["cache_control"] != EPHEMERAL_CACHE_CONTROL:
            return None
        out.append(block["text"])
    return out


def _check_form(data: Mapping[str, Any], allowed_models: frozenset[str]) -> str | None:
    """Форма разобранного тела: ключи, запрещённые поля, параметры, одно user-сообщение."""
    # Инструменты запрещены полностью: ключ не должен быть даже пустым списком
    if "tools" in data:
        return REASON_TOOLS
    if "tool_choice" in data:
        return REASON_TOOL_CHOICE
    if "stream" in data:
        return REASON_STREAM
    if not set(data) <= ALLOWED_TOP_KEYS:
        return REASON_KEYS
    if not _params_ok(data, allowed_models):
        return REASON_PARAMS
    messages = data.get("messages")
    if not isinstance(messages, list) or len(messages) != 1:
        return REASON_MESSAGES
    message = messages[0]
    if not isinstance(message, dict) or set(message) - {"role", "content"}:
        return REASON_MESSAGES
    if message.get("role") != USER_ROLE or _text_parts(message.get("content")) is None:
        return REASON_MESSAGES
    system = data.get("system")
    if system is not None and _text_parts(system) is None:
        return REASON_PARAMS
    return None


def check_webpage_request(
    method: str,
    query: str,
    content_encoding: str,
    body: bytes,
    allowed_models: frozenset[str] | None = None,
) -> WebpageVerdict:
    """Проверяет форму запроса и собирает виды ПДн для журнала (ПДн отказа не дают).

    Args:
        method: HTTP-метод.
        query: Строка запроса без `?`.
        content_encoding: Значение заголовка Content-Encoding.
        body: Тело запроса.
        allowed_models: Допустимые model (по умолчанию только `agent-main`).

    Returns:
        Вердикт: reason=None - запрос можно пересылать (pii_types - имена найденных видов,
        не значения); иначе - код причины отказа по форме или размеру.
    """
    models = allowed_models or frozenset({DEFAULT_WEBPAGE_MODEL})
    head = check_webpage_head(method, query, content_encoding)
    if head is not None:
        return WebpageVerdict(reason=head)
    if len(body) > WEBPAGE_MAX_BODY_BYTES:
        return WebpageVerdict(reason=REASON_SIZE)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return WebpageVerdict(reason=REASON_NOT_JSON)
    if not isinstance(data, dict):
        return WebpageVerdict(reason=REASON_NOT_JSON)
    form = _check_form(data, models)
    if form is not None:
        return WebpageVerdict(reason=form)
    try:
        # Тот же полный скан, что на основном маршруте (сырое тело, \u-экранирования, строки)
        found = scan_body(body, WEBPAGE_MAX_BODY_BYTES, True)
    except BodyTooLargeError:
        return WebpageVerdict(reason=REASON_SIZE)
    except BodyNotJsonError:
        return WebpageVerdict(reason=REASON_NOT_JSON)
    # Решение владельца 28.10: на маршруте публичных страниц никакой вид ПДн (ФИО, телефоны,
    # ИНН, реквизиты и т. п. со страниц поставщиков) не причина отказа. Защита маршрута -
    # форма запроса (только текст, без tools, разрешённый алиас, предел размера) и то, что ядро
    # кладёт в него лишь инструкцию, текст страницы и название товара.
    return WebpageVerdict(pii_types=frozenset(found))
