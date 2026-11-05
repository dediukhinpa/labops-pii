"""Маршрут веб-поиска: проверка ФОРМЫ запроса вместо фильтра ПДн.

Запрос поиска намеренно не анонимизируется (владелец: нужен поиск по ИНН и ФИО), поэтому
на этом маршруте допустим только узкий короткий запрос с серверным инструментом поиска.
Любое отклонение от формы - отказ. Модуль не делает ввода-вывода и не логирует тела.
"""

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote

from labops_pii.guard.detector import find_pii_types
from labops_pii.guard.policy import split_findings

# Единственный путь маршрута и пространство имён под ним (всё, кроме точного пути, - 403).
SEARCH_ROUTE_PATH = "/search/v1/messages"
SEARCH_NAMESPACE_PREFIX = "/search/"
# Путь в апстриме: запрос уходит в обычный /v1/messages, а не под /search/.
SEARCH_UPSTREAM_PATH = "/v1/messages"
SEARCH_MAX_BODY_BYTES = 4096
# Продолжение после pause_turn несёт ответ ассистента (результаты поиска), поэтому тело больше.
SEARCH_CONTINUATION_MAX_BODY_BYTES = 262144
SEARCH_ENABLED_ENV = "SEARCH_ROUTE_ENABLED"
SEARCH_ALLOWED_MODELS_ENV = "SEARCH_ALLOWED_MODELS"
SEARCH_TOOL_TYPE_PREFIX = "web_search_"
SEARCH_TOOL_NAME = "web_search"
# Предел текста user-сообщения и system (в байтах UTF-8) в любом варианте запроса.
SEARCH_MAX_TEXT_BYTES = 4096
# Пределы скалярных параметров.
SEARCH_MAX_USES_LIMIT = 10
SEARCH_MAX_TOKENS_LIMIT = 8192
SEARCH_TEMPERATURE_MAX = 1.0
SEARCH_MODEL_MAX_LEN = 128
# Ровно один инструмент: либо поиск, либо чтение. Смешение дало бы модели возможность искать
# и тут же читать найденные адреса, а шлюз проверяет URL только по заданному allowed_domains.
SEARCH_MAX_TOOLS = 1
SEARCH_TOOL_MAX_JSON_BYTES = 2048
# Пределы блоков ответа ассистента (при продолжении).
SEARCH_TOOL_INPUT_MAX_BYTES = 1024
SEARCH_ASSISTANT_TEXT_MAX_CHARS = 8192
SEARCH_CITED_TEXT_MAX_CHARS = 1024
SEARCH_ASSISTANT_TEXT_TOTAL_BYTES = 32768  # text и cited_text суммарно по всем блокам
SEARCH_MAX_ASSISTANT_BLOCKS = 64
SEARCH_MAX_RESULTS_PER_BLOCK = 32
SEARCH_ID_MAX_LEN = 128
SEARCH_URL_MAX_LEN = 2048
SEARCH_TITLE_MAX_LEN = 512
SEARCH_SHORT_MAX_LEN = 64
SEARCH_FORM_CODE = "search_route_form"

# Серверный web_fetch: читает страницу по URL из разговора. Тип - только датированная версия.
FETCH_TOOL_TYPE_PREFIX = "web_fetch_"
# fullmatch + re.ASCII: `$` пропускает завершающий \n, а `\d` без ASCII принимает юникод-цифры.
FETCH_TOOL_TYPE_RE = re.compile(r"web_fetch_\d{8}", re.ASCII)
FETCH_TOOL_NAME = "web_fetch"
# Пределы fetch-инструмента: без них один запрос мог бы прочитать много чужих страниц и
# раздуть расход токенов. Отсутствие любого из трёх обязательных параметров - отказ.
FETCH_MAX_DOMAINS = 5
FETCH_MAX_USES_LIMIT = 5
FETCH_MAX_CONTENT_TOKENS_LIMIT = 50000
# Сообщение fetch-запроса: адреса и короткая инструкция. Адресов немного: один кандидат - один сайт.
FETCH_MAX_URLS = 3
FETCH_URL_MAX_LEN = 250  # предел самого провайдера (url_too_long)
FETCH_INSTRUCTION_MAX_BYTES = 1024  # текст сообщения без адресов
FETCH_DOMAIN_MAX_LEN = 253
ALLOWED_FETCH_TOOL_KEYS = frozenset(
    {"type", "name", "allowed_domains", "max_uses", "max_content_tokens"}
)
# Метка имени хоста (LDH) и целый адрес: схема, хост, необязательный путь из безопасных
# символов. Порт, userinfo, query, фрагмент, обратный слэш и юникод не проходят по построению.
# Все три разбираются через fullmatch и с re.ASCII: иначе `$` терпит хвостовой \n,
# а без ASCII IGNORECASE сопоставляет юникод-символы (например, знак Кельвина) с a-z.
_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_DOMAIN_TLD_RE = re.compile(r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})", re.ASCII)
_FETCH_URL_RE = re.compile(r"(?i:https?)://([^/?#@\\:\s]+)((?:/[A-Za-z0-9._~%-]*)*)", re.ASCII)
# Остаток сообщения (инструкция) не должен сам нести адрес или доменоподобное слово
_URL_HINT_RE = re.compile(r"(?i)://|@|\bwww\.|[a-z0-9-]\.[a-z]{2,63}(?![a-z0-9])")

# Явный allowlist ключей верхнего уровня (stream сюда не входит: ответ целиком).
ALLOWED_TOP_KEYS = frozenset(
    {"model", "max_tokens", "system", "messages", "tools", "tool_choice", "temperature"}
)
ALLOWED_TOOL_CHOICE_TYPES = frozenset({"auto", "any", "none"})
ALLOWED_TOOL_CHOICE_KEYS = frozenset({"type", "name", "disable_parallel_tool_use"})
ALLOWED_TOOL_KEYS = frozenset(
    {"type", "name", "max_uses", "user_location", "allowed_domains", "blocked_domains"}
)
ALLOWED_TEXT_BLOCK_KEYS = frozenset({"type", "text"})
ALLOWED_SERVER_TOOL_USE_KEYS = frozenset({"type", "id", "name", "input", "caller"})
ALLOWED_RESULT_BLOCK_KEYS = frozenset({"type", "tool_use_id", "content", "caller"})
ALLOWED_RESULT_ITEM_KEYS = frozenset(
    {"type", "url", "title", "encrypted_content", "page_age"}
)
ALLOWED_ASSISTANT_TEXT_KEYS = frozenset({"type", "text", "citations"})
ALLOWED_CITATION_KEYS = frozenset({"type", "url", "title", "cited_text", "encrypted_index"})
# Единственный допустимый вид caller: прямой вызов модели.
CALLER_DIRECT = {"type": "direct"}
USER_ROLE = "user"
ASSISTANT_ROLE = "assistant"
# Блоки ответа ассистента, допустимые при продолжении (thinking, tool_use и прочее - отказ)
ALLOWED_ASSISTANT_BLOCK_TYPES = frozenset({"server_tool_use", "web_search_tool_result", "text"})
TEXT_BLOCK_TYPE = "text"

# Коды причин отказа (попадают в журнал и ответ; значения из тела не попадают никуда)
REASON_METHOD = "method"
REASON_QUERY = "query_string"
REASON_ENCODING = "content_encoding"
REASON_SIZE = "body_size"
REASON_NOT_JSON = "not_json_object"
REASON_KEYS = "top_level_keys"
REASON_MESSAGES = "messages"
REASON_TOOLS = "tools"
REASON_TOOL_CHOICE = "tool_choice"
REASON_STREAM = "stream"
REASON_PARAMS = "params"
REASON_FETCH_URL = "fetch_url"


def first_path_segment(path: str) -> str:
    """Первый сегмент пути после нормализации (строчные буквы, без `//`, `.`, %-кодирования).

    Путь раскодируется до стабильного состояния, чтобы %2e, %2F, двойное кодирование и
    `//search` не обходили проверку. Общий для пространств /search/ и /vision/.

    Args:
        path: Путь запроса (как в ASGI scope или сырой).

    Returns:
        Первый сегмент или пустая строка.
    """
    current = path
    for _ in range(4):  # конечное число проходов: хватает против многократного кодирования
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    parts = [p for p in current.replace("\\", "/").lower().split("/") if p not in ("", ".")]
    return parts[0].strip() if parts else ""


def is_search_namespace(path: str) -> bool:
    """Относится ли путь к пространству /search/ (без учёта регистра и повторных слэшей).

    Args:
        path: Путь запроса (как в ASGI scope или сырой).

    Returns:
        True, если первый сегмент после нормализации равен `search`.
    """
    return first_path_segment(path) == "search"


def _text_bytes(content: Any) -> int | None:
    """Размер текста user/system в байтах UTF-8 или None, если форма не текстовая.

    Строка либо непустой список блоков строго `{type: text, text: str}` (прочие ключи -
    канал для протаскивания данных, поэтому отказ).
    """
    if isinstance(content, str):
        return len(content.encode("utf-8"))
    if not isinstance(content, list) or not content:
        return None
    total = 0
    for block in content:
        if not isinstance(block, dict) or set(block) - ALLOWED_TEXT_BLOCK_KEYS:
            return None
        if block.get("type") != TEXT_BLOCK_TYPE or not isinstance(block.get("text"), str):
            return None
        total += len(block["text"].encode("utf-8"))
    return total


def _is_str(value: Any, limit: int) -> bool:
    """Строка не длиннее limit символов."""
    return isinstance(value, str) and len(value) <= limit


def _json_size(value: Any) -> int:
    """Размер значения в JSON (байты UTF-8)."""
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def _caller_ok(block: Mapping[str, Any]) -> bool:
    """caller отсутствует или равен прямому вызову."""
    return "caller" not in block or block["caller"] == CALLER_DIRECT


def _server_tool_use_ok(block: Mapping[str, Any]) -> bool:
    """Серверный вызов поиска: только web_search и маленький input из одного query."""
    if set(block) - ALLOWED_SERVER_TOOL_USE_KEYS or not _caller_ok(block):
        return False
    if block.get("name") != SEARCH_TOOL_NAME or not _is_str(block.get("id"), SEARCH_ID_MAX_LEN):
        return False
    tool_input = block.get("input")
    if not isinstance(tool_input, dict) or set(tool_input) - {"query"}:
        return False
    if "query" in tool_input and not isinstance(tool_input["query"], str):
        return False
    return _json_size(tool_input) <= SEARCH_TOOL_INPUT_MAX_BYTES


def _result_item_ok(item: Any) -> bool:
    """Один web_search_result: allowlist ключей и разумные длины полей."""
    if not isinstance(item, dict) or set(item) - ALLOWED_RESULT_ITEM_KEYS:
        return False
    if item.get("type") != "web_search_result":
        return False
    if not isinstance(item.get("encrypted_content"), str):
        return False
    page_age = item.get("page_age")
    return (
        _is_str(item.get("url"), SEARCH_URL_MAX_LEN)
        and _is_str(item.get("title"), SEARCH_TITLE_MAX_LEN)
        and (page_age is None or _is_str(page_age, SEARCH_SHORT_MAX_LEN))
    )


def _result_block_ok(block: Mapping[str, Any]) -> bool:
    """web_search_tool_result: список результатов либо объект ошибки."""
    if set(block) - ALLOWED_RESULT_BLOCK_KEYS or not _caller_ok(block):
        return False
    if not _is_str(block.get("tool_use_id"), SEARCH_ID_MAX_LEN):
        return False
    content = block.get("content")
    if isinstance(content, list):
        return len(content) <= SEARCH_MAX_RESULTS_PER_BLOCK and all(
            _result_item_ok(i) for i in content
        )
    if isinstance(content, dict):
        return (
            set(content) == {"type", "error_code"}
            and content["type"] == "web_search_tool_result_error"
            and _is_str(content["error_code"], SEARCH_SHORT_MAX_LEN)
        )
    return False


def _citation_bytes(citation: Any) -> int | None:
    """Размер cited_text цитаты в байтах или None, если цитата недопустима."""
    if not isinstance(citation, dict) or set(citation) - ALLOWED_CITATION_KEYS:
        return None
    if citation.get("type") != "web_search_result_location":
        return None
    cited = citation.get("cited_text")
    if not _is_str(cited, SEARCH_CITED_TEXT_MAX_CHARS):
        return None
    if not _is_str(citation.get("url"), SEARCH_URL_MAX_LEN):
        return None
    if not _is_str(citation.get("title"), SEARCH_TITLE_MAX_LEN):
        return None
    if not isinstance(citation.get("encrypted_index"), str):
        return None
    return len(cited.encode("utf-8"))


def _text_block_bytes(block: Mapping[str, Any]) -> int | None:
    """Размер text и cited_text блока ответа в байтах или None, если блок недопустим."""
    if set(block) - ALLOWED_ASSISTANT_TEXT_KEYS:
        return None
    if not _is_str(block.get("text"), SEARCH_ASSISTANT_TEXT_MAX_CHARS):
        return None
    total = len(block["text"].encode("utf-8"))
    citations = block.get("citations")
    if citations is None:
        return total
    if not isinstance(citations, list) or len(citations) > SEARCH_MAX_RESULTS_PER_BLOCK:
        return None
    for citation in citations:
        size = _citation_bytes(citation)
        if size is None:
            return None
        total += size
    return total


def check_search_form(
    method: str,
    query: str,
    content_encoding: str,
    body: bytes,
    allowed_models: frozenset[str] | None = None,
) -> str | None:
    """Проверяет форму запроса поиска.

    Args:
        method: HTTP-метод.
        query: Строка запроса без `?`.
        content_encoding: Значение заголовка Content-Encoding.
        body: Тело запроса.
        allowed_models: Допустимые значения model (None - любая строка до 128 символов).

    Returns:
        None, если форма допустима, иначе короткий код причины отказа.
    """
    if method.upper() != "POST":
        return REASON_METHOD
    if query:
        return REASON_QUERY
    if content_encoding.strip().lower() not in ("", "identity"):
        return REASON_ENCODING
    if len(body) > SEARCH_CONTINUATION_MAX_BODY_BYTES:
        return REASON_SIZE
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return REASON_NOT_JSON
    if not isinstance(data, dict):
        return REASON_NOT_JSON
    if "stream" in data:
        return REASON_STREAM
    if not set(data) <= ALLOWED_TOP_KEYS:
        return REASON_KEYS
    return _check_fields(data, len(body), allowed_models)


def _is_assistant_continuation(message: Any) -> bool:
    """Сообщение ассистента: список блоков только допустимых типов и форм."""
    if not isinstance(message, dict) or set(message) - {"role", "content"}:
        return False
    content = message.get("content")
    if message.get("role") != ASSISTANT_ROLE or not isinstance(content, list) or not content:
        return False
    if len(content) > SEARCH_MAX_ASSISTANT_BLOCKS:
        return False
    text_total = 0
    for block in content:
        if not isinstance(block, dict) or block.get("type") not in ALLOWED_ASSISTANT_BLOCK_TYPES:
            return False
        kind = block["type"]
        if kind == "server_tool_use":
            ok = _server_tool_use_ok(block)
        elif kind == "web_search_tool_result":
            ok = _result_block_ok(block)
        else:
            size = _text_block_bytes(block)
            ok = size is not None
            text_total += size or 0
        if not ok:
            return False
    return text_total <= SEARCH_ASSISTANT_TEXT_TOTAL_BYTES


def _valid_domain(value: Any) -> bool:
    """Имя хоста: строчные ASCII-метки, минимум две, TLD буквенный (IP и подстановки не проходят).

    Регистр не нормализуется, а отвергается: нормализация - дело вызывающего, шлюз fail closed.
    """
    if not isinstance(value, str) or not value or len(value) > FETCH_DOMAIN_MAX_LEN:
        return False
    labels = value.split(".")
    if len(labels) < 2 or not all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return False
    return bool(_DOMAIN_TLD_RE.fullmatch(labels[-1]))


def _host_in_domains(host: str, domains: list[str]) -> bool:
    """Хост равен разрешённому домену или его поддомену (граница по точке, не по суффиксу)."""
    return any(host == d or host.endswith("." + d) for d in domains)


def _fetch_tool_ok(tool: Mapping[str, Any]) -> bool:
    """web_fetch: обязательные allowed_domains, max_uses и max_content_tokens в пределах.

    blocked_domains, citations, url_sources, use_cache и response_inclusion не допускаются:
    allowed_domains уже сужает область, а лишние ключи - ненужная поверхность.
    """
    if set(tool) - ALLOWED_FETCH_TOOL_KEYS or tool.get("name") != FETCH_TOOL_NAME:
        return False
    tool_type = tool.get("type")
    if not isinstance(tool_type, str) or not FETCH_TOOL_TYPE_RE.fullmatch(tool_type):
        return False
    domains = tool.get("allowed_domains")
    if not isinstance(domains, list) or not 1 <= len(domains) <= FETCH_MAX_DOMAINS:
        return False
    if not all(_valid_domain(d) for d in domains):
        return False
    for key, limit in (
        ("max_uses", FETCH_MAX_USES_LIMIT),
        ("max_content_tokens", FETCH_MAX_CONTENT_TOKENS_LIMIT),
    ):
        value = tool.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= limit:
            return False
    return _json_size(tool) <= SEARCH_TOOL_MAX_JSON_BYTES


def _plain_text(content: Any) -> str | None:
    """Текст user/system одной строкой (блоки через перевод строки) или None при иной форме."""
    if _text_bytes(content) is None:
        return None
    if isinstance(content, str):
        return content
    return "\n".join(block["text"] for block in content)


def _fetch_text_ok(text: str, domains: list[str], need_urls: bool) -> bool:
    """Текст fetch-запроса: только адреса на разрешённых доменах и инструкция без ПДн.

    В отличие от поискового запроса (ПДн там допустимы по решению владельца), здесь текст
    уходит на сторонний сайт как часть адреса и инструкции, поэтому ПДн запрещены целиком.
    Каждый токен, начинающийся со схемы, обязан быть полным безопасным адресом; остальной
    текст не должен содержать адресов и доменоподобных слов.
    """
    urls: list[str] = []
    rest: list[str] = []
    for token in text.split():
        if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", token):
            urls.append(token)
        else:
            rest.append(token)
    if len(urls) > FETCH_MAX_URLS or (need_urls and not urls):
        return False
    for url in urls:
        match = _FETCH_URL_RE.fullmatch(url)
        if len(url) > FETCH_URL_MAX_LEN or not match:
            return False
        host = match.group(1).lower()
        if not _valid_domain(host) or not _host_in_domains(host, domains):
            return False
    instruction = " ".join(rest)
    if len(instruction.encode("utf-8")) > FETCH_INSTRUCTION_MAX_BYTES:
        return False
    if _URL_HINT_RE.search(instruction):
        return False
    # ФИО и адрес в log_only не блокируют и здесь (инструкция fetch); в enforce - блокирует
    return not split_findings(find_pii_types(text)).blocking


def _tool_ok(tool: Any) -> bool:
    """Инструмент: поиск (web_search_*) или чтение (web_fetch_*), каждый со своим allowlist."""
    if not isinstance(tool, dict):
        return False
    if tool.get("name") == FETCH_TOOL_NAME:
        return _fetch_tool_ok(tool)
    if set(tool) - ALLOWED_TOOL_KEYS:
        return False
    tool_type = tool.get("type")
    if not isinstance(tool_type, str) or not tool_type.startswith(SEARCH_TOOL_TYPE_PREFIX):
        return False
    if tool.get("name") != SEARCH_TOOL_NAME:
        return False
    if "max_uses" in tool:
        uses = tool["max_uses"]
        if isinstance(uses, bool) or not isinstance(uses, int):
            return False
        if not 1 <= uses <= SEARCH_MAX_USES_LIMIT:
            return False
    return _json_size(tool) <= SEARCH_TOOL_MAX_JSON_BYTES


def _params_ok(data: Mapping[str, Any], allowed_models: frozenset[str] | None) -> bool:
    """model, max_tokens и temperature в допустимых пределах."""
    model = data.get("model")
    if model is None:
        if allowed_models is not None:
            return False
    elif not _is_str(model, SEARCH_MODEL_MAX_LEN):
        return False
    elif allowed_models is not None and model not in allowed_models:
        return False
    max_tokens = data.get("max_tokens")
    if max_tokens is not None:
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
            return False
        if not 1 <= max_tokens <= SEARCH_MAX_TOKENS_LIMIT:
            return False
    temp = data.get("temperature")
    if temp is not None:
        if isinstance(temp, bool) or not isinstance(temp, (int, float)):
            return False
        if not 0 <= temp <= SEARCH_TEMPERATURE_MAX:  # NaN тоже даёт False
            return False
    return True


def parse_allowed_models(raw: str | None) -> frozenset[str] | None:
    """Список допустимых моделей из строки через запятую; пусто - без ограничения."""
    names = frozenset(p.strip() for p in (raw or "").split(",") if p.strip())
    return names or None


def _fetch_domains(tools: Any) -> list[str] | None:
    """allowed_domains единственного fetch-инструмента или None, если это не fetch-запрос.

    Только выбирает ветку проверки текста; сам инструмент полностью проверяет `_tool_ok`
    (при невалидных доменах вернётся пустой список, и текст не пройдёт - fail closed).
    """
    if not isinstance(tools, list) or len(tools) != 1 or not isinstance(tools[0], dict):
        return None
    if tools[0].get("name") != FETCH_TOOL_NAME:
        return None
    domains = tools[0].get("allowed_domains")
    if isinstance(domains, list) and all(isinstance(d, str) for d in domains):
        return list(domains)
    return []


def _check_fields(
    data: Mapping[str, Any], size: int, allowed_models: frozenset[str] | None = None
) -> str | None:
    """Проверяет сообщения, инструменты и скалярные параметры."""
    messages = data.get("messages")
    if not isinstance(messages, list) or len(messages) not in (1, 2):
        return REASON_MESSAGES
    message = messages[0]
    if not isinstance(message, dict) or set(message) - {"role", "content"}:
        return REASON_MESSAGES
    if message.get("role") != USER_ROLE:
        return REASON_MESSAGES
    user_bytes = _text_bytes(message.get("content"))
    if user_bytes is None:
        return REASON_MESSAGES
    # Предел текста действует всегда: у продолжения снимается лишь общий предел тела
    if user_bytes > SEARCH_MAX_TEXT_BYTES:
        return REASON_SIZE
    tools = data.get("tools")
    fetch_domains = _fetch_domains(tools)
    if fetch_domains is not None:
        # Продолжение после pause_turn для fetch не поддерживается (fail closed): ответ ассистента
        # несёт текст чужих страниц, а при динамической фильтрации и блоки выполнения кода -
        # проверять их allowlist-ом нечем, а канал для протаскивания данных был бы широким.
        # Вызывающий при pause_turn считает чтение неудачным и не повторяет его.
        if not _tool_ok(tools[0]):
            return REASON_TOOLS
        if len(messages) != 1:
            return REASON_MESSAGES
        user_text = _plain_text(message.get("content"))
        if user_text is None or not _fetch_text_ok(user_text, fetch_domains, need_urls=True):
            return REASON_FETCH_URL
    if len(messages) == 2:
        if not _is_assistant_continuation(messages[1]):
            return REASON_MESSAGES
    elif size > SEARCH_MAX_BODY_BYTES:
        return REASON_SIZE
    system = data.get("system")
    if system is not None:
        system_bytes = _text_bytes(system)
        if system_bytes is None:
            return REASON_PARAMS
        if system_bytes > SEARCH_MAX_TEXT_BYTES:
            return REASON_SIZE
        if fetch_domains is not None:
            system_text = _plain_text(system)
            # Пустой список доменов: адреса в system не допускаются вовсе (fetch их там не видит)
            if system_text is None or not _fetch_text_ok(system_text, [], False):
                return REASON_FETCH_URL

    if not isinstance(tools, list) or not tools or len(tools) > SEARCH_MAX_TOOLS:
        return REASON_TOOLS
    if not all(_tool_ok(tool) for tool in tools):
        return REASON_TOOLS
    names = {tool["name"] for tool in tools}

    choice = data.get("tool_choice")
    if choice is not None:
        if not isinstance(choice, dict) or set(choice) - ALLOWED_TOOL_CHOICE_KEYS:
            return REASON_TOOL_CHOICE
        kind = choice.get("type")
        if kind == "tool":
            if choice.get("name") not in names:
                return REASON_TOOL_CHOICE
        elif kind not in ALLOWED_TOOL_CHOICE_TYPES or "name" in choice:
            return REASON_TOOL_CHOICE

    if not _params_ok(data, allowed_models):
        return REASON_PARAMS
    return None
