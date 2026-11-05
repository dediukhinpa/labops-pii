"""Общие данные тестов: апстримы и транспорт."""

from labops_pii.guard.edge.config import Upstream, parse_upstreams

# Апстрим для тестов: http допустим только к loopback, транспорт всё равно подменяется
UPSTREAMS: dict[str, Upstream] = parse_upstreams(
    "anthropic=http://127.0.0.1:9,deepseek=http://127.0.0.1:9/anthropic"
)

# Основной маршрут CLI через guard
MESSAGES = "/u/anthropic/v1/messages"
