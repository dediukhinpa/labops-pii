"""Счётчики срабатываний guard по типам: закрытый список меток, отсутствие значений ПДн."""

from __future__ import annotations

import httpx
import pytest

from labops_pii.guard.litellm.app import create_app
from labops_pii.guard.metrics import (
    DENIED_METRIC,
    FINDINGS_METRIC,
    METRIC_TYPES,
    METRICS,
    GuardMetrics,
    metric_label,
)

MODE_ENV = "PII_GUARD_NAMES_MODE"
FIO = "Иванов Иван Иванович"
PHONE = "+7 916 123 45 67"


async def _stream(data: bytes):
    yield data


def _client() -> httpx.AsyncClient:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    app = create_app("http://upstream", transport=httpx.MockTransport(handler))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


@pytest.fixture(autouse=True)
def _reset() -> None:
    METRICS.reset()


def test_closed_label_list() -> None:
    assert METRIC_TYPES == (
        "phone", "email", "inn", "snils", "card", "account", "name", "address", "other",
    )
    assert metric_label("phone") == "phone"
    assert metric_label("address") == "address"  # зарезервирован под этап Г
    assert metric_label("Иванов Иван") == "other"  # произвольная строка в метку не идёт
    assert metric_label("") == "other"


def test_render_has_all_series_from_zero() -> None:
    text = GuardMetrics().render()
    for metric in (FINDINGS_METRIC, DENIED_METRIC):
        assert f"# TYPE {metric} counter" in text
        for label in METRIC_TYPES:
            assert f'{metric}{{type="{label}"}} 0' in text


def test_one_request_counts_each_type_once() -> None:
    metrics = GuardMetrics()
    metrics.record_denied(["phone", "phone", "weird"])
    assert metrics.snapshot(DENIED_METRIC)["phone"] == 1
    assert metrics.snapshot(DENIED_METRIC)["other"] == 1


async def test_log_only_counts_findings_not_denials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "log_only")
    async with _client() as c:
        assert (await c.post("/v1/messages", json={"content": FIO})).status_code == 200
        text = (await c.get("/_guard/metrics")).text
    assert f'{FINDINGS_METRIC}{{type="name"}} 1' in text
    assert f'{DENIED_METRIC}{{type="name"}} 0' in text


async def test_enforce_and_phone_count_denials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "enforce")
    async with _client() as c:
        await c.post("/v1/messages", json={"content": f"{FIO} {PHONE}"})
        await c.post("/v1/messages", json={"content": "без данных"})
        text = (await c.get("/_guard/metrics")).text
    for label in ("name", "phone"):
        assert f'{DENIED_METRIC}{{type="{label}"}} 1' in text
        assert f'{FINDINGS_METRIC}{{type="{label}"}} 1' in text


async def test_no_pii_values_in_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODE_ENV, "enforce")
    async with _client() as c:
        await c.post("/v1/messages", json={"content": f"{FIO} {PHONE}"})
        text = (await c.get("/_guard/metrics")).text
    for fragment in ("Иванов", "916", "123 45"):
        assert fragment not in text
    # только имена серий и закрытые метки
    for line in text.splitlines():
        assert line.startswith("#") or line.split("{")[0] in (FINDINGS_METRIC, DENIED_METRIC)


async def test_metrics_route_is_known_for_log() -> None:
    from labops_pii.guard.litellm.jsonlog import known_route

    assert known_route("/_guard/metrics") == "/_guard/metrics"
