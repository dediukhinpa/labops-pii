"""Тесты маршрута зрения: форма, base64, mime, размеры, лимиты, ПДн в тексте, флаг, журнал."""

import base64
import json
import logging
import struct
import zlib
from typing import Any

import httpx
import pytest

from labops_pii.guard.litellm.app import create_app
from labops_pii.guard.litellm.vision_route import (
    VISION_ROUTE_PATH,
    VisionLimits,
    check_vision_request,
    image_dimensions,
    is_vision_namespace,
    parse_vision_models,
)

PII_TEXT = "владелец ИНН 7707083893, звонить +7 916 123 45 67"
PROMPT = "Опиши изделие на фото: материал, размеры, нанесение."


def _png(width: int = 64, height: int = 48) -> bytes:
    """Минимальный валидный по заголовку PNG (IHDR + IEND)."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data)
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IEND", b"")


def _jpeg(width: int = 200, height: int = 100) -> bytes:
    """JPEG-заголовок: SOI, APP0, SOF0 с размерами, SOS (кадр до SOS)."""
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + app0 + sof + b"\xff\xda\x00\x02" + b"\x00" * 8 + b"\xff\xd9"


def _gif(width: int = 30, height: int = 20) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00\x00\x00;"


def _webp_vp8x(width: int = 300, height: int = 200) -> bytes:
    payload = b"\x00\x00\x00\x00" + (width - 1).to_bytes(3, "little")
    payload += (height - 1).to_bytes(3, "little")
    chunk = b"VP8X" + struct.pack("<I", len(payload)) + payload
    return b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk


def _webp_vp8(width: int = 120, height: int = 80) -> bytes:
    frame = b"\x00\x00\x00" + b"\x9d\x01\x2a" + struct.pack("<HH", width, height) + b"\x00" * 4
    chunk = b"VP8 " + struct.pack("<I", len(frame)) + frame
    return b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk


def _webp_vp8l(width: int = 90, height: int = 70) -> bytes:
    bits = (width - 1) | ((height - 1) << 14)
    data = b"\x2f" + struct.pack("<I", bits) + b"\x00" * 4
    chunk = b"VP8L" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _image(raw: bytes | None = None, mime: str = "image/png", **source: Any) -> dict[str, Any]:
    src: dict[str, Any] = {
        "type": "base64", "media_type": mime, "data": _b64(raw if raw is not None else _png()),
    }
    src.update(source)
    return {"type": "image", "source": src}


def _body(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "model": "agent-main",
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": [_image(), {"type": "text", "text": PROMPT}]}
        ],
    }
    data.update(over)
    return data


async def _stream(data: bytes):
    yield data


def _transport(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=_stream(b'{"ok": true}'))

    return httpx.MockTransport(handler)


def _client(
    seen: list[httpx.Request], enabled: bool = True, limits: VisionLimits | None = None
) -> httpx.AsyncClient:
    app = create_app(
        "http://upstream", transport=_transport(seen), vision_enabled=enabled,
        vision_limits=limits,
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://guard")


async def test_valid_request_forwarded_to_v1_messages() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(
            VISION_ROUTE_PATH, json=_body(),
            headers={"x-api-key": "k", "anthropic-version": "1", "anthropic-beta": "x"},
        )
    assert r.status_code == 200
    assert len(seen) == 1
    assert seen[0].url.path == "/v1/messages"
    assert seen[0].headers["x-api-key"] == "k"
    assert "anthropic-beta" not in seen[0].headers
    assert json.loads(seen[0].content) == _body()


@pytest.mark.parametrize(
    ("raw", "mime"),
    [
        (_png(), "image/png"),
        (_jpeg(), "image/jpeg"),
        (_gif(), "image/gif"),
        (_webp_vp8x(), "image/webp"),
        (_webp_vp8(), "image/webp"),
        (_webp_vp8l(), "image/webp"),
    ],
)
async def test_all_formats_accepted(raw: bytes, mime: str) -> None:
    seen: list[httpx.Request] = []
    body = _body(messages=[{"role": "user", "content": [_image(raw, mime)]}])
    async with _client(seen) as c:
        r = await c.post(VISION_ROUTE_PATH, json=body)
    assert r.status_code == 200


def test_jpeg_garbage_between_segments_is_skipped() -> None:
    clean = _jpeg(321, 123)
    soi, rest = clean[:2], clean[2:]
    # Мусор без 0xFF между SOI и первым сегментом, затем без маркеров вообще.
    assert image_dimensions("image/jpeg", soi + b"\x00" * 5000 + rest) == (321, 123)
    assert image_dimensions("image/jpeg", soi + b"\x00" * 5000) is None


def test_dimensions_parsed_from_headers() -> None:
    assert image_dimensions("image/png", _png(640, 480)) == (640, 480)
    assert image_dimensions("image/jpeg", _jpeg(1568, 1000)) == (1568, 1000)
    assert image_dimensions("image/gif", _gif(31, 21)) == (31, 21)
    assert image_dimensions("image/webp", _webp_vp8x(300, 200)) == (300, 200)
    assert image_dimensions("image/webp", _webp_vp8(120, 80)) == (120, 80)
    assert image_dimensions("image/webp", _webp_vp8l(90, 70)) == (90, 70)


@pytest.mark.parametrize(
    ("mime", "raw"),
    [
        ("image/png", _jpeg()),  # mime не совпал с содержимым
        ("image/jpeg", _png()),
        ("image/png", b"\x89PNG\r\n\x1a\n"),  # обрезанный заголовок
        ("image/jpeg", b"\xff\xd8\xff\xda\x00\x02"),  # кадра нет
        ("image/gif", b"GIF89a"),
        ("image/webp", b"RIFF\x00\x00\x00\x00WEBPVP8 "),
        ("image/webp", b"RIFF" + b"\x00" * 40),
        ("image/png", b""),
    ],
)
def test_broken_headers_rejected(mime: str, raw: bytes) -> None:
    assert image_dimensions(mime, raw) is None


BAD_BODIES: dict[str, dict[str, Any]] = {
    "tools": _body(tools=[{"name": "x", "input_schema": {}}]),
    "tools_empty": _body(tools=[]),
    "tool_choice": _body(tool_choice={"type": "auto"}),
    "stream": _body(stream=True),
    "extra_key": _body(metadata={"user_id": "x"}),
    "two_messages": _body(messages=[
        {"role": "user", "content": [_image()]}, {"role": "user", "content": [_image()]}
    ]),
    "assistant_role": _body(messages=[{"role": "assistant", "content": [_image()]}]),
    "string_content": _body(messages=[{"role": "user", "content": PROMPT}]),
    "no_image": _body(messages=[{"role": "user", "content": [{"type": "text", "text": "a"}]}]),
    "tool_use_block": _body(messages=[{"role": "user", "content": [
        _image(), {"type": "tool_result", "tool_use_id": "t", "content": "x"}]}]),
    "document_block": _body(messages=[{"role": "user", "content": [
        _image(), {"type": "document", "source": {}}]}]),
    "url_source": _body(messages=[{"role": "user", "content": [
        {"type": "image", "source": {"type": "url", "url": "https://x.example/a.png"}}]}]),
    "file_source": _body(messages=[{"role": "user", "content": [
        {"type": "image", "source": {"type": "file", "file_id": "f"}}]}]),
    "extra_block_key": _body(messages=[{"role": "user", "content": [
        {**_image(), "cache_control": {"type": "ephemeral"}}]}]),
    "extra_source_key": _body(messages=[{"role": "user", "content": [
        _image(extra="x")]}]),
    "text_extra_key": _body(messages=[{"role": "user", "content": [
        _image(), {"type": "text", "text": "a", "cache_control": {}}]}]),
    "mime_gif_as_bmp": _body(messages=[{"role": "user", "content": [
        _image(mime="image/bmp")]}]),
    "mime_heic": _body(messages=[{"role": "user", "content": [_image(mime="image/heic")]}]),
    "mime_svg": _body(messages=[{"role": "user", "content": [_image(mime="image/svg+xml")]}]),
    "mime_mismatch": _body(messages=[{"role": "user", "content": [
        _image(_jpeg(), "image/png")]}]),
    "base64_garbage": _body(messages=[{"role": "user", "content": [
        _image(data="!!!not base64!!!")]}]),
    "base64_urlsafe": _body(messages=[{"role": "user", "content": [
        _image(data=_b64(_png()).replace("+", "-") + "-_")]}]),
    "base64_whitespace": _body(messages=[{"role": "user", "content": [
        _image(data=_b64(_png())[:20] + "\n" + _b64(_png())[20:])]}]),
    "base64_bad_padding": _body(messages=[{"role": "user", "content": [
        _image(data=_b64(_png()).rstrip("=") + "=")]}]),
    "base64_empty": _body(messages=[{"role": "user", "content": [_image(data="")]}]),
    "base64_not_str": _body(messages=[{"role": "user", "content": [_image(data=123)]}]),
    "too_big_side": _body(messages=[{"role": "user", "content": [
        _image(_png(1569, 100))]}]),
    "zero_side": _body(messages=[{"role": "user", "content": [_image(_png(0, 10))]}]),
    "system_not_text": _body(system=[{"type": "image"}]),
    "bad_max_tokens": _body(max_tokens="1024"),
}


@pytest.mark.parametrize("name", list(BAD_BODIES))
async def test_bad_request_rejected_403(name: str) -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(VISION_ROUTE_PATH, json=BAD_BODIES[name])
    assert r.status_code == 403, name
    assert r.json()["code"] == "vision_route_form"
    assert seen == []


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("tools", "tools"),
        ("tools_empty", "tools"),
        ("tool_choice", "tool_choice"),
        ("stream", "stream"),
        ("mime_heic", "image_mime"),
        ("mime_mismatch", "image_format"),
        ("base64_garbage", "image_base64"),
        ("base64_urlsafe", "image_base64"),
        ("base64_whitespace", "image_base64"),
        ("too_big_side", "image_dimensions"),
        ("url_source", "image_block"),
        ("no_image", "image_count"),
    ],
)
def test_reason_codes(name: str, reason: str) -> None:
    verdict = check_vision_request("POST", "", "", json.dumps(BAD_BODIES[name]).encode())
    assert verdict.reason == reason


def test_image_count_limit() -> None:
    limits = VisionLimits(max_images=2)
    ok = _body(messages=[{"role": "user", "content": [_image(), _image()]}])
    over = _body(messages=[{"role": "user", "content": [_image(), _image(), _image()]}])
    assert check_vision_request("POST", "", "", json.dumps(ok).encode(), limits).reason is None
    verdict = check_vision_request("POST", "", "", json.dumps(over).encode(), limits)
    assert verdict.reason == "image_count"


def test_default_ten_images_ok_eleven_rejected() -> None:
    def many(n: int) -> bytes:
        content = [_image() for _ in range(n)]
        return json.dumps(_body(messages=[{"role": "user", "content": content}])).encode()

    assert check_vision_request("POST", "", "", many(10)).reason is None
    assert check_vision_request("POST", "", "", many(11)).reason == "image_count"


def test_single_image_size_limit() -> None:
    limits = VisionLimits(max_image_b64_bytes=100)
    big = _png() + b"\x00" * 200
    body = json.dumps(_body(messages=[{"role": "user", "content": [_image(big)]}])).encode()
    assert check_vision_request("POST", "", "", body, limits).reason == "image_size"
    # граница: ровно предел проходит
    raw = _png()
    edge = VisionLimits(max_image_b64_bytes=len(_b64(raw)))
    body = json.dumps(_body(messages=[{"role": "user", "content": [_image(raw)]}])).encode()
    assert check_vision_request("POST", "", "", body, edge).reason is None


def test_side_limit_boundary() -> None:
    ok = json.dumps(_body(messages=[{"role": "user", "content": [
        _image(_png(1568, 1568))]}])).encode()
    assert check_vision_request("POST", "", "", ok).reason is None
    bad = json.dumps(_body(messages=[{"role": "user", "content": [
        _image(_png(100, 1569))]}])).encode()
    assert check_vision_request("POST", "", "", bad).reason == "image_dimensions"


def test_body_limit() -> None:
    body = json.dumps(_body()).encode()
    verdict = check_vision_request("POST", "", "", body, VisionLimits(max_body_bytes=100))
    assert verdict.reason == "body_size"


def test_text_size_limit() -> None:
    body = _body(messages=[{"role": "user", "content": [_image(), {"type": "text", "text":
                                                                    "a" * 20000}]}])
    verdict = check_vision_request("POST", "", "", json.dumps(body).encode())
    assert verdict.reason == "text_size"


async def test_pii_in_text_denied_422() -> None:
    seen: list[httpx.Request] = []
    body = _body(messages=[{"role": "user", "content": [_image(), {"type": "text",
                                                                    "text": PII_TEXT}]}])
    async with _client(seen) as c:
        r = await c.post(VISION_ROUTE_PATH, json=body)
    assert r.status_code == 422
    assert set(r.json()["pii_types"]) >= {"inn", "phone"}
    assert seen == []


async def test_pii_in_system_denied_422() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(VISION_ROUTE_PATH, json=_body(system=PII_TEXT))
    assert r.status_code == 422
    assert seen == []


async def test_system_text_allowed() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(VISION_ROUTE_PATH, json=_body(system=[{"type": "text", "text": PROMPT}]))
    assert r.status_code == 200


async def test_base64_not_scanned_as_text() -> None:
    """Цифровые серии внутри base64 не дают ложного отказа ПДн (в отличие от основного)."""
    digits_png = _png() + b"7707083893" * 5  # base64 может нести любые серии цифр
    raw_text = "ИНН 7707083893"
    body = _body(messages=[{"role": "user", "content": [
        {"type": "image", "source": {
            "type": "base64", "media_type": "image/png", "data": _b64(digits_png)}}]}])
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(VISION_ROUTE_PATH, json=body)
        assert r.status_code == 200
        # а голый текст с ИНН как отдельный блок по-прежнему отказ
        body["messages"][0]["content"].append({"type": "text", "text": raw_text})
        r = await c.post(VISION_ROUTE_PATH, json=body)
        assert r.status_code == 422


async def test_method_query_encoding_rejected() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        assert (await c.get(VISION_ROUTE_PATH)).status_code == 403
        assert (await c.put(VISION_ROUTE_PATH, json=_body())).status_code == 403
        assert (await c.post(VISION_ROUTE_PATH + "?x=1", json=_body())).status_code == 403
        r = await c.post(VISION_ROUTE_PATH, json=_body(), headers={"content-encoding": "gzip"})
        assert r.status_code == 403
    assert seen == []


async def test_non_object_and_garbage_rejected() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        for raw in (b"[]", b"not json", b"", b'"str"'):
            r = await c.post(VISION_ROUTE_PATH, content=raw)
            assert r.status_code == 403
    assert seen == []


async def test_oversize_streamed_body_rejected() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen, limits=VisionLimits(max_body_bytes=100)) as c:
        r = await c.post(VISION_ROUTE_PATH, json=_body())
    assert r.status_code == 403
    assert "body_size" in r.json()["error"]["message"]
    assert seen == []


@pytest.mark.parametrize(
    "path",
    [
        "/vision/v1/chat/completions",
        "/vision/v1/messages/extra",
        "/vision/v1/messages/",
        "/vision",
        "/vision/",
        "/VISION/v1/messages",
        "/vision//v1/messages",
        "/vision/v1/%2e/messages",
        "/%76ision/v1/messages",
        "/vision%2Fv1/messages",
        "/%252fvision/v1/messages",
    ],
)
async def test_path_bypass_forbidden_before_body(path: str) -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post(path, json=_body())
    assert r.status_code == 403
    assert seen == []


def test_namespace_helper() -> None:
    assert is_vision_namespace("/vision/v1/messages")
    assert is_vision_namespace("//VISION/x")
    assert not is_vision_namespace("/v1/messages")
    assert not is_vision_namespace("/v1/vision/x")
    assert not is_vision_namespace("/search/v1/messages")


async def test_disabled_flag_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VISION_ROUTE_ENABLED", raising=False)
    seen: list[httpx.Request] = []
    app = create_app("http://upstream", transport=_transport(seen))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        assert (await c.post(VISION_ROUTE_PATH, json=_body())).status_code == 404
        assert (await c.post("/vision/other", json=_body())).status_code == 403
    assert seen == []


async def test_env_flag_and_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VISION_ROUTE_ENABLED", "1")
    monkeypatch.setenv("VISION_MAX_IMAGES", "1")
    seen: list[httpx.Request] = []
    app = create_app("http://upstream", transport=_transport(seen))
    two = _body(messages=[{"role": "user", "content": [_image(), _image()]}])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as c:
        assert (await c.post(VISION_ROUTE_PATH, json=_body())).status_code == 200
        assert (await c.post(VISION_ROUTE_PATH, json=two)).status_code == 403


@pytest.mark.parametrize("value", ["0", "-1", "abc", "21"])
def test_bad_env_limit_fails_startup(value: str) -> None:
    with pytest.raises(ValueError):
        VisionLimits.from_env({"VISION_MAX_IMAGES": value})


def test_env_defaults() -> None:
    limits = VisionLimits.from_env({})
    assert (limits.max_images, limits.max_image_side) == (10, 1568)
    assert limits.max_image_b64_bytes == 5 * 1024 * 1024


async def test_allowed_models_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VISION_ALLOWED_MODELS", "agent-main")
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        assert (await c.post(VISION_ROUTE_PATH, json=_body())).status_code == 200
        r = await c.post(VISION_ROUTE_PATH, json=_body(model="other"))
        assert r.status_code == 403


async def test_default_model_is_agent_main(monkeypatch: pytest.MonkeyPatch) -> None:
    """Без VISION_ALLOWED_MODELS проходит только алиас агентов, другая модель - 403."""
    monkeypatch.delenv("VISION_ALLOWED_MODELS", raising=False)
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        assert (await c.post(VISION_ROUTE_PATH, json=_body())).status_code == 200
        r = await c.post(VISION_ROUTE_PATH, json=_body(model="claude-opus"))
        assert r.status_code == 403
    assert len(seen) == 1


def test_parse_vision_models_default() -> None:
    assert parse_vision_models(None) == frozenset({"agent-main"})
    assert parse_vision_models(" , ") == frozenset({"agent-main"})
    assert parse_vision_models("a, b") == frozenset({"a", "b"})


async def test_main_route_unchanged_for_pii() -> None:
    seen: list[httpx.Request] = []
    async with _client(seen) as c:
        r = await c.post("/v1/messages", json={"messages": [{"role": "user", "content": PII_TEXT}]})
    assert r.status_code == 422
    assert seen == []


async def test_logs_have_no_image_content(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    seen: list[httpx.Request] = []
    raw = _png()
    async with _client(seen) as c:
        await c.post(VISION_ROUTE_PATH, json=_body())
        await c.post(VISION_ROUTE_PATH, json=_body(tools=[]))
    assert _b64(raw) not in caplog.text
    assert "7707083893" not in caplog.text
    assert PROMPT not in caplog.text
    records = [r for r in caplog.records if getattr(r, "event", None) == "vision_images"]
    assert len(records) == 1
    (entry,) = records[0].images  # type: ignore[attr-defined]
    mime, size, dims, digest = entry.split(":")
    assert (mime, int(size), dims) == ("image/png", len(raw), "64x48")
    assert len(digest) == 12
