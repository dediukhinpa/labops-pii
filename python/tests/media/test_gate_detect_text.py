"""Тесты /images/detect-text: подставной бинарь tesseract, лимиты, очередь, fail closed."""

from __future__ import annotations

import asyncio
import io
import shutil
import stat
import sys
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from labops_pii.media.gate.api import GateSettings as Settings
from labops_pii.media.gate.api import create_app
from labops_pii.media.gate.normalize import ImageLimits
from labops_pii.media.gate.detect import (
    OcrBusyError,
    OcrGate,
    OcrSettings,
    count_significant_words,
    detect_text,
)

URL = "/images/detect-text"
TSV_HEADER = "\t".join(
    "level page_num block_num par_num line_num word_num left top width height conf text".split()
)
SLEEP_SECONDS = 3
FAST_TIMEOUT_MS = 500


def tsv_word(text: str, conf: float = 90.0, level: int = 5) -> str:
    return f"{level}\t1\t1\t1\t1\t1\t0\t0\t10\t10\t{conf}\t{text}"


def tsv(*words: str) -> str:
    return "\n".join([TSV_HEADER, *words]) + "\n"


def make_fake(tmp_path: Path, body: str, name: str = "fake_tesseract") -> str:
    """Исполняемый скрипт вместо tesseract: читает stdin и выполняет `body`."""
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\nimport sys, time\nsys.stdin.buffer.read()\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def print_tsv(content: str) -> str:
    return f"sys.stdout.write({content!r})"


def png_bytes(size: tuple[int, int] = (200, 100), fmt: str = "PNG") -> bytes:
    image = Image.new("RGB", size, "white")
    ImageDraw.Draw(image).text((10, 10), "Hello world", fill="black")
    buffer = io.BytesIO()
    image.save(buffer, fmt)
    return buffer.getvalue()


def make_client(tmp_path: Path, **ocr: object) -> TestClient:
    settings = Settings(ocr=replace(OcrSettings(), **ocr))  # type: ignore[arg-type]
    return TestClient(create_app(settings))


def post(client: TestClient, data: bytes, name: str = "a.png") -> httpx.Response:
    return client.post(URL, files={"file": (name, data, "application/octet-stream")})


def test_text_detected(tmp_path: Path) -> None:
    words = tsv(*(tsv_word(w) for w in ("Счёт", "на", "оплату", "No5")))
    client = make_client(tmp_path, binary=make_fake(tmp_path, print_tsv(words)))
    response = post(client, png_bytes())
    assert response.status_code == 200
    assert response.json() == {"result": "text"}


def test_no_text_when_few_or_weak_words(tmp_path: Path) -> None:
    # два нормальных слова, слабое слово, односимвольный шум и не-словесный уровень
    words = tsv(
        tsv_word("Hello"), tsv_word("мир"), tsv_word("blur", conf=10.0),
        tsv_word("|"), tsv_word("-,"), tsv_word("lineword", level=4), tsv_word("x", conf=-1),
    )
    client = make_client(tmp_path, binary=make_fake(tmp_path, print_tsv(words)))
    assert post(client, png_bytes()).json() == {"result": "no_text"}


def test_threshold_is_configurable(tmp_path: Path) -> None:
    words = tsv(tsv_word("Hello"), tsv_word("мир"))
    client = make_client(
        tmp_path, binary=make_fake(tmp_path, print_tsv(words)), min_words=2
    )
    assert post(client, png_bytes()).json() == {"result": "text"}


def test_empty_output_is_no_text(tmp_path: Path) -> None:
    client = make_client(tmp_path, binary=make_fake(tmp_path, print_tsv(TSV_HEADER + "\n")))
    assert post(client, png_bytes()).json() == {"result": "no_text"}


@pytest.mark.parametrize("fmt", ["JPEG", "PNG", "WEBP"])
def test_allowed_formats(tmp_path: Path, fmt: str) -> None:
    words = tsv(*(tsv_word(w) for w in ("один", "два", "три")))
    client = make_client(tmp_path, binary=make_fake(tmp_path, print_tsv(words)))
    assert post(client, png_bytes(fmt=fmt)).json() == {"result": "text"}


def test_missing_binary_is_not_recognized(tmp_path: Path) -> None:
    client = make_client(tmp_path, binary=str(tmp_path / "нет-такого-бинаря"))
    response = post(client, png_bytes())
    assert response.status_code == 200
    assert response.json() == {"result": "not_recognized"}


def test_engine_failure_is_not_recognized(tmp_path: Path) -> None:
    client = make_client(tmp_path, binary=make_fake(tmp_path, "sys.exit(3)"))
    assert post(client, png_bytes()).json() == {"result": "not_recognized"}


def test_timeout_kills_process(tmp_path: Path) -> None:
    marker = tmp_path / "finished"
    body = f"time.sleep({SLEEP_SECONDS})\nopen({str(marker)!r}, 'w').close()"
    client = make_client(
        tmp_path, binary=make_fake(tmp_path, body), timeout_ms=FAST_TIMEOUT_MS
    )
    assert post(client, png_bytes()).json() == {"result": "not_recognized"}
    # процесс убит: до записи маркера он не дошёл
    time.sleep(SLEEP_SECONDS)
    assert not marker.exists()


def test_undecodable_body_is_not_recognized(tmp_path: Path) -> None:
    called = tmp_path / "called"
    binary = make_fake(tmp_path, f"open({str(called)!r}, 'w').close()")
    client = make_client(tmp_path, binary=binary)
    truncated = png_bytes((400, 400))[:200]  # заголовок цел, данные обрезаны
    assert post(client, truncated).json() == {"result": "not_recognized"}
    assert not called.exists()  # движок на битой картинке не запускался


def test_too_many_pixels_is_not_recognized(tmp_path: Path) -> None:
    client = make_client(
        tmp_path, binary=make_fake(tmp_path, print_tsv(tsv(tsv_word("a1")))), max_pixels=100
    )
    assert post(client, png_bytes((200, 100))).json() == {"result": "not_recognized"}


def test_unsupported_format_415(tmp_path: Path) -> None:
    client = make_client(tmp_path, binary=make_fake(tmp_path, "pass"))
    assert post(client, png_bytes(fmt="BMP")).status_code == 415
    assert post(client, b"not an image at all").status_code == 415


def test_file_too_large_413(tmp_path: Path) -> None:
    settings = Settings(
        image_limits=ImageLimits(max_input_bytes=100),
        ocr=replace(OcrSettings(), binary=make_fake(tmp_path, "pass")),
    )
    client = TestClient(create_app(settings))
    assert post(client, png_bytes()).status_code == 413


def test_no_content_in_logs(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    secret = "СекретноеСлово"
    words = tsv(*(tsv_word(w) for w in (secret, "два", "три")))
    client = make_client(tmp_path, binary=make_fake(tmp_path, print_tsv(words)))
    with caplog.at_level("DEBUG"):
        response = post(client, png_bytes(), name="секретный-файл.png")
    assert secret not in response.text
    assert secret not in caplog.text
    assert "секретный-файл" not in caplog.text


def test_busy_returns_503_with_retry_after(tmp_path: Path) -> None:
    body = f"time.sleep(1)\n{print_tsv(tsv(tsv_word('a1')))}"
    settings = Settings(
        ocr=replace(OcrSettings(), binary=make_fake(tmp_path, body), queue_max=0)
    )
    app = create_app(settings)

    async def scenario() -> list[httpx.Response]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            files = {"file": ("a.png", png_bytes(), "image/png")}
            first = asyncio.create_task(client.post(URL, files=files))
            await asyncio.sleep(0.4)  # первый уже держит слот
            second = await client.post(URL, files=files)
            return [await first, second]

    first, second = asyncio.run(scenario())
    assert first.status_code == 200
    assert second.status_code == 503
    assert second.headers["Retry-After"]


def test_gate_waits_in_bounded_queue() -> None:
    gate = OcrGate(replace(OcrSettings(), queue_max=1, queue_wait_ms=2000))
    order: list[str] = []

    async def worker(name: str, hold: float) -> None:
        async with gate.slot():
            order.append(name)
            await asyncio.sleep(hold)

    async def scenario() -> None:
        a = asyncio.create_task(worker("a", 0.3))
        await asyncio.sleep(0.05)
        b = asyncio.create_task(worker("b", 0.0))  # ждёт в очереди
        await asyncio.sleep(0.05)
        with pytest.raises(OcrBusyError):  # очередь на одного уже занята
            async with gate.slot():
                pass
        await asyncio.gather(a, b)

    asyncio.run(scenario())
    assert order == ["a", "b"]


def test_gate_wait_timeout() -> None:
    gate = OcrGate(replace(OcrSettings(), queue_max=1, queue_wait_ms=100))

    async def scenario() -> None:
        async with gate.slot():
            with pytest.raises(OcrBusyError):
                async with gate.slot():
                    pass

    asyncio.run(scenario())


def test_count_words_ignores_short_tokens() -> None:
    settings = OcrSettings()
    text = tsv(tsv_word("ab"), tsv_word("a"), tsv_word("?!"), tsv_word("x1", conf=39.9))
    assert count_significant_words(text, settings) == 1


def test_child_env_has_single_thread_and_no_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOME_SECRET_TOKEN", "x")
    out = tmp_path / "env.txt"
    body = f"import os\nopen({str(out)!r}, 'w').write(repr(dict(os.environ)))"
    settings = replace(OcrSettings(), binary=make_fake(tmp_path, body))
    detect_text(png_bytes(), ImageLimits(), settings)
    seen = out.read_text()
    assert "'OMP_THREAD_LIMIT': '1'" in seen
    assert "SOME_SECRET_TOKEN" not in seen


@pytest.mark.skipif(shutil.which("tesseract") is None, reason="tesseract не установлен")
def test_real_tesseract_smoke() -> None:
    from PIL import ImageFont

    image = Image.new("RGB", (900, 200), "white")
    font = ImageFont.load_default(size=60)
    ImageDraw.Draw(image).text((20, 50), "INVOICE TOTAL 1500", fill="black", font=font)
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    blank = io.BytesIO()
    Image.new("RGB", (900, 200), "white").save(blank, "PNG")
    settings = OcrSettings()
    assert detect_text(buffer.getvalue(), ImageLimits(), settings) == "text"
    assert detect_text(blank.getvalue(), ImageLimits(), settings) == "no_text"
