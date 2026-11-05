"""HTTP API: токен, пределы, PDF с текстовым слоем и скан, коды отказов."""

from __future__ import annotations

import base64
import io
import json

import pypdfium2 as pdfium
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from tests.media.conftest import (
    PII_FRAGMENTS, PII_LINES, SAFE_LINES, b64, make_text_image, to_bytes,
)

TEXT_PDF_BODY = (
    "Dear customer, please contact Peter Ivanov by phone +7 912 345-67-89 about order 1234."
)


def text_pdf() -> bytes:
    """Минимальный PDF с одной страницей и настоящим текстовым слоем (Helvetica, латиница)."""
    stream = f"BT /F1 12 Tf 40 700 Td ({TEXT_PDF_BODY}) Tj ET".encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1, xref)
    return bytes(out)


def scan_pdf(pages: int = 1) -> bytes:
    """PDF из картинок без текстового слоя (скан) с ПДн на каждой странице."""
    images = [make_text_image((SAFE_LINES[0], *PII_LINES)) for _ in range(pages)]
    buf = io.BytesIO()
    images[0].save(buf, format="PDF", save_all=True, append_images=images[1:], resolution=100.0)
    return buf.getvalue()


def post(
    client: TestClient, path: str, auth: dict[str, str], media_type: str, raw: bytes
):  # noqa: ANN201
    return client.post(path, headers=auth, json={"media_type": media_type, "data": b64(raw)})


def test_health_without_token(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/mask_image", "/extract_document"])
def test_requires_bearer(client: TestClient, path: str) -> None:
    body = {"media_type": "image/png", "data": ""}
    assert client.post(path, json=body).status_code == 401
    assert client.post(path, json=body, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_mask_image_endpoint(client: TestClient, auth: dict[str, str]) -> None:
    raw = to_bytes(make_text_image(PII_LINES))
    resp = post(client, "/mask_image", auth, "image/png", raw)
    assert resp.status_code == 200
    body = resp.json()
    assert body["media_type"] == "image/png"
    assert body["stats"]["masked_boxes"] >= 3
    assert base64.b64decode(body["data"]) != raw
    # Значения в ответе только в виде картинки: счётчики числовые
    assert set(body["stats"]) == {
        "words", "masked_boxes", "faces", "low_conf_boxes", "codes", "unreadable_boxes",
    }


def test_gif_becomes_png(client: TestClient, auth: dict[str, str]) -> None:
    raw = to_bytes(make_text_image(SAFE_LINES), "GIF")
    body = post(client, "/mask_image", auth, "image/gif", raw).json()
    assert body["media_type"] == "image/png"


@pytest.mark.parametrize(
    ("media_type", "payload", "status"),
    [
        ("image/png", b"garbage", 422),
        ("image/png", b"", 422),
        ("text/plain", b"x", 422),
    ],
)
def test_bad_image_requests(
    client: TestClient, auth: dict[str, str], media_type: str, payload: bytes, status: int
) -> None:
    assert post(client, "/mask_image", auth, media_type, payload).status_code == status


def test_bad_base64(client: TestClient, auth: dict[str, str]) -> None:
    resp = client.post(
        "/mask_image", headers=auth, json={"media_type": "image/png", "data": "!!not-base64!!"}
    )
    assert resp.status_code == 422


def test_body_limit(client: TestClient, auth: dict[str, str], monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr("labops_pii.media.mask.api.MAX_BODY_BYTES", 10)
    resp = client.post(
        "/mask_image", headers=auth, json={"media_type": "image/png", "data": "A" * 100}
    )
    assert resp.status_code == 413


def test_pdf_with_text_layer_returns_text(client: TestClient, auth: dict[str, str]) -> None:
    resp = post(client, "/extract_document", auth, "application/pdf", text_pdf())
    assert resp.status_code == 200
    body = resp.json()
    assert body["kind"] == "text"
    assert len(body["pages"]) == 1
    assert "Peter Ivanov" in body["pages"][0]["text"]
    assert body["pages"][0]["image"] is None


def test_scanned_pdf_returns_masked_images(
    client: TestClient, auth: dict[str, str], ocr  # noqa: ANN001
) -> None:
    body = post(client, "/extract_document", auth, "application/pdf", scan_pdf(2)).json()
    assert body["kind"] == "images"
    assert len(body["pages"]) == 2
    for page in body["pages"]:
        assert page["text"] is None
        img = Image.open(io.BytesIO(base64.b64decode(page["image"]["data"])))
        text = " ".join(w.text for w in ocr.recognize(img))
        for fragment in PII_FRAGMENTS:
            assert fragment not in text
        assert "Заявление" in text
    assert body["stats"]["masked_boxes"] >= 6


def test_mixed_pdf(client: TestClient, auth: dict[str, str]) -> None:
    merged = pdfium.PdfDocument.new()
    merged.import_pages(pdfium.PdfDocument(text_pdf()))
    merged.import_pages(pdfium.PdfDocument(scan_pdf(1)))
    buf = io.BytesIO()
    merged.save(buf)
    body = post(client, "/extract_document", auth, "application/pdf", buf.getvalue()).json()
    assert body["kind"] == "mixed"
    assert [p["text"] is not None for p in body["pages"]] == [True, False]


def test_pdf_page_limit(client: TestClient, auth: dict[str, str]) -> None:
    resp = post(client, "/extract_document", auth, "application/pdf", scan_pdf(5))
    assert resp.status_code == 413
    assert resp.json() == {"error": "pdf_too_many_pages"}


@pytest.mark.parametrize("raw", [b"%PDF-1.4 broken", b"hello"])
def test_broken_pdf(client: TestClient, auth: dict[str, str], raw: bytes) -> None:
    assert post(client, "/extract_document", auth, "application/pdf", raw).status_code == 422


def test_document_rejects_other_media_types(client: TestClient, auth: dict[str, str]) -> None:
    resp = post(client, "/extract_document", auth, "application/msword", b"x")
    assert resp.status_code == 422


def test_log_has_no_content(
    client: TestClient, auth: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    from labops_pii.media.mask.jsonlog import configure_logging

    configure_logging()
    post(client, "/mask_image", auth, "image/png", to_bytes(make_text_image(PII_LINES)))
    err = capsys.readouterr().err
    assert "Иванов" not in err and "912" not in err
    events = [json.loads(line) for line in err.splitlines() if line.startswith("{")]
    assert any(e.get("event") == "media_masked" for e in events)
