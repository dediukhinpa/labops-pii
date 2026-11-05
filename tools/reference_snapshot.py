"""Эталонные снимки ответов: исходная копия или библиотека на общем корпусе.

Один и тот же сценарий запускается на исходном коде (`--impl original --src <каталог>`, пакеты
`pseudonymizer` / `pii_guard` из ref проекта) и на библиотеке (`--impl library --profile P`).
Снимки сравнивает tests/test_reference_snapshots.py. Значения секретов в снимок не попадают:
ключ Fernet и токен API здесь тестовые и одноразовые.

Примеры:
  reference_snapshot.py --kind pseudonymizer --impl original --src /tmp/lab/pseudonymizer \
      --with-case-labels --out ref_labops.json
  reference_snapshot.py --kind pseudonymizer --impl library --profile labops --out lib.json
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "python" / "tests" / "fixtures" / "common_corpus.json"
API_TOKEN = "snapshot-token-0123456789"
AUTH = {"Authorization": f"Bearer {API_TOKEN}"}
# Подписанты для маршрута /inflect_signatory (только профиль pragmatika)
SIGNATORIES = [
    ("Директор", "Иванов Иван Иванович"),
    ("Генеральный директор", "Петрова Мария Сергеевна"),
    ("Главный бухгалтер", "Сидоров Пётр Алексеевич"),
    ("Заместитель директора по закупкам", "Кузнецова Анна Викторовна"),
    ("ИП", "Смирнов Алексей Петрович"),
]
# Режимы guard, на которых снимается детектор (имя -> переменные окружения)
GUARD_MODES = {
    "default": {},
    "enforce": {"PII_GUARD_NAMES_MODE": "enforce", "PII_GUARD_ADDRESS_MODE": "enforce"},
}
GUARD_EDGE_MODES = {"default": {}}
# Расширенный набор режимов для снимков бывших профилей (--all-modes)
GUARD_ALL_MODES = {
    **GUARD_MODES,
    "log_only": {"PII_GUARD_NAMES_MODE": "log_only", "PII_GUARD_ADDRESS_MODE": "log_only"},
}
UPSTREAM_STUB = "http://upstream.test"
GUARD_FORWARDED = "forwarded"

# (вид, реализация) -> имена модулей
MODULES = {
    ("pseudonymizer", "original"): {"pkg": "pseudonymizer"},
    ("pseudonymizer", "library"): {"pkg": "labops_pii"},
    ("guard-litellm", "original"): {"detector": "pii_guard.detector", "app": "pii_guard.app"},
    ("guard-litellm", "library"): {
        "detector": "labops_pii.guard.detector", "app": "labops_pii.guard.litellm.app",
    },
    ("guard-edge", "original"): {
        "detector": "pii_guard.detector", "app": "pii_guard.app", "config": "pii_guard.config",
    },
    ("guard-edge", "library"): {
        "detector": "labops_pii.guard.detector", "app": "labops_pii.guard.edge.app",
        "config": "labops_pii.guard.edge.config",
    },
}


def load_corpus() -> list[str]:
    """Общий корпус текстов."""
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def snapshot_pseudonymizer(
    pkg: str, with_case_labels: bool, with_signatory: bool
) -> dict[str, Any]:
    """Снимок сервиса псевдонимизации: одиночные вызовы, пачка, восстановление, проверка."""
    from cryptography.fernet import Fernet
    from fastapi.testclient import TestClient

    api = importlib.import_module(f"{pkg}.api")
    config = importlib.import_module(f"{pkg}.config")
    settings = config.Settings(
        key=Fernet.generate_key().decode(), db_path=":memory:", api_token=API_TOKEN
    )
    client = TestClient(api.create_app(settings), headers=AUTH)
    texts = load_corpus()
    out: dict[str, Any] = {"texts": len(texts)}
    single = [
        client.post("/pseudonymize", json={"thread_id": f"t{i}", "text": text}).json()
        for i, text in enumerate(texts)
    ]
    out["single"] = single
    out["batch"] = client.post(
        "/pseudonymize_batch", json={"thread_id": "batch", "texts": texts}
    ).json()
    out["restore"] = [
        client.post("/restore", json={"thread_id": f"t{i}", "text": item["text"]}).json()
        for i, item in enumerate(single)
    ]
    out["check"] = [client.post("/check", json={"text": text}).json() for text in texts]
    if with_case_labels:
        out["case_labels"] = [
            client.post(
                "/pseudonymize", json={"thread_id": f"c{i}", "text": text, "case_labels": True}
            ).json()
            for i, text in enumerate(texts)
        ]
    if with_signatory:
        out["signatory"] = [
            client.post("/inflect_signatory", json={"position": p, "full_name": n}).json()
            for p, n in SIGNATORIES
        ]
    health = client.get("/health").json()
    out["health_keys"] = sorted(health)
    out["health_status"] = health.get("status")
    out["unknown_route_status"] = client.delete("/threads/x").status_code
    return out


async def _stream(data: bytes) -> AsyncIterator[bytes]:
    """Тело подставного ответа апстрима как асинхронный поток."""
    yield data


def _body(text: str) -> dict[str, Any]:
    """Тело запроса к модели с текстом в сообщении."""
    return {"model": "m", "messages": [{"role": "user", "content": text}]}


async def _guard_http(app: Any, path: str, texts: list[str]) -> list[list[Any]]:
    """Статус и тип ошибки guard на каждом тексте (апстрим подставной)."""
    import httpx

    out: list[list[Any]] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as client:
        for text in texts:
            response = await client.post(path, json=_body(text))
            error: Any = None
            if response.status_code != 200:
                try:
                    error = response.json().get("error", {}).get("type")
                except ValueError:
                    error = "non_json"
            out.append([response.status_code, error])
    return out


def snapshot_guard(kind: str, impl: str, modes: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Снимок guard: типы находок детектора и ответы прокси по режимам."""
    import httpx

    names = MODULES[(kind, impl)]
    texts = load_corpus()
    out: dict[str, Any] = {"texts": len(texts), "modes": {}}
    for mode_name, env in modes.items():
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            detector = importlib.import_module(names["detector"])
            app_module = importlib.import_module(names["app"])
            found = [sorted(detector.find_pii_types(t)) for t in texts]
            bodies = [
                sorted(detector.scan_body(json.dumps(_body(t)).encode())) for t in texts
            ]

            def handler(_: httpx.Request) -> httpx.Response:
                # Тело как поток: так отвечает настоящий транспорт, прокси читает его потоком
                return httpx.Response(200, content=_stream(b'{"ok": true}'))

            transport = httpx.MockTransport(handler)
            if kind == "guard-litellm":
                app = app_module.create_app(upstream_url=UPSTREAM_STUB, transport=transport)
                path = "/v1/messages"
            else:
                config = importlib.import_module(names["config"])
                upstreams = {
                    "anthropic": config.Upstream(name="anthropic", base_url=UPSTREAM_STUB)
                }
                app = app_module.create_app(upstreams, transport=transport)
                path = "/u/anthropic/v1/messages"
            http = asyncio.run(_guard_http(app, path, texts))
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        out["modes"][mode_name] = {"types": found, "bodies": bodies, "http": http}
    return out


def snapshot_config() -> dict[str, Any]:
    """Снимок эффективных настроек бывшего профиля (значения полей и производные от них)."""
    from dataclasses import asdict

    from cryptography.fernet import Fernet

    from labops_pii import allowlist, config
    from labops_pii.guard import address, names
    from labops_pii.profiles import get_profile

    profile = asdict(get_profile())
    settings = config.Settings(key=Fernet.generate_key().decode(), api_token=API_TOKEN)
    effective = asdict(settings)
    for secret in ("key", "api_token"):
        effective.pop(secret)
    effective["db_path"] = str(effective["db_path"])
    return {
        "profile": profile,
        "settings": effective,
        "allowed_stems": list(allowlist.allowed_stems()),
        "guard_names_mode": names.default_names_mode().value,
        "guard_address_mode": address.default_address_mode().value,
    }


def main() -> None:
    """Точка входа."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kind", choices=("pseudonymizer", "guard-litellm", "guard-edge", "config"),
                        required=True)
    parser.add_argument("--impl", choices=("original", "library"), required=True)
    parser.add_argument("--src", type=Path, help="каталог исходной копии (для original)")
    parser.add_argument("--profile", help="профиль библиотеки")
    parser.add_argument("--with-case-labels", action="store_true")
    parser.add_argument("--with-signatory", action="store_true")
    parser.add_argument("--all-modes", action="store_true",
                        help="guard: режимы default, enforce и log_only")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.impl == "original":
        if args.src is None:
            parser.error("для original нужен --src")
        sys.path.insert(0, str(args.src))
    else:
        sys.path.insert(0, str(ROOT / "python"))
        if args.profile:
            os.environ["LABOPS_PII_PROFILE"] = args.profile
    if args.kind == "config":
        result = snapshot_config()
    elif args.kind == "pseudonymizer":
        pkg = MODULES[(args.kind, args.impl)]["pkg"]
        result = snapshot_pseudonymizer(
            pkg, args.with_case_labels, args.with_signatory
        )
    else:
        modes = GUARD_MODES if args.kind == "guard-litellm" else GUARD_EDGE_MODES
        if args.all_modes:
            modes = GUARD_ALL_MODES
        result = snapshot_guard(args.kind, args.impl, modes)
    args.out.write_text(
        json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"снимок: {args.out}")


if __name__ == "__main__":
    main()
