"""Ошибки старта: нет схемы ключей при sqlite, прежняя LABOPS_PII_PROFILE, флаги маршрутов."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import labops_pii.api as api
from labops_pii.__main__ import main
from labops_pii.api import create_app
from labops_pii.config import (
    ENV_API_TOKEN,
    ENV_ENABLE_CASE_LABELS,
    ENV_ENABLE_DELETE_THREADS,
    ENV_ENABLE_EXPOSE_BOOT_ID,
    ENV_ENABLE_INFLECT_SIGNATORY,
    ENV_KEY,
    ENV_KEY_SCHEME,
    ENV_STORE,
    ConfigError,
    Settings,
    load_settings,
)
from labops_pii.errors import LEGACY_PROFILE_ENV, reject_legacy_profile
from labops_pii.store import SqliteReplacementStore, resolve_key_scheme
from tests.env_sets import ENV_SETS, MANAGED_KEYS

TOKEN = "startup-token-0123456789abcdef"
LEGACY_NAMES = ("labops", "pragmatika", "webapp_v2", "nope")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Окружение процесса без переменных библиотеки: тесты задают их сами."""
    for key in (*MANAGED_KEYS, LEGACY_PROFILE_ENV, ENV_KEY, ENV_API_TOKEN):
        monkeypatch.delenv(key, raising=False)


def _base(**extra: str) -> dict[str, str]:
    return {ENV_KEY: Fernet.generate_key().decode(), ENV_API_TOKEN: TOKEN, **extra}


# --- PSEUDONYMIZER_KEY_SCHEME обязательна при sqlite --------------------------------------

@pytest.mark.parametrize("bad", ["", "  ", "v1", "v4", "V", "3"])
def test_sqlite_without_valid_scheme_refuses_to_start(bad: str) -> None:
    env = _base(**{ENV_STORE: "sqlite", ENV_KEY_SCHEME: bad})
    with pytest.raises(ConfigError, match=ENV_KEY_SCHEME):
        load_settings(env)


def test_sqlite_without_scheme_variable_refuses_to_start() -> None:
    with pytest.raises(ConfigError) as info:
        load_settings(_base(**{ENV_STORE: "sqlite"}))
    assert ENV_KEY_SCHEME in str(info.value) and "v2" in str(info.value)


@pytest.mark.parametrize("scheme", ["v2", "v3", " V3 "])
def test_sqlite_with_scheme_starts(scheme: str) -> None:
    settings = load_settings(_base(**{ENV_STORE: "sqlite", ENV_KEY_SCHEME: scheme}))
    assert settings.key_scheme == scheme.strip().lower()


def test_memory_store_does_not_need_scheme() -> None:
    settings = load_settings(_base())
    assert settings.store_backend == "memory"


def test_store_without_scheme_argument_and_env_fails(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=ENV_KEY_SCHEME):
        SqliteReplacementStore(tmp_path / "x.sqlite3", Fernet.generate_key().decode())


def test_resolve_key_scheme_values() -> None:
    assert resolve_key_scheme("v2") == "v2" and resolve_key_scheme(" v3 ") == "v3"
    for bad in (None, "", "v9"):
        with pytest.raises(ConfigError):
            resolve_key_scheme(bad)


def test_create_app_refuses_sqlite_settings_without_scheme(tmp_path: Path) -> None:
    settings = Settings(
        key=Fernet.generate_key().decode(), api_token=TOKEN, store_backend="sqlite",
        key_scheme="", db_path=tmp_path / "a.sqlite3",
    )
    with pytest.raises(ConfigError):
        create_app(settings)


def test_main_exits_nonzero_without_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in _base(**{ENV_STORE: "sqlite"}).items():
        monkeypatch.setenv(key, value)
    assert main() == 1


# --- Прежняя LABOPS_PII_PROFILE ---------------------------------------------------------

@pytest.mark.parametrize("name", LEGACY_NAMES)
def test_legacy_profile_refuses_to_start(name: str) -> None:
    with pytest.raises(ConfigError) as info:
        load_settings(_base(**{LEGACY_PROFILE_ENV: name}))
    assert LEGACY_PROFILE_ENV in str(info.value) and "MIGRATION.md" in str(info.value)


def test_legacy_profile_refused_even_with_full_env_set() -> None:
    env = _base(**ENV_SETS["labops"], **{LEGACY_PROFILE_ENV: "labops"})
    with pytest.raises(ConfigError):
        load_settings(env)


def test_empty_legacy_profile_is_ignored() -> None:
    reject_legacy_profile({LEGACY_PROFILE_ENV: "  "})
    assert load_settings(_base(**{LEGACY_PROFILE_ENV: ""})).store_backend == "memory"


def test_service_main_exits_nonzero_with_legacy_profile(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for key, value in _base().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(LEGACY_PROFILE_ENV, "labops")
    with caplog.at_level(logging.ERROR):
        assert main() == 1


def test_create_app_refuses_legacy_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LEGACY_PROFILE_ENV, "pragmatika")
    settings = Settings(key=Fernet.generate_key().decode(), api_token=TOKEN)
    with pytest.raises(ConfigError, match="MIGRATION"):
        create_app(settings)


def test_guard_apps_refuse_legacy_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    from labops_pii.guard.edge import app as edge_app
    from labops_pii.guard.litellm import app as litellm_app

    monkeypatch.setenv(LEGACY_PROFILE_ENV, "webapp_v2")
    with pytest.raises(ConfigError, match="MIGRATION"):
        litellm_app.create_app(upstream_url="http://upstream.test")
    with pytest.raises(ConfigError, match="MIGRATION"):
        edge_app.create_app({})


def test_media_settings_refuse_legacy_profile() -> None:
    from labops_pii.media.mask.config import ConfigError as MediaConfigError
    from labops_pii.media.mask.config import load_settings as load_media_settings

    with pytest.raises(MediaConfigError, match="MIGRATION"):
        load_media_settings({"MEDIA_MASKER_API_TOKEN": TOKEN, LEGACY_PROFILE_ENV: "labops"})


# --- Флаги маршрутов: по умолчанию выключены ---------------------------------------------

FLAGS = {
    "inflect": (ENV_ENABLE_INFLECT_SIGNATORY, "enable_inflect_signatory"),
    "delete": (ENV_ENABLE_DELETE_THREADS, "enable_delete_threads"),
    "boot_id": (ENV_ENABLE_EXPOSE_BOOT_ID, "enable_expose_boot_id"),
    "case_labels": (ENV_ENABLE_CASE_LABELS, "enable_case_labels"),
}


def test_all_route_flags_off_by_default() -> None:
    settings = load_settings(_base())
    assert [getattr(settings, field) for _, field in FLAGS.values()] == [False] * len(FLAGS)
    default = Settings(key="", api_token=TOKEN)
    assert [getattr(default, field) for _, field in FLAGS.values()] == [False] * len(FLAGS)


@pytest.mark.parametrize("flag", sorted(FLAGS))
def test_each_flag_turns_only_itself_on(flag: str) -> None:
    env_name, field = FLAGS[flag]
    settings = load_settings(_base(**{env_name: "on"}))
    assert {f: getattr(settings, f) for _, f in FLAGS.values()} == {
        f: f == field for _, f in FLAGS.values()
    }


@pytest.mark.parametrize("flag", sorted(FLAGS))
def test_flag_typo_is_an_error_not_a_silent_default(flag: str) -> None:
    env_name, _ = FLAGS[flag]
    with pytest.raises(ConfigError, match=env_name):
        load_settings(_base(**{env_name: "enabled"}))


class _StubDetector:
    """Детектор-заглушка: форма API не зависит от модели."""

    def detect(self, _text: str) -> list[object]:
        return []


def _client(monkeypatch: pytest.MonkeyPatch, **flags: bool) -> TestClient:
    monkeypatch.setattr(api, "PiiDetector", lambda *_a, **_k: _StubDetector())
    settings = Settings(key="", api_token=TOKEN, db_path=Path(":memory:"), **flags)
    return TestClient(create_app(settings), headers={"Authorization": f"Bearer {TOKEN}"})


def test_routes_absent_when_flags_off(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    assert client.delete("/threads/x").status_code in (404, 405)
    assert client.post("/inflect_signatory", json={"position": "Директор",
                                                   "full_name": "Иванов Иван Иванович"}
                       ).status_code == 404
    assert "boot_id" not in client.get("/health").json()


def test_routes_present_when_flags_on(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, enable_delete_threads=True, enable_inflect_signatory=True,
                     enable_expose_boot_id=True)
    assert client.delete("/threads/x").status_code not in (404, 405)
    response = client.post("/inflect_signatory", json={"position": "Директор",
                                                       "full_name": "Иванов Иван Иванович"})
    assert response.status_code == 200
    assert "boot_id" in client.get("/health").json()


def test_rekey_requires_scheme_and_rejects_legacy_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from labops_pii import rekey

    db = tmp_path / "r.sqlite3"
    db.write_bytes(b"")
    monkeypatch.setenv(ENV_KEY, Fernet.generate_key().decode())
    assert rekey.main(["--db", str(db), "--dry-run"]) == rekey.EXIT_USAGE  # нет схемы
    monkeypatch.setenv(ENV_KEY_SCHEME, "v3")
    monkeypatch.setenv(LEGACY_PROFILE_ENV, "pragmatika")
    assert rekey.main(["--db", str(db), "--dry-run"]) == rekey.EXIT_USAGE
