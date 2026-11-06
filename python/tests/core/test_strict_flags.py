"""Флаги маскирования строгие: опечатка - ошибка старта, а не молчаливое выключение."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from labops_pii.config import ConfigError, load_settings

BASE = {"PSEUDONYMIZER_API_TOKEN": "t", "PSEUDONYMIZER_KEY": Fernet.generate_key().decode()}


@pytest.mark.parametrize("raw", ["onn", "enabled", "вкл"])
def test_legal_entity_typo_refuses_to_start(raw: str) -> None:
    with pytest.raises(ConfigError, match="PSEUDONYMIZER_MASK_LEGAL_ENTITY"):
        load_settings({**BASE, "PSEUDONYMIZER_MASK_LEGAL_ENTITY": raw})


@pytest.mark.parametrize(
    ("raw", "expected"), [("", True), ("on", True), ("off", False), ("0", False)]
)
def test_legal_entity_values(raw: str, expected: bool) -> None:
    settings = load_settings({**BASE, "PSEUDONYMIZER_MASK_LEGAL_ENTITY": raw})
    assert settings.mask_legal_entity_requisites is expected


def test_media_flags_strict() -> None:
    media = pytest.importorskip("labops_pii.media.mask.config")
    env = {"MEDIA_MASKER_API_TOKEN": "t"}
    with pytest.raises(media.ConfigError):
        media.load_settings({**env, "MEDIA_MASKER_MASK_LEGAL_ENTITY": "onn"})
    off = media.load_settings({**env, "MEDIA_MASKER_MASK_LEGAL_ENTITY": "off"})
    assert off.mask_legal_entity is False
    with pytest.raises(media.ConfigError):
        media.load_settings({**env, "MEDIA_MASKER_HIDE_UNREADABLE": "nope"})
