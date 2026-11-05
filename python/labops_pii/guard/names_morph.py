"""ФИО в guard с морфологией (необязательный режим, extras: natasha и pymorphy3).

По умолчанию guard ищет ФИО эвристикой по окончаниям (names.py), без морфологии: образ
шлюза лёгкий. Здесь тот же вопрос («есть ли ФИО») решает детектор псевдонимизатора: он
знает падежи и словари имён и реже срабатывает на обычные слова. Включается переменной
PII_GUARD_NAMES_MORPH=on (по умолчанию для всех профилей выключено) и только вместе с
режимом ФИО не off. Модель грузится лениво при первом вызове.
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING

from labops_pii.profiles import get_profile

if TYPE_CHECKING:
    from labops_pii.detector import PiiDetector

NAMES_MORPH_ENV = "PII_GUARD_NAMES_MORPH"
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_LOCK = threading.Lock()
_DETECTOR: PiiDetector | None = None


def names_morph_enabled() -> bool:
    """Включена ли морфология ФИО (окружение главнее профиля).

    Неизвестное значение трактуется как включённое: морфология только добавляет находки,
    а при сомнении безопаснее найти больше (fail closed).
    """
    raw = os.environ.get(NAMES_MORPH_ENV, "").strip().lower()
    if not raw:
        return get_profile().guard_names_morph
    return raw not in _FALSE


def has_person_morph(text: str) -> bool:
    """Есть ли в тексте ФИО по детектору с морфологией (значения наружу не отдаются)."""
    from labops_pii.detector import PiiDetector, PiiType

    global _DETECTOR
    with _LOCK:
        if _DETECTOR is None:
            _DETECTOR = PiiDetector(mask_addresses=False)
        detector = _DETECTOR
    return any(d.pii_type is PiiType.PERSON for d in detector.detect(text))
