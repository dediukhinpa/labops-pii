"""Счётчики срабатываний guard по типам ПДн (в памяти процесса, Prometheus-текст).

Метка `type` - только из закрытого списка METRIC_TYPES; любое другое значение становится
"other" (произвольная строка в метку не пускается: кардинальность и утечки исключены).
Значения ПДн, пути, request_id в метрики не попадают. Зависимостей нет.

  pii_guard_findings_total{type}  - запросов, где тип найден (отказ или только наблюдение);
  pii_guard_denied_total{type}    - запросов, отклонённых из-за типа.

Один запрос с несколькими типами увеличивает счётчик каждого типа на 1.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

FINDINGS_METRIC = "pii_guard_findings_total"
DENIED_METRIC = "pii_guard_denied_total"
OTHER_TYPE = "other"
# Закрытый список меток. «address» - детектор адресов (PII_GUARD_ADDRESS_MODE, этап Г).
METRIC_TYPES: tuple[str, ...] = (
    "phone", "email", "inn", "snils", "card", "account", "name", "address", OTHER_TYPE,
)
_KNOWN = frozenset(METRIC_TYPES)

_HELP = {
    FINDINGS_METRIC: "Requests where pii-guard found a personal data type (blocked or observed).",
    DENIED_METRIC: "Requests denied by pii-guard because of a personal data type.",
}


def metric_label(pii_type: str) -> str:
    """Значение метки type: из закрытого списка, иначе "other"."""
    return pii_type if pii_type in _KNOWN else OTHER_TYPE


class GuardMetrics:
    """Потокобезопасные счётчики по закрытому списку типов."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, dict[str, int]] = {
            FINDINGS_METRIC: dict.fromkeys(METRIC_TYPES, 0),
            DENIED_METRIC: dict.fromkeys(METRIC_TYPES, 0),
        }

    def _add(self, metric: str, types: Iterable[str]) -> None:
        labels = {metric_label(t) for t in types}  # один запрос - +1 на тип
        with self._lock:
            for label in labels:
                self._values[metric][label] += 1

    def record_findings(self, types: Iterable[str]) -> None:
        """Тип найден в запросе (отказ или наблюдение)."""
        self._add(FINDINGS_METRIC, types)

    def record_denied(self, types: Iterable[str]) -> None:
        """Запрос отклонён из-за типа."""
        self._add(DENIED_METRIC, types)

    def snapshot(self, metric: str) -> dict[str, int]:
        """Копия значений счётчика по типам."""
        with self._lock:
            return dict(self._values[metric])

    def reset(self) -> None:
        """Обнуляет счётчики (для тестов)."""
        with self._lock:
            for series in self._values.values():
                for label in series:
                    series[label] = 0

    def render(self) -> str:
        """Текст в формате экспозиции Prometheus; серии есть для всех типов (с нуля)."""
        lines: list[str] = []
        for metric in (FINDINGS_METRIC, DENIED_METRIC):
            lines.append(f"# HELP {metric} {_HELP[metric]}")
            lines.append(f"# TYPE {metric} counter")
            for label, value in self.snapshot(metric).items():
                lines.append(f'{metric}{{type="{label}"}} {value}')
        return "\n".join(lines) + "\n"


METRICS = GuardMetrics()
