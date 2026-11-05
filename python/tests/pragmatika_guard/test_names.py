"""Эвристика ФИО (pii_guard/names.py): положительные, отрицательные примеры, пределы."""

from __future__ import annotations

import time

import pytest

from labops_pii.guard.names import (
    NamesMode,
    has_person_name,
    names_mode,
    parse_names_mode,
)
from labops_pii.pii_patterns import normalize_text


def _found(text: str) -> bool:
    return has_person_name(normalize_text(text))


POSITIVE = [
    # полное ФИО и падежи
    "Иванов Иван Иванович",
    "Иванова Мария Ивановна",
    "СИДОРОВ ПЕТР ИВАНОВИЧ",
    "Позвоните Ивану Петровичу",
    "Передайте Ольге Николаевне Смирновой",
    "Скажи Марии Сергеевне, что товар пришёл",
    "Мария Никитична",
    "Мария Ильинична",
    "Владимир Ильич",
    "Договор подписал Кузнецов Алексей Петрович",
    "иван иванович",
    # фамилия + имя в обе стороны, суффиксы фамилий
    "Петров Сергей",
    "Анна Петрова",
    "Толстая Любовь Сергеевна",
    "Достоевского Фёдора Михайловича",
    "Шевчук Мария",
    "Ткаченко Игорь",
    "Смирнова-Петрова Анна Игоревна",
    # инициалы
    "Иванов И.И.",
    "Иванов И. И.",
    "И.И. Иванов",
    "И. И. Иванов",
    "Иванов И.",
    "Цой В.Р.",
    "Заказ у Петрова О.И. оформлен",
    "Сидоров А.В., тел. снизу",
    # ИП - физлицо, это ПДн
    "ИП Иванов",
    "ИП Иванов И.И.",
    "Поставщик ИП Петров Пётр",
    "Индивидуальный предприниматель Петров",
    # должность не прячет ФИО
    "Генеральный директор Дудорова Марина Евгеньевна",
    "Директор: Иванов Иван Иванович",
    # ФИО внутри JSON-строки и длинного текста
    '{"owner": "Сидоров А.В."}',
    "Нужен цемент М500, 40 тонн. Контакт: Иван Иванов.",
]

NEGATIVE = [
    # одно имя, одна фамилия, одно слово
    "Иван",
    "Иванов",
    "Мария",
    # юрформы и организации
    "ООО Ромашка",
    "АО «Металлторг»",
    "ПАО Сбербанк",
    "ИП ИНН 500100732259",
    # должности
    "генеральный директор",
    "Менеджер по закупкам",
    "Главный бухгалтер",
    "Исполнительный директор компании",
    # улицы, площади, учреждения
    "ул. Александра Невского, д. 5",
    "улица Ленина 5",
    "проспект Ленина",
    "Москва, Тверская улица",
    "школа имени Ивана Петрова",
    "площадь Гагарина",
    # товары, бренды, нарицательные слова
    "Лада Веста",
    "Магазин Камин",
    "Sony Bravia 55",
    "Цемент М500 ГОСТ 10178-85",
    "Арматура А500С d12 мм",
    "Швеллер 12П, 40 тонн",
    "Петр Первый",
    "Это практична и логична",
    "Королевна Мария",
    # конец предложения разделяет слова
    "Позвони Ивану. Петрович придёт позже",
    "Мария. Иванов пришёл",
    # латиница не разбирается (известный предел)
    "John Smith",
]


@pytest.mark.parametrize("text", POSITIVE)
def test_positive(text: str) -> None:
    assert _found(text), text


@pytest.mark.parametrize("text", NEGATIVE)
def test_negative(text: str) -> None:
    assert not _found(text), text


def test_placeholder_tokens_not_names() -> None:
    """Токены-заменители псевдонимизатора вырезаются в detector до этого модуля."""
    from labops_pii.guard.detector import find_pii_types

    assert "name" not in find_pii_types("Передай [PERSON_1] привет")


def test_window_bounds_respected() -> None:
    """Поиск идёт внутри окна [start, end)."""
    text = "Иванов Иван " + "x " * 20 + "конец"
    assert has_person_name(text, 0, 12)
    assert not has_person_name(text, 12)


# Объём пробы масштабирования: достаточно, чтобы квадратичный разбор был заметен, и мало,
# чтобы тест оставался быстрым
SCALE_BASE_CHARS = 512 * 1024
# Удвоение входа не должно утраивать время (линейный рост даёт около 2; запас на шум)
SCALE_RATIO_MAX = 4.0
SCALE_RUNS = 2
SCALE_FLOOR = 0.1
PATHOLOGICAL = {
    "names": "Иванов Иван Иванович ",
    "initials": "И. ",
    "hyphen": "а-",
    "longword": "а",
    "dots": "А.Б.",
    "caps": "Иванов ",
    "lower": "аааа ",
    "mixed": "Петров И. Сергеевна ип Лев Ильич. ",
}


def _elapsed(unit: str, chars: int) -> float:
    text = unit * (chars // len(unit))
    started = time.perf_counter()
    has_person_name(text)
    return time.perf_counter() - started


@pytest.mark.parametrize("kind", sorted(PATHOLOGICAL))
def test_linear_time(kind: str) -> None:
    """Патологические входы не дают квадратичного роста времени (вдвое длиннее - не втрое)."""
    unit = PATHOLOGICAL[kind]
    # Лучший из нескольких прогонов отсекает шум соседних процессов; нижняя граница времени
    # не даёт делить на миллисекунды у входов, которые разбираются почти мгновенно
    small = max(min(_elapsed(unit, SCALE_BASE_CHARS) for _ in range(SCALE_RUNS)), SCALE_FLOOR)
    large = min(_elapsed(unit, 2 * SCALE_BASE_CHARS) for _ in range(SCALE_RUNS))
    assert large / small < SCALE_RATIO_MAX, (kind, small, large)


def test_mode_parsing() -> None:
    assert parse_names_mode(None) is NamesMode.LOG_ONLY
    assert parse_names_mode("") is NamesMode.LOG_ONLY
    assert parse_names_mode(" Enforce ") is NamesMode.ENFORCE
    assert parse_names_mode("off") is NamesMode.OFF
    with pytest.raises(ValueError):
        parse_names_mode("on")


def test_unknown_mode_at_runtime_is_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    """Опечатка в окружении мимо проверки старта не выключает защиту."""
    monkeypatch.setenv("PII_GUARD_NAMES_MODE", "enforсe")  # кириллическая «с»
    assert names_mode() is NamesMode.ENFORCE
