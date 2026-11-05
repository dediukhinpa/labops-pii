"""QR-коды и штрихкоды: поиск, локальная расшифровка, разбор визиток (vCard, MECARD).

Область кода закрашивается всегда, даже если расшифровать его не вышло: в коде может быть
контакт. Расшифрованное содержимое отдаётся прокси текстом, а он заменяет ПДн метками.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import cv2
import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)

# Поле вокруг кода (доля большей стороны рамки): рамка детектора бывает на пару модулей уже
CODE_PAD_SHARE = 0.08
CODE_PAD_MIN_PX = 4
# Предел длины содержимого одного кода в ответе (символов); длиннее - обрезка
MAX_CODE_CHARS = 2_000
# Масштабы поиска штрихкодов (детектор OpenCV чувствителен к ширине штриха) и наименьшая
# допустимая сторона уменьшенной копии
BARCODE_SCALES = (1.0, 0.5, 0.25)
BARCODE_MIN_SIDE_PX = 100
# Метки полей в тексте, который уходит на проверку детектору
LABEL_NAME = "ФИО"
LABEL_PHONE = "Телефон"
LABEL_EMAIL = "Эл. почта"
LABEL_ADDRESS = "Адрес"
LABEL_ORG = "Организация"
LABEL_TITLE = "Должность"
LABEL_URL = "Сайт"
LABEL_NOTE = "Заметка"
FIELD_SEP = "; "
KIND_QR = "qr"
KIND_BARCODE = "barcode"

VCARD_BEGIN = "BEGIN:VCARD"
MECARD_PREFIX = "MECARD:"
WIFI_PREFIX = "WIFI:"
# Wi-Fi в коде: имя сети и пароль. Пароль - секрет, детектор ПДн его не знает: не отдаётся
WIFI_NOTE = "доступ к Wi-Fi (имя сети и пароль скрыты)"

# vCard: свойство[;параметры]:значение
_VCARD_LINE = re.compile(r"^([A-Za-z0-9-]+)(?:;[^:]*)?:(.*)$")
_VCARD_FIELDS: dict[str, str] = {
    "FN": LABEL_NAME, "TEL": LABEL_PHONE, "EMAIL": LABEL_EMAIL, "ORG": LABEL_ORG,
    "TITLE": LABEL_TITLE, "URL": LABEL_URL, "NOTE": LABEL_NOTE,
}
_MECARD_FIELDS: dict[str, str] = {
    "TEL": LABEL_PHONE, "EMAIL": LABEL_EMAIL, "ADR": LABEL_ADDRESS, "URL": LABEL_URL,
    "NOTE": LABEL_NOTE, "ORG": LABEL_ORG, "TITLE": LABEL_TITLE,
}
# Части структурных свойств vCard N (фамилия;имя;отчество;префикс;суффикс) и ADR
# (абонентский ящик;доп.адрес;улица;город;регион;индекс;страна)
_N_ORDER = (1, 2, 0)


@dataclass(frozen=True, slots=True)
class CodeHit:
    """Найденный код.

    Attributes:
        rect: Рамка закраски (left, top, right, bottom) с полем.
        text: Расшифрованное содержимое, приведённое к читаемому виду; пусто, если не
            расшифровано.
        kind: qr или barcode.
    """

    rect: tuple[int, int, int, int]
    text: str
    kind: str = KIND_QR


def _unescape(value: str) -> str:
    """Снимает экранирование vCard и склеивает многострочное значение."""
    return (value.replace("\\n", " ").replace("\\N", " ").replace("\\,", ",")
            .replace("\\;", ";").strip())


def _join(parts: list[str], sep: str = " ") -> str:
    return sep.join(p for p in (x.strip() for x in parts) if p)


def _unfold(text: str) -> list[str]:
    """Строки vCard: продолжение (строка с пробелом в начале) приклеивается к предыдущей."""
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        elif raw.strip():
            lines.append(raw.rstrip())
    return lines


def _parse_vcard(text: str) -> str:
    """vCard в строку «ФИО: ...; Телефон: ...; Адрес: ...»."""
    fields: list[str] = []
    lines = _unfold(text)
    # FN - готовое отображаемое имя; N разбирается, только если FN нет (иначе имя дважды)
    has_fn = any(line.upper().startswith(("FN:", "FN;")) for line in lines)
    for line in lines:
        m = _VCARD_LINE.match(line)
        if m is None:
            continue
        prop, value = m.group(1).upper(), m.group(2)
        if prop == "N" and not has_fn:
            parts = value.split(";")
            # Порядок для чтения: имя, отчество, фамилия
            ordered = [parts[i] for i in _N_ORDER if i < len(parts)]
            name = _join([_unescape(p) for p in ordered])
            if name:
                fields.append(f"{LABEL_NAME}: {name}")
        elif prop == "N":
            continue
        elif prop == "ADR":
            address = _join([_unescape(p) for p in value.split(";")], ", ")
            if address:
                fields.append(f"{LABEL_ADDRESS}: {address}")
        elif prop in _VCARD_FIELDS:
            clean = _unescape(value.replace(";", ", ") if prop == "ORG" else value)
            if clean:
                fields.append(f"{_VCARD_FIELDS[prop]}: {clean}")
    return FIELD_SEP.join(fields)


def _split_mecard(body: str) -> list[str]:
    """Поля MECARD через «;» с учётом экранирования «\\;»."""
    return [p for p in re.split(r"(?<!\\);", body) if p]


def _parse_mecard(text: str) -> str:
    """MECARD:N:Фамилия,Имя;TEL:...;EMAIL:...;ADR:...;; в читаемую строку."""
    fields: list[str] = []
    for part in _split_mecard(text[len(MECARD_PREFIX):]):
        key, _, value = part.partition(":")
        key, value = key.strip().upper(), _unescape(value)
        if not value:
            continue
        if key == "N":
            # «Фамилия,Имя» - для чтения «Имя Фамилия»
            fields.append(f"{LABEL_NAME}: {_join(value.split(',')[::-1])}")
        elif key == "ADR":
            fields.append(f"{LABEL_ADDRESS}: {_join(value.split(','), ', ')}")
        elif key in _MECARD_FIELDS:
            fields.append(f"{_MECARD_FIELDS[key]}: {value}")
    return FIELD_SEP.join(fields)


def describe_payload(payload: str) -> str:
    """Приводит содержимое кода к тексту для детектора ПДн.

    vCard и MECARD разбираются по полям (ФИО, телефон, почта, адрес с подписями): в «сыром»
    виде «N:Иванов;Пётр;;;» детектор имён не видит. Wi-Fi теряет пароль. Остальное - как есть,
    в одну строку и с пределом длины.
    """
    text = payload.strip()
    upper = text.upper()
    if upper.startswith(VCARD_BEGIN):
        parsed = _parse_vcard(text)
    elif upper.startswith(MECARD_PREFIX):
        parsed = _parse_mecard(text)
    elif upper.startswith(WIFI_PREFIX):
        parsed = WIFI_NOTE
    else:
        parsed = " ".join(text.split())
    return parsed[:MAX_CODE_CHARS]


def _rect_of(points: np.ndarray, size: tuple[int, int]) -> tuple[int, int, int, int]:
    """Габаритная рамка четырёхугольника с полем, в пределах картинки."""
    pts = points.reshape(-1, 2)
    left, top = float(pts[:, 0].min()), float(pts[:, 1].min())
    right, bottom = float(pts[:, 0].max()), float(pts[:, 1].max())
    pad = max(CODE_PAD_MIN_PX, round(max(right - left, bottom - top) * CODE_PAD_SHARE))
    return (
        max(0, int(left) - pad), max(0, int(top) - pad),
        min(size[0] - 1, int(right) + pad), min(size[1] - 1, int(bottom) + pad),
    )


def _overlaps(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


class CodeFinder:
    """Ищет QR-коды и штрихкоды средствами OpenCV (без новых зависимостей)."""

    def __init__(self) -> None:
        self._qr = cv2.QRCodeDetector()
        # Модуль штрихкодов есть в opencv >= 4.8; без него ищем только QR
        barcode = getattr(cv2, "barcode", None)
        self._barcode = barcode.BarcodeDetector() if barcode is not None else None

    def find(self, image: Image.Image) -> list[CodeHit]:
        """Находит все коды на картинке.

        Raises:
            cv2.error: Сбой OpenCV (вызывающий считает это отказом).
        """
        gray = np.ascontiguousarray(np.asarray(image.convert("L")))
        hits: list[CodeHit] = []
        hits += self._find_qr(gray, image.size)
        for hit in self._find_barcodes(gray, image.size):
            # Штрихкод внутри уже найденного QR (ложное срабатывание) не дублируется
            if not any(_overlaps(hit.rect, h.rect) for h in hits):
                hits.append(hit)
        return hits

    def _find_qr(self, gray: np.ndarray, size: tuple[int, int]) -> list[CodeHit]:
        # Сначала поиск рамок, потом расшифровка: нерасшифрованный код всё равно закрашивается
        found, points = self._qr.detectMulti(gray)
        if not found or points is None:
            return []
        try:
            _ok, infos, _pts, _straight = self._qr.detectAndDecodeMulti(gray)
        except cv2.error:
            infos = ()
        texts = list(infos) if infos is not None else []
        hits: list[CodeHit] = []
        for i, quad in enumerate(points):
            payload = texts[i] if i < len(texts) else ""
            hits.append(CodeHit(_rect_of(quad, size), describe_payload(payload), KIND_QR))
        return hits

    def _find_barcodes(self, gray: np.ndarray, size: tuple[int, int]) -> list[CodeHit]:
        """Штрихкоды в нескольких масштабах: детектор OpenCV находит штрихи только узкие."""
        if self._barcode is None:
            return []
        hits: list[CodeHit] = []
        for scale in BARCODE_SCALES:
            small = gray if scale == 1.0 else cv2.resize(
                gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
            if min(small.shape) < BARCODE_MIN_SIDE_PX:
                continue
            found, infos, _types, points = self._barcode.detectAndDecodeWithType(small)
            if not found or points is None:
                # Рамку видно, расшифровать не вышло: область всё равно закрашивается
                found, points = self._barcode.detect(small)
                infos = ()
            if not found or points is None:
                continue
            texts = list(infos) if infos is not None else []
            for i, quad in enumerate(points):
                hit = CodeHit(
                    _rect_of(np.asarray(quad) / scale, size),
                    describe_payload(texts[i] if i < len(texts) else ""),
                    KIND_BARCODE,
                )
                same = next((j for j, h in enumerate(hits) if _overlaps(hit.rect, h.rect)), None)
                if same is None:
                    hits.append(hit)
                elif hit.text and not hits[same].text:
                    hits[same] = hit
        return hits
