"""Нераспознанный текст (рукопись, подпись, вычурный шрифт): поиск областей для закраски.

Tesseract не читает рукопись, и подпись «Сабина» уходила бы модели открытой. Эвристика:
находим мелкие тёмные (или светлые) штрихи на ровном фоне, склеиваем в области и отбрасываем
всё, что покрыто распознанными словами. Остаток закрашивается. Фото без текста не должно
закрашиваться: области с неправдоподобными размерами и слишком большая суммарная площадь
(фото, текстура) отбрасываются.
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np
from PIL import Image

# Работаем на уменьшенной копии: больше пикселей не добавляет точности, но стоит времени
WORK_SIDE = 1600
# Толщина штриха не больше этой доли короткой стороны (ядро blackhat/tophat), не меньше MIN_PX
STROKE_KERNEL_SHARE = 0.025
STROKE_KERNEL_MIN_PX = 5
# Штрихи слабее по контрасту - шум и текстура, не письмо
MIN_STROKE_CONTRAST = 40
# Склейка штрихов в слова: ядро по ширине/высоте, доля короткой стороны
JOIN_KERNEL_W_SHARE = 0.03
JOIN_KERNEL_H_SHARE = 0.008
# Допустимые размеры области (доли картинки) и форма
MIN_REGION_H_SHARE = 0.012
MAX_REGION_H_SHARE = 0.22
MIN_REGION_W_SHARE = 0.025
MAX_ASPECT = 18.0
# Доля пикселей-штрихов внутри рамки области: линия или заливка не похожи на письмо
MIN_INK_DENSITY = 0.03
MAX_INK_DENSITY = 0.55
# Суммарная площадь кандидатов больше этой доли картинки - это фото или текстура, а не
# редкие надписи: не закрашиваем ничего (иначе испорчено всё изображение)
MAX_TOTAL_SHARE = 0.20
# Поле вокруг распознанного слова, которое исключается из поиска (доля высоты слова)
KNOWN_PAD_SHARE = 0.35
# Поле закраски вокруг найденной области (доля высоты области)
FILL_PAD_SHARE = 0.15
FILL_PAD_MIN_PX = 3
# Часть площади области, перекрытая распознанными словами, после которой область отбрасывается
KNOWN_OVERLAP_SHARE = 0.5


@dataclass(frozen=True, slots=True)
class UnreadableRegions:
    """Итог поиска.

    Attributes:
        rects: Рамки закраски (left, top, right, bottom) в координатах исходной картинки.
        dropped_as_photo: Кандидаты отброшены по суммарной площади (картинка похожа на фото).
    """

    rects: list[tuple[int, int, int, int]]
    dropped_as_photo: bool = False


def _stroke_mask(gray: np.ndarray) -> np.ndarray:
    """Бинарная маска тонких штрихов: тёмных на светлом и светлых на тёмном."""
    side = min(gray.shape)
    k = max(STROKE_KERNEL_MIN_PX, round(side * STROKE_KERNEL_SHARE))
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k))
    smooth = cv2.GaussianBlur(gray, (3, 3), 0)
    dark = cv2.morphologyEx(smooth, cv2.MORPH_BLACKHAT, kernel)
    light = cv2.morphologyEx(smooth, cv2.MORPH_TOPHAT, kernel)
    mask = np.zeros_like(gray)
    for layer in (dark, light):
        if int(layer.max()) < MIN_STROKE_CONTRAST:
            continue
        # Порог не ниже MIN_STROKE_CONTRAST: на ровном фоне Отсу выбрал бы шум
        level, binary = cv2.threshold(layer, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        if level < MIN_STROKE_CONTRAST:
            _lvl, binary = cv2.threshold(layer, MIN_STROKE_CONTRAST, 255, cv2.THRESH_BINARY)
        mask = cv2.bitwise_or(mask, binary)
    return mask


def find_unreadable(
    image: Image.Image, known: list[tuple[int, int, int, int]]
) -> UnreadableRegions:
    """Ищет области с признаками письма, не покрытые распознанными словами.

    Args:
        image: Картинка (RGB), которую читал OCR; чёрные заливки уже на ней допустимы.
        known: Рамки слов, найденных OCR (в координатах image): они уже проверены или
            закрашены, поэтому исключаются из поиска.

    Returns:
        Рамки закраски в координатах image.
    """
    width, height = image.size
    scale = min(1.0, WORK_SIDE / max(width, height))
    work = image.convert("L")
    if scale < 1.0:
        work = work.resize((round(width * scale), round(height * scale)), Image.Resampling.BOX)
    gray = np.asarray(work)
    h, w = gray.shape
    ink = _stroke_mask(gray)
    for left, top, right, bottom in known:
        pad = round((bottom - top) * KNOWN_PAD_SHARE)
        ink[
            max(0, round((top - pad) * scale)):round((bottom + pad) * scale) + 1,
            max(0, round((left - pad) * scale)):round((right + pad) * scale) + 1,
        ] = 0
    side = min(h, w)
    join = cv2.getStructuringElement(
        cv2.MORPH_RECT,
        (max(3, round(side * JOIN_KERNEL_W_SHARE)), max(1, round(side * JOIN_KERNEL_H_SHARE))),
    )
    joined = cv2.morphologyEx(ink, cv2.MORPH_CLOSE, join)
    count, labels, stats, _centroids = cv2.connectedComponentsWithStats(joined, connectivity=8)
    rects: list[tuple[int, int, int, int]] = []
    area = 0
    for i in range(1, count):
        x, y, bw, bh, _a = (int(v) for v in stats[i])
        if not _plausible(bw, bh, w, h):
            continue
        region = ink[y:y + bh, x:x + bw]
        density = float(np.count_nonzero(region)) / (bw * bh)
        if not MIN_INK_DENSITY <= density <= MAX_INK_DENSITY:
            continue
        pad = max(FILL_PAD_MIN_PX, round(bh * FILL_PAD_SHARE))
        rect = (
            max(0, round((x - pad) / scale)), max(0, round((y - pad) / scale)),
            min(width - 1, round((x + bw + pad) / scale)),
            min(height - 1, round((y + bh + pad) / scale)),
        )
        rects.append(rect)
        area += (rect[2] - rect[0]) * (rect[3] - rect[1])
    if area > MAX_TOTAL_SHARE * width * height:
        return UnreadableRegions([], dropped_as_photo=True)
    return UnreadableRegions(rects)


def _plausible(bw: int, bh: int, w: int, h: int) -> bool:
    """Размер и пропорции рамки похожи на слово или подпись."""
    if bh < MIN_REGION_H_SHARE * h or bh > MAX_REGION_H_SHARE * h:
        return False
    if bw < MIN_REGION_W_SHARE * w:
        return False
    return bw / bh <= MAX_ASPECT
