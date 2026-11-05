"""Поиск лиц каскадами Хаара (OpenCV) и их необратимая пикселизация."""

from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np
from PIL import Image

FRONTAL_CASCADES = ("haarcascade_frontalface_default.xml", "haarcascade_frontalface_alt2.xml")
PROFILE_CASCADE = "haarcascade_profileface.xml"
SCALE_FACTOR = 1.1
# Ниже порога соседей Хаара даёт много ложных срабатываний; ложная заливка дешевле пропуска,
# но 3 уже давало шум на тексте
MIN_NEIGHBORS = 4
# Наименьшее лицо: доля короткой стороны картинки и абсолютный пол в пикселях
MIN_FACE_SIDE_SHARE = 0.04
MIN_FACE_SIDE_PX = 24
# Поле вокруг найденного лица (доля стороны): каскад режет лоб и подбородок
FACE_PAD_SHARE = 0.3
# Лицо сводится к сетке PIXEL_GRID x PIXEL_GRID блоков: черты не восстановить
PIXEL_GRID = 6


class FaceError(Exception):
    """Каскады лиц не загрузились."""


class FaceBlurrer:
    """Находит лица и пикселизирует их."""

    def __init__(self) -> None:
        base = Path(cv2.data.haarcascades)
        self._frontal = [self._load(base / name) for name in FRONTAL_CASCADES]
        self._profile = self._load(base / PROFILE_CASCADE)

    @staticmethod
    def _load(path: Path) -> cv2.CascadeClassifier:
        """Загружает каскад; пустой каскад = ошибка (иначе лица молча не искались бы)."""
        cascade = cv2.CascadeClassifier(str(path))
        if cascade.empty():
            raise FaceError(f"каскад не загружен: {path.name}")
        return cascade

    def find(self, image: Image.Image) -> list[tuple[int, int, int, int]]:
        """Возвращает рамки лиц (left, top, right, bottom) с полем."""
        width, height = image.size
        gray = np.asarray(image.convert("L"))
        min_side = max(MIN_FACE_SIDE_PX, int(min(width, height) * MIN_FACE_SIDE_SHARE))
        size = (min_side, min_side)
        found: list[tuple[int, int, int, int]] = []
        for cascade in self._frontal:
            found += self._run(cascade, gray, size)
        found += self._run(self._profile, gray, size)
        # Профиль в другую сторону: зеркалим картинку и пересчитываем x
        for x, y, w, h in self._run_raw(self._profile, np.ascontiguousarray(gray[:, ::-1]), size):
            found.append(self._pad(width - x - w, y, w, h, width, height))
        return found

    def _run_raw(
        self, cascade: cv2.CascadeClassifier, gray: np.ndarray, size: tuple[int, int]
    ) -> list[tuple[int, int, int, int]]:
        boxes = cascade.detectMultiScale(
            gray, scaleFactor=SCALE_FACTOR, minNeighbors=MIN_NEIGHBORS, minSize=size
        )
        return [(int(x), int(y), int(w), int(h)) for x, y, w, h in boxes]

    def _run(
        self, cascade: cv2.CascadeClassifier, gray: np.ndarray, size: tuple[int, int]
    ) -> list[tuple[int, int, int, int]]:
        height, width = gray.shape
        return [self._pad(x, y, w, h, width, height) for x, y, w, h in
                self._run_raw(cascade, gray, size)]

    @staticmethod
    def _pad(
        x: int, y: int, w: int, h: int, width: int, height: int
    ) -> tuple[int, int, int, int]:
        pad_x, pad_y = int(w * FACE_PAD_SHARE), int(h * FACE_PAD_SHARE)
        return (
            max(0, x - pad_x), max(0, y - pad_y),
            min(width, x + w + pad_x), min(height, y + h + pad_y),
        )

    @staticmethod
    def pixelate(image: Image.Image, box: tuple[int, int, int, int]) -> None:
        """Заменяет область на грубую мозаику (на месте)."""
        left, top, right, bottom = box
        region = image.crop(box)
        small = region.resize((PIXEL_GRID, PIXEL_GRID), Image.Resampling.BOX)
        mosaic = small.resize((right - left, bottom - top), Image.Resampling.NEAREST)
        image.paste(mosaic, (left, top))
