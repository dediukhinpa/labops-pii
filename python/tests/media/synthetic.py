"""Синтетические картинки для тестов текста, кодов и рукописи. Все значения вымышлены."""

from __future__ import annotations

import random

import cv2
import numpy as np
from PIL import Image, ImageDraw

from tests.media.conftest import make_text_image

CARD_SIZE = (1200, 600)
CARD_LINES = (
    "Иванов Пётр Сергеевич",
    "Директор по закупкам",
    "+7 912 345-67-89",
    "г. Абакан, ул. Ленина 15",
)
CARD_FRAGMENTS = ("Иванов", "Сергеевич", "912", "Абакан", "Ленина")

VCARD = (
    "BEGIN:VCARD\nVERSION:3.0\nN:Иванов;Пётр;Сергеевич;;\nFN:Иванов Пётр Сергеевич\n"
    "TEL;TYPE=CELL:+7 912 345-67-89\nEMAIL:petr.ivanov@example.com\n"
    "ADR;TYPE=WORK:;;ул. Ленина 15;Абакан;;655017;Россия\nEND:VCARD"
)
QR_MODULE_PX = 5
QR_QUIET_PX = 40
QR_ORIGIN = (100, 100)

SIGNATURE_ORIGIN = (700, 450)
SIGNATURE_BOX = (680, 400, 1000, 520)
INK = (20, 20, 60)
SIGNATURE_POINTS = 40
SIGNATURE_WIDTH = 3

EAN_L = ("0001101", "0011001", "0010011", "0111101", "0100011",
         "0110001", "0101111", "0111011", "0110111", "0001011")
EAN_G = ("0100111", "0110011", "0011011", "0100001", "0011101",
         "0111001", "0000101", "0010001", "0001001", "0010111")
EAN_R = ("1110010", "1100110", "1101100", "1000010", "1011100",
         "1001110", "1010000", "1000100", "1001000", "1110100")
EAN_PARITY = ("LLLLLL", "LLGLGG", "LLGGLG", "LLGGGL", "LGLLGG",
              "LGGLLG", "LGGGLL", "LGLGLG", "LGLGGL", "LGGLGL")
EAN_BAR_PX = 4
EAN_HEIGHT_PX = 180


def card_image() -> Image.Image:
    """Визитка: ФИО, должность, телефон, адрес."""
    return make_text_image(CARD_LINES, CARD_SIZE)


def draw_signature(img: Image.Image, origin: tuple[int, int] = SIGNATURE_ORIGIN) -> None:
    """Рисует «рукописную» подпись: плавная кривая со случайной дрожью и росчерк.

    Tesseract такое не читает (проверено в тестах), как и настоящую подпись.
    """
    rnd = random.Random(7)
    draw = ImageDraw.Draw(img)
    x, y = origin
    points = []
    for i in range(SIGNATURE_POINTS):
        x += rnd.randint(4, 9)
        y = origin[1] + int(35 * np.sin(i / 2.3)) + rnd.randint(-6, 6)
        points.append((x, y))
    draw.line(points, fill=INK, width=SIGNATURE_WIDTH, joint="curve")
    draw.line([(origin[0] - 10, origin[1] + 50), (x + 20, origin[1] + 30)],
              fill=INK, width=SIGNATURE_WIDTH)


def qr_image(payload: str, size: tuple[int, int] = (1200, 700)) -> Image.Image:
    """Белая картинка с QR-кодом на месте QR_ORIGIN."""
    code = cv2.QRCodeEncoder.create().encode(payload)
    code = cv2.resize(code, None, fx=QR_MODULE_PX, fy=QR_MODULE_PX,
                      interpolation=cv2.INTER_NEAREST)
    code = cv2.copyMakeBorder(code, QR_QUIET_PX, QR_QUIET_PX, QR_QUIET_PX, QR_QUIET_PX,
                              cv2.BORDER_CONSTANT, value=255)
    img = Image.new("RGB", size, "white")
    img.paste(Image.fromarray(code).convert("RGB"), QR_ORIGIN)
    return img


def ean13_bits(digits: str) -> str:
    """Битовая строка EAN-13 (12 цифр + контрольная считается здесь)."""
    total = sum(int(d) * (3 if i % 2 else 1) for i, d in enumerate(digits[:12]))
    full = digits[:12] + str((10 - total % 10) % 10)
    parity = EAN_PARITY[int(full[0])]
    left = "".join((EAN_L if p == "L" else EAN_G)[int(d)] for p, d in zip(parity, full[1:7]))
    right = "".join(EAN_R[int(d)] for d in full[7:])
    return "101" + left + "01010" + right + "101"


def barcode_image(digits: str, size: tuple[int, int] = (900, 500)) -> Image.Image:
    """Белая картинка со штрихкодом EAN-13 в центре."""
    bits = ean13_bits(digits)
    quiet = 9 * EAN_BAR_PX
    strip = np.full((EAN_HEIGHT_PX, len(bits) * EAN_BAR_PX + 2 * quiet), 255, np.uint8)
    for i, bit in enumerate(bits):
        if bit == "1":
            strip[:, quiet + i * EAN_BAR_PX:quiet + (i + 1) * EAN_BAR_PX] = 0
    img = Image.new("RGB", size, "white")
    img.paste(Image.fromarray(strip).convert("RGB"),
              ((size[0] - strip.shape[1]) // 2, (size[1] - strip.shape[0]) // 2))
    return img


def photo_image(size: tuple[int, int] = (900, 600)) -> Image.Image:
    """Фото без текста: градиент, пятна и мелкий шум, слегка размытые."""
    rnd = np.random.RandomState(1)
    width, height = size
    base = np.zeros((height, width, 3), np.float32)
    yy, xx = np.mgrid[0:height, 0:width]
    base[..., 0] = 120 + 60 * xx / width
    base[..., 1] = 140 + 50 * yy / height
    base[..., 2] = 170
    for _ in range(6):
        center = (int(rnd.randint(100, width - 100)), int(rnd.randint(100, height - 100)))
        color = tuple(int(v) for v in rnd.randint(40, 230, 3))
        cv2.circle(base, center, int(rnd.randint(40, 120)), color, -1)
    base += rnd.normal(0, 6, base.shape)
    base = cv2.GaussianBlur(base, (0, 0), 3)
    return Image.fromarray(np.clip(base, 0, 255).astype(np.uint8))


def dark_share(img: Image.Image, box: tuple[int, int, int, int]) -> float:
    """Доля чисто чёрных пикселей (цвет заливки) в рамке."""
    region = np.asarray(img.convert("RGB").crop(box))
    return float(np.mean(np.all(region == 0, axis=2)))
