"""Режим «gate»: есть ли на картинке текст (Tesseract), без распознавания наружу."""

from labops_pii.media.gate.detect import (
    RESULT_NO_TEXT,
    RESULT_NOT_RECOGNIZED,
    RESULT_TEXT,
    OcrBusyError,
    OcrGate,
    OcrSettings,
    check_input,
    detect_text,
    load_ocr_settings,
)
from labops_pii.media.gate.normalize import (
    ImageCorruptError,
    ImageLimits,
    ImageTooLargeError,
    ImageUnsupportedError,
)

__all__ = [
    "ImageCorruptError", "ImageLimits", "ImageTooLargeError", "ImageUnsupportedError",
    "OcrBusyError", "OcrGate", "OcrSettings", "RESULT_NOT_RECOGNIZED", "RESULT_NO_TEXT",
    "RESULT_TEXT", "check_input", "detect_text", "load_ocr_settings",
]
