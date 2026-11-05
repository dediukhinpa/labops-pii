"""Медиа: маска фото и PDF (`mask`) и детектор «есть ли текст на картинке» (`gate`).

Чистый Python API без FastAPI в `mask` и `gate.detect`: им пользуются и HTTP-обёртки, и
пакетные пути (например, indexer с картинками с диска). HTTP — в `gate.api` и `mask.api`.
Зависимости — extras `media` (Pillow, OpenCV, pypdfium2); текстовый сервис их не тянет.
"""
