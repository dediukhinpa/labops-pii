"""ASGI-middleware: проверка Bearer и предел размера тела до его разбора.

FastAPI читает и разбирает тело (`await request.json()`) раньше, чем выполняются зависимости
(токен) и обработчик (`ensure_size`, семафор), а у uvicorn предела тела нет: запрос на сотни
мегабайт целиком попадал в память. Здесь токен проверяется по заголовкам, размер - по
`Content-Length` и потоковым счётчиком байт, и тело дальше не читается.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

logger = logging.getLogger(__name__)

HTTP_UNAUTHORIZED = 401
HTTP_TOO_LARGE = 413

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class BodyTooLargeError(Exception):
    """Тело запроса выросло сверх предела во время чтения."""


class BodyGuardMiddleware:
    """Отказывает 401 без верного токена и 413 на теле сверх предела, не читая лишнего.

    Args:
        app: Следующее приложение ASGI.
        max_body_bytes: Предел тела в байтах (по `Content-Length` и по факту чтения).
        authorize: Принимает значение заголовка Authorization, возвращает True для верного
            токена; None - токен не проверяется (сервис без аутентификации).
        guarded_paths: Пути POST-запросов, для которых проверяются токен и размер; остальные
            запросы (health, чужие методы) проходят как есть.
        guarded_delete_prefixes: Префиксы путей DELETE-запросов (например, "/threads/"):
            для них проверяется токен, тела у такого запроса нет.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int,
        authorize: Callable[[str], bool] | None,
        guarded_paths: Iterable[str],
        guarded_delete_prefixes: Iterable[str] = (),
    ) -> None:
        self._app = app
        self._max_body_bytes = max_body_bytes
        self._authorize = authorize
        self._guarded_paths = frozenset(guarded_paths)
        self._delete_prefixes = tuple(guarded_delete_prefixes)

    def _is_guarded(self, scope: Scope) -> bool:
        """Запрос попадает под проверку: POST по списку путей или DELETE по префиксу."""
        if scope["type"] != "http":
            return False
        if scope["method"] == "POST":
            return scope["path"] in self._guarded_paths
        if scope["method"] == "DELETE":
            return bool(self._delete_prefixes) and scope["path"].startswith(
                self._delete_prefixes
            )
        return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self._is_guarded(scope):
            await self._app(scope, receive, send)
            return
        headers = {name: value for name, value in scope["headers"]}
        if self._authorize is not None:
            supplied = headers.get(b"authorization", b"").decode("latin-1")
            if not self._authorize(supplied):
                logger.warning("request unauthorized: path=%s", scope["path"])
                await _reply(
                    send, HTTP_UNAUTHORIZED, "unauthorized", {"WWW-Authenticate": "Bearer"}
                )
                return
        if self._declared_too_large(headers.get(b"content-length")):
            await self._reject_too_large(scope, send)
            return

        received = 0
        # Отказ 413 уже отправлен: дальнейшие ответы приложения отбрасываются
        rejected = False

        async def counting_receive() -> Message:
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_body_bytes and not rejected:
                    # Ответ уходит отсюда, а не из обработчика исключения ниже: FastAPI
                    # перехватывает любое исключение чтения тела и подменяет его на 400.
                    rejected = True
                    await self._reject_too_large(scope, send)
                    raise BodyTooLargeError
            return message

        async def guarded_send(message: Message) -> None:
            if not rejected:
                await send(message)

        try:
            await self._app(scope, counting_receive, guarded_send)
        except BodyTooLargeError:
            # Приложение не перехватило исключение: ответ 413 уже отправлен
            pass

    def _declared_too_large(self, content_length: bytes | None) -> bool:
        """Заявленная длина тела сверх предела; нечисловое значение проверит счётчик."""
        try:
            return content_length is not None and int(content_length) > self._max_body_bytes
        except ValueError:
            return False

    async def _reject_too_large(self, scope: Scope, send: Send) -> None:
        logger.warning(
            "request body rejected: path=%s limit=%d bytes", scope["path"], self._max_body_bytes
        )
        await _reply(
            send,
            HTTP_TOO_LARGE,
            f"request body is too large: limit is {self._max_body_bytes} bytes",
        )


async def _reply(
    send: Send, status: int, detail: str, extra_headers: dict[str, str] | None = None
) -> None:
    """Отправляет JSON-ответ `{"detail": ...}` как FastAPI для HTTPException."""
    body = json.dumps({"detail": detail}).encode()
    headers = {"content-type": "application/json", "content-length": str(len(body))}
    headers.update(extra_headers or {})
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )
    await send({"type": "http.response.body", "body": body})
