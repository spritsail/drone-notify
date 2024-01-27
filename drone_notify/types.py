"""
Type signatures, mostly useful for static type checking
"""

from collections.abc import Awaitable, Callable

from aiohttp.web import Request, StreamResponse

# FIXME: import these from aiohttp.typedefs when aiohttp 4.x is released
Handler = Callable[[Request], Awaitable[StreamResponse]]
Middleware = Callable[[Request, Handler], Awaitable[StreamResponse]]
