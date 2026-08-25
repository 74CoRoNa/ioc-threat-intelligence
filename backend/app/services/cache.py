import asyncio
from dataclasses import replace
from time import monotonic

from app.services.provider import ProviderResult


class TTLProviderCache:
    """Keep short-lived normalized provider results in memory."""

    def __init__(self, ttl: int) -> None:
        self.ttl = ttl
        self._items: dict[str, tuple[float, ProviderResult]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> ProviderResult | None:
        if self.ttl == 0:
            return None
        async with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            stored_at, result = item
            if monotonic() - stored_at > self.ttl:
                self._items.pop(key, None)
                return None
            return replace(result, cached=True)

    async def set(self, key: str, result: ProviderResult) -> None:
        if self.ttl == 0 or result.status != "ok":
            return
        async with self._lock:
            self._items[key] = (monotonic(), result)

