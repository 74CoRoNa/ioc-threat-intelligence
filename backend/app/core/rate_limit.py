import asyncio
from collections import defaultdict, deque
from time import monotonic

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


class RateLimiter:
    """Bound requests per client key with an in-memory sliding window."""

    def __init__(self, requests: int, window_seconds: int) -> None:
        self.requests = requests
        self.window_seconds = window_seconds
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = asyncio.Lock()

    async def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        current = monotonic() if now is None else now
        async with self.lock:
            events = self.events[key]
            threshold = current - self.window_seconds
            while events and events[0] <= threshold:
                events.popleft()
            if len(events) >= self.requests:
                retry_after = max(1, round(events[0] + self.window_seconds - current))
                return False, retry_after
            events.append(current)
            return True, 0


class AnalyzeRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: object, requests: int, window_seconds: int) -> None:
        super().__init__(app)
        self.limiter = RateLimiter(requests, window_seconds)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if request.url.path.startswith("/api/analyze"):
            client = request.client.host if request.client else "unknown"
            allowed, retry_after = await self.limiter.allow(client)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                    content={
                        "error": {
                            "code": "rate_limited",
                            "message": "Too many analysis requests. Try again shortly.",
                            "details": {"retry_after_seconds": retry_after},
                        }
                    },
                )
        return await call_next(request)

