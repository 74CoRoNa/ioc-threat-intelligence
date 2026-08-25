import pytest

from app.core.rate_limit import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_blocks_and_recovers_after_window() -> None:
    limiter = RateLimiter(requests=2, window_seconds=10)

    assert await limiter.allow("client", now=0) == (True, 0)
    assert await limiter.allow("client", now=1) == (True, 0)
    allowed, retry_after = await limiter.allow("client", now=2)
    assert allowed is False
    assert retry_after == 8
    assert await limiter.allow("client", now=11) == (True, 0)


@pytest.mark.asyncio
async def test_rate_limits_are_independent_per_client() -> None:
    limiter = RateLimiter(requests=1, window_seconds=60)

    assert (await limiter.allow("one", now=0))[0] is True
    assert (await limiter.allow("one", now=1))[0] is False
    assert (await limiter.allow("two", now=1))[0] is True

