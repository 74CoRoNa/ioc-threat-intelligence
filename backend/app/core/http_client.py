import asyncio
from typing import Any

import httpx

from app.core.config import get_settings


class HTTPClient:
    """Make bounded vendor requests and normalize transport failures."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            follow_redirects=True,
        )
        self.owns_client = client is None

    async def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any] | None, str | None]:
        response: httpx.Response | None = None
        for attempt in range(2):
            try:
                response = await self.client.get(url, headers=headers, params=params)
                break
            except httpx.ConnectError:
                if attempt == 1:
                    return "error", None, "Could not connect to the external service."
                await asyncio.sleep(0)
            except httpx.TimeoutException:
                return "timeout", None, "The external service request timed out."
            except httpx.HTTPError:
                return "error", None, "The external service request failed."

        if response is None:
            return "error", None, "The external service request failed."
        if response.status_code == 429:
            return "rate_limited", None, "The external service rate limit was reached."
        if response.status_code in {401, 403}:
            return "error", None, "The external service rejected its configured credentials."
        if response.status_code == 404:
            return "error", None, "No report was found for this target."
        if response.is_error:
            return "error", None, f"The external service returned HTTP {response.status_code}."
        try:
            payload = response.json()
        except ValueError:
            return "error", None, "The external service returned invalid JSON."
        if not isinstance(payload, dict):
            return "error", None, "The external service returned an unexpected response."
        return "ok", payload, None

    async def post_form_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any] | None, str | None]:
        try:
            response = await self.client.post(url, headers=headers, data=data)
        except httpx.TimeoutException:
            return "timeout", None, "The external service request timed out."
        except httpx.HTTPError:
            return "error", None, "The external service request failed."
        if response.status_code == 429:
            return "rate_limited", None, "The external service rate limit was reached."
        if response.status_code in {401, 403}:
            return "error", None, "The external service rejected its configured credentials."
        if response.is_error:
            return "error", None, f"The external service returned HTTP {response.status_code}."
        try:
            payload = response.json()
        except ValueError:
            return "error", None, "The external service returned invalid JSON."
        if not isinstance(payload, dict):
            return "error", None, "The external service returned an unexpected response."
        return "ok", payload, None

    async def close(self) -> None:
        if self.owns_client:
            await self.client.aclose()

    async def post_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any] | None, str | None]:
        try:
            response = await self.client.post(url, headers=headers, json=json)
        except httpx.TimeoutException:
            return "timeout", None, "The external service request timed out."
        except httpx.HTTPError:
            return "error", None, "The external service request failed."
        if response.status_code == 429:
            return "rate_limited", None, "The external service rate limit was reached."
        if response.status_code in {401, 403}:
            return "error", None, "The external service rejected its configured credentials."
        if response.is_error:
            return "error", None, f"The external service returned HTTP {response.status_code}."
        try:
            payload = response.json()
        except ValueError:
            return "error", None, "The external service returned invalid JSON."
        if not isinstance(payload, dict):
            return "error", None, "The external service returned an unexpected response."
        return "ok", payload, None
