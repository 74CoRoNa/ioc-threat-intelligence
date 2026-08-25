from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ProviderResult:
    source: str
    status: str
    data: dict[str, Any] | None = None
    message: str | None = None
    external_url: str | None = None
    cached: bool = False


def not_configured(source: str) -> ProviderResult:
    return ProviderResult(
        source=source,
        status="not_configured",
        message="API key not configured.",
    )

