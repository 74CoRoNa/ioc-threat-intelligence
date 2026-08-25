from typing import Any

from pydantic import BaseModel, ConfigDict


class ProviderResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: str
    status: str
    data: dict[str, Any] | None
    message: str | None
    external_url: str | None
    cached: bool

