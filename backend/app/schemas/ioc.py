from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LogAnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)


class ExtractedIOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    value: str
    type: str
    count: int
    private_or_local: bool
    common_benign: bool


class ExtractionResponse(BaseModel):
    iocs: list[ExtractedIOCResponse]
    truncated: bool
    message: str | None
    refanged: bool
    investigation_id: int


class IOCAnalysisRequest(BaseModel):
    value: str = Field(min_length=1, max_length=4096)
    type: str | None = None


class BulkIOCAnalysisRequest(BaseModel):
    iocs: list[IOCAnalysisRequest] = Field(min_length=1, max_length=500)


class IOCAnalysisResponse(BaseModel):
    value: str
    type: str
    status: str
    result: dict[str, Any] | None
    score: int | None
    error: str | None


class BulkIOCAnalysisResponse(BaseModel):
    items: list[IOCAnalysisResponse]
    investigation_id: int

