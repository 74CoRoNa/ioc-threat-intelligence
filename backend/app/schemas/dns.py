from typing import TypeAlias

from pydantic import BaseModel, ConfigDict, Field


DNSRecordValue: TypeAlias = str | dict[str, str | int]


class DNSRequest(BaseModel):
    target: str = Field(min_length=1, max_length=256, examples=["example.com"])


class DNSRecordSetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: str
    records: list[DNSRecordValue]
    message: str | None


class DNSAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    target: str
    records: dict[str, DNSRecordSetResponse]


class DNSLookupResponse(DNSAnalysisResponse):
    investigation_id: int
