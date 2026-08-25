from pydantic import BaseModel, ConfigDict, Field

from app.schemas.subnet import SubnetResponse
from app.schemas.threat import ProviderResultResponse
from app.schemas.risk import RiskAssessmentResponse


class IPAnalysisRequest(BaseModel):
    ip: str = Field(
        min_length=1,
        max_length=256,
        examples=["8.8.8.8", "192.168.10.25/24", "2001:db8::1/64"],
    )


class IPClassificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    public: bool
    private: bool
    loopback: bool
    link_local: bool
    multicast: bool
    reserved: bool
    unspecified: bool
    cgnat: bool
    documentation: bool


class LegacyClassResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    value: str | None
    legacy_only: bool
    note: str


class IPAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    input: str
    ip_address: str
    version: int
    classification: IPClassificationResponse
    legacy_class: LegacyClassResponse | None
    network: SubnetResponse
    reverse_dns: str | None
    country: str | None
    asn: str | None
    isp: str | None
    enrichment: str
    investigation_id: int | None = None
    threat_intelligence: dict[str, ProviderResultResponse] = Field(default_factory=dict)
    risk_assessment: RiskAssessmentResponse | None = None
