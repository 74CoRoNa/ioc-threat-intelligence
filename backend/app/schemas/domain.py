from pydantic import BaseModel, ConfigDict, Field

from app.schemas.dns import DNSAnalysisResponse
from app.schemas.ip import IPAnalysisResponse
from app.schemas.threat import ProviderResultResponse
from app.schemas.risk import RiskAssessmentResponse


class DomainRequest(BaseModel):
    target: str = Field(
        min_length=1,
        max_length=256,
        examples=["example.com", "münich.example"],
    )


class URLRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=4096,
        examples=["https://example.com/login?source=email"],
    )


class TargetRequest(BaseModel):
    target: str = Field(
        min_length=1,
        max_length=4096,
        examples=["8.8.8.8", "example.com", "https://example.com/login"],
    )


class DomainAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    input: str
    domain: str
    unicode_domain: str
    registered_domain: str
    subdomain: str | None
    punycode: bool
    dns: DNSAnalysisResponse
    investigation_id: int | None = None
    threat_intelligence: dict[str, ProviderResultResponse] = Field(default_factory=dict)
    risk_assessment: RiskAssessmentResponse | None = None


class URLFlagResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    description: str


class URLAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    input: str
    refanged: str
    scheme: str
    host: str
    port: int
    explicit_port: bool
    path: str
    query_parameters: list[dict[str, str]]
    fragment: str
    userinfo: str | None
    registered_domain: str | None
    subdomain: str | None
    host_is_ip: bool
    https: bool
    flags: list[URLFlagResponse]
    dns: DNSAnalysisResponse | None
    tls: None
    redirect_chain: None
    disabled_features: dict[str, str]
    investigation_id: int | None = None
    threat_intelligence: dict[str, ProviderResultResponse] = Field(default_factory=dict)
    risk_assessment: RiskAssessmentResponse | None = None


class TargetAnalysisResponse(BaseModel):
    target_type: str
    result: IPAnalysisResponse | DomainAnalysisResponse | URLAnalysisResponse
    investigation_id: int
