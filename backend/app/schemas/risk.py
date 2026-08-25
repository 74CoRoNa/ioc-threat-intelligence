from pydantic import BaseModel, ConfigDict


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: str
    key: str
    weight: int
    description: str
    confidence: str


class RiskAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    score: int
    severity: str
    verdict: str
    evidence: list[EvidenceResponse]
    confidence: str
    sources_available: int
    sources_expected: int
    statement: str
    correlation: str
