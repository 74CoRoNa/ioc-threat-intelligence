from time import perf_counter
from typing import Any

from sqlalchemy.orm import Session

from app.services.investigation_service import InvestigationService


def elapsed_ms(started_at: float) -> int:
    return max(0, round((perf_counter() - started_at) * 1000))


def record_analysis(
    session: Session,
    *,
    target: str,
    target_type: str,
    result: Any,
    started_at: float,
) -> int:
    provider_results = getattr(result, "threat_intelligence", {}) or {}
    stored_provider_results = [
        {
            "source": provider.source,
            "status": provider.status,
            "raw_response": {
                "data": provider.data,
                "message": provider.message,
                "external_url": provider.external_url,
                "cached": provider.cached,
            },
        }
        for provider in provider_results.values()
    ]
    risk = getattr(result, "risk_assessment", None)
    stored_risk = (
        {
            "score": risk.score,
            "verdict": risk.verdict,
            "evidence": [
                {
                    "source": item.source,
                    "key": item.key,
                    "weight": item.weight,
                    "description": item.description,
                    "confidence": item.confidence,
                }
                for item in risk.evidence
            ],
        }
        if risk is not None
        else None
    )
    investigation = InvestigationService(session).record(
        target=target,
        target_type=target_type,
        raw_result=result,
        duration_ms=elapsed_ms(started_at),
        threat_results=stored_provider_results,
        risk_assessment=stored_risk,
    )
    return investigation.id

def stored_intelligence(result: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Shape an already-encoded analysis result for storage.

    The IOC endpoints hand back plain dictionaries rather than dataclasses, so
    the provider and risk records are read by key instead of by attribute.
    """

    if not isinstance(result, dict):
        return [], None

    providers = result.get("threat_intelligence")
    stored_providers: list[dict[str, Any]] = []
    if isinstance(providers, dict):
        for provider in providers.values():
            if not isinstance(provider, dict):
                continue
            stored_providers.append(
                {
                    "source": provider.get("source", "unknown"),
                    "status": provider.get("status", "unknown"),
                    "raw_response": {
                        "data": provider.get("data"),
                        "message": provider.get("message"),
                        "external_url": provider.get("external_url"),
                        "cached": provider.get("cached", False),
                    },
                }
            )

    risk = result.get("risk_assessment")
    stored_risk = None
    if isinstance(risk, dict) and risk.get("score") is not None:
        stored_risk = {
            "score": risk["score"],
            "verdict": risk.get("verdict", "Unknown"),
            "evidence": [
                {
                    "source": item.get("source"),
                    "key": item.get("key"),
                    "weight": item.get("weight"),
                    "description": item.get("description"),
                    "confidence": item.get("confidence"),
                }
                for item in risk.get("evidence", [])
                if isinstance(item, dict)
            ],
        }
    return stored_providers, stored_risk
