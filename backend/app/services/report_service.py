from datetime import timezone
from html import escape
from typing import Any

from app.models import Investigation


DISCLAIMER = (
    "CyberIP Analyzer is an educational Mini SOC Investigation and Threat "
    "Intelligence Tool, not a SIEM, EDR, IDS, or malware sandbox. Findings "
    "depend on the sources available at analysis time and must be validated "
    "before defensive action is taken."
)


class ReportService:
    """Build reproducible reports exclusively from stored investigation data."""

    @classmethod
    def build(cls, investigation: Investigation) -> dict[str, Any]:
        risk = (
            investigation.risk_assessments[-1]
            if investigation.risk_assessments
            else None
        )
        providers = [
            {
                "source": item.source,
                "status": item.status,
                "data": item.raw_response,
                "fetched_at": item.fetched_at,
            }
            for item in investigation.threat_results
        ]
        return {
            "report_title": "CyberIP Analyzer Investigation Report",
            "investigation_id": investigation.id,
            "target": investigation.target,
            "target_type": investigation.target_type,
            "timestamp": investigation.created_at,
            "status": investigation.status,
            "duration_ms": investigation.duration_ms,
            "analysis": investigation.raw_result,
            "iocs": [
                {"value": item.ioc_value, "type": item.ioc_type}
                for item in investigation.iocs
            ],
            "threat_intelligence": providers,
            "sources_consulted": [
                item["source"] for item in providers if item["status"] == "ok"
            ],
            "sources_unavailable": [
                {"source": item["source"], "status": item["status"]}
                for item in providers
                if item["status"] != "ok"
            ],
            "risk": (
                {
                    "score": risk.score,
                    "verdict": risk.verdict,
                    "evidence": risk.evidence,
                }
                if risk
                else None
            ),
            "recommendations": cls._recommendations(
                risk.verdict if risk else None,
                risk.evidence if risk else [],
            ),
            "disclaimer": DISCLAIMER,
        }

    @staticmethod
    def _recommendations(
        verdict: str | None,
        evidence: list[dict[str, Any]],
    ) -> list[str]:
        recommendations = [
            "Search firewall and proxy logs for the target.",
            "Pivot on the indicator in the SIEM and review related internal hosts.",
        ]
        if verdict in {"HIGH", "CRITICAL"}:
            recommendations.extend(
                [
                    "Review EDR alerts on systems that contacted the target.",
                    "Consider blocking the indicator after analyst validation.",
                ]
            )
        elif verdict == "MEDIUM":
            recommendations.append(
                "Increase monitoring and validate the strongest evidence before containment."
            )
        else:
            recommendations.append(
                "Retain the result for correlation and reassess if new evidence appears."
            )
        if any(item.get("source") == "dns" for item in evidence):
            recommendations.append("Review passive DNS and historical resolution data.")
        return recommendations

    @classmethod
    def to_markdown(cls, report: dict[str, Any]) -> str:
        risk = report["risk"] or {}
        lines = [
            f"# {report['report_title']}",
            "",
            f"- Investigation ID: {report['investigation_id']}",
            f"- Target: `{report['target']}`",
            f"- Target type: {report['target_type']}",
            f"- Timestamp: {report['timestamp'].astimezone(timezone.utc).isoformat()}",
            f"- Status: {report['status']}",
            "",
            "## Risk Assessment",
            "",
            f"- Score: {risk.get('score', 'Not scored')}",
            f"- Verdict: {risk.get('verdict', 'Not scored')}",
            "",
            "## Evidence",
            "",
        ]
        evidence = risk.get("evidence") or []
        lines.extend(
            f"- [{item.get('source', 'unknown')}] +{item.get('weight', 0)} — {item.get('description', '')}"
            for item in evidence
        )
        if not evidence:
            lines.append("- No scored evidence was stored.")
        lines.extend(["", "## Sources", ""])
        lines.append(
            "- Consulted: " + (", ".join(report["sources_consulted"]) or "None")
        )
        unavailable = report["sources_unavailable"]
        lines.append(
            "- Unavailable: "
            + (", ".join(f"{item['source']} ({item['status']})" for item in unavailable) or "None")
        )
        lines.extend(["", "## Defensive Recommendations", ""])
        lines.extend(f"- {item}" for item in report["recommendations"])
        lines.extend(["", "## Stored Analysis", "", "```json"])
        import json

        lines.append(json.dumps(report["analysis"], indent=2, ensure_ascii=False))
        lines.extend(["```", "", "## Limitations", "", report["disclaimer"]])
        return "\n".join(lines)

    @classmethod
    def to_html(cls, report: dict[str, Any]) -> str:
        markdown = cls.to_markdown(report)
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(report['report_title'])}</title>
<style>body{{font:16px/1.6 system-ui;max-width:900px;margin:40px auto;padding:0 24px;color:#14202a}}pre{{white-space:pre-wrap;background:#f3f6f8;padding:20px;border-radius:8px}}@media print{{body{{margin:0;max-width:none}}}}</style>
</head><body><h1>{escape(report['report_title'])}</h1><pre>{escape(markdown)}</pre></body></html>"""

