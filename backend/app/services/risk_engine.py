from dataclasses import dataclass, replace
from typing import Any, Iterable

from app.services.provider import ProviderResult


@dataclass(frozen=True, slots=True)
class Evidence:
    source: str
    key: str
    weight: int
    description: str
    confidence: str


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    severity: str
    verdict: str
    evidence: list[Evidence]
    confidence: str
    sources_available: int
    sources_expected: int
    statement: str
    correlation: str


class RiskEngine:
    """Correlate independent provider evidence without averaging or duplication."""

    @classmethod
    def assess_ip(cls, analysis: Any) -> RiskAssessment:
        return cls.from_providers(analysis.threat_intelligence or {}, expected_sources=4)

    @classmethod
    def assess_domain(cls, analysis: Any) -> RiskAssessment:
        return cls.from_providers(analysis.threat_intelligence or {}, expected_sources=3)

    @classmethod
    def assess_url(cls, analysis: Any) -> RiskAssessment:
        return cls.from_providers(analysis.threat_intelligence or {}, expected_sources=3)

    @classmethod
    def from_providers(cls, providers: dict[str, ProviderResult], *, expected_sources: int) -> RiskAssessment:
        evidence = cls._provider_evidence(providers)
        positives = cls._positive_sources(providers)
        if len(positives) >= 2:
            weight = min(5 * len(positives), 20)
            evidence.append(Evidence("correlation", "correlation:independent_agreement", weight, f"{len(positives)} independent providers reported risk evidence.", "high"))
        return cls.score_evidence(evidence, providers.values(), expected_sources=expected_sources, positive_sources=positives)

    @classmethod
    def score_evidence(cls, evidence: Iterable[Evidence], providers: Iterable[ProviderResult] = (), *, expected_sources: int = 0, force_low: bool = False, positive_sources: set[str] | None = None) -> RiskAssessment:
        provider_list = list(providers)
        deduplicated: list[Evidence] = []
        seen: set[str] = set()
        score = 0
        for item in evidence:
            if item.key in seen:
                continue
            seen.add(item.key)
            weight = 0 if force_low else min(max(item.weight, 0), 100 - score)
            deduplicated.append(replace(item, weight=weight) if weight != item.weight else item)
            score += weight
        available = sum(item.status == "ok" for item in provider_list)
        positives = positive_sources or set()
        severity = cls._severity(score)
        verdict = cls._verdict(score, available, positives, provider_list)
        correlation = cls._correlation(available, expected_sources, positives)
        confidence = "none" if available == 0 else "low" if available == 1 else "medium" if available < expected_sources else "high"
        return RiskAssessment(score, severity, verdict, deduplicated, confidence, available, expected_sources, f"{severity} risk — {verdict}.", correlation)

    @classmethod
    def _provider_evidence(cls, providers: dict[str, ProviderResult]) -> list[Evidence]:
        evidence: list[Evidence] = []
        vt = providers.get("virustotal")
        if vt and vt.status == "ok" and vt.data:
            malicious = int(vt.data.get("malicious", 0))
            suspicious = int(vt.data.get("suspicious", 0))
            malicious_weight = 65 if malicious >= 10 else 50 if malicious >= 5 else 35 if malicious >= 2 else 20 if malicious == 1 else 0
            if malicious_weight:
                evidence.append(Evidence("virustotal", "vt:malicious", malicious_weight, f"VirusTotal reported {malicious} malicious engine detection(s).", "high"))
            if suspicious:
                evidence.append(Evidence("virustotal", "vt:suspicious", min(suspicious * 3, 10), f"VirusTotal reported {suspicious} suspicious engine detection(s).", "medium"))
        abuse = providers.get("abuseipdb")
        if abuse and abuse.status == "ok" and abuse.data:
            confidence = int(abuse.data.get("abuse_confidence_score", 0))
            confidence_weight = 40 if confidence >= 75 else 30 if confidence >= 50 else 15 if confidence >= 25 else 0
            if confidence_weight:
                evidence.append(Evidence("abuseipdb", "abuse:confidence", confidence_weight, f"AbuseIPDB reported {confidence}% abuse confidence.", "high" if confidence >= 75 else "medium"))
            reports = int(abuse.data.get("total_reports", 0))
            if reports >= 10:
                evidence.append(Evidence("abuseipdb", "abuse:reports", 10 if reports >= 100 else 5, f"AbuseIPDB recorded {reports} report(s) in its query window.", "medium"))
        threatfox = providers.get("threatfox")
        if threatfox and threatfox.status == "ok" and threatfox.data and threatfox.data.get("listed"):
            evidence.append(Evidence("threatfox", "threatfox:match", 45, "ThreatFox matched the IOC to malware-associated intelligence.", "high"))
            confidence = int(threatfox.data.get("maximum_confidence", 0))
            if confidence >= 75:
                evidence.append(Evidence("threatfox", "threatfox:confidence", 5, f"ThreatFox match confidence reached {confidence}/100.", "high"))
        urlhaus = providers.get("urlhaus")
        if urlhaus and urlhaus.status == "ok" and urlhaus.data and urlhaus.data.get("listed"):
            evidence.append(Evidence("urlhaus", "urlhaus:match", 45, "URLhaus matched the IOC to known malware-distribution activity.", "high"))
            if int(urlhaus.data.get("online_url_count", 0)) > 0:
                evidence.append(Evidence("urlhaus", "urlhaus:online", 10, f"URLhaus lists {int(urlhaus.data['online_url_count'])} malware URL(s) still serving on this host.", "high"))
            elif str(urlhaus.data.get("url_status", "")).lower() == "online":
                evidence.append(Evidence("urlhaus", "urlhaus:online", 10, "URLhaus reports this URL as currently online.", "high"))
            if urlhaus.data.get("blacklists"):
                evidence.append(Evidence("urlhaus", "urlhaus:blacklist", 5, f"Listed on {', '.join(urlhaus.data['blacklists'])}.", "medium"))
        return evidence

    @staticmethod
    def _positive_sources(providers: dict[str, ProviderResult]) -> set[str]:
        positive: set[str] = set()
        vt = providers.get("virustotal")
        if vt and vt.status == "ok" and vt.data and (int(vt.data.get("malicious", 0)) > 0 or int(vt.data.get("suspicious", 0)) > 0): positive.add("virustotal")
        abuse = providers.get("abuseipdb")
        if abuse and abuse.status == "ok" and abuse.data and (int(abuse.data.get("abuse_confidence_score", 0)) >= 25 or int(abuse.data.get("total_reports", 0)) > 0): positive.add("abuseipdb")
        fox = providers.get("threatfox")
        if fox and fox.status == "ok" and fox.data and fox.data.get("listed"): positive.add("threatfox")
        haus = providers.get("urlhaus")
        if haus and haus.status == "ok" and haus.data and haus.data.get("listed"): positive.add("urlhaus")
        return positive

    @staticmethod
    def _severity(score: int) -> str:
        return "LOW" if score <= 20 else "MODERATE" if score <= 40 else "SUSPICIOUS" if score <= 60 else "HIGH" if score <= 80 else "CRITICAL"

    @staticmethod
    def _verdict(score: int, available: int, positives: set[str], providers: list[ProviderResult]) -> str:
        if available == 0:
            return "Analysis Error" if any(item.status in {"error", "timeout"} for item in providers) else "Insufficient Evidence"
        if not positives:
            return "No Known Threat Intelligence"
        if score >= 81 and len(positives) >= 2:
            return "Confirmed Malicious"
        if score >= 61:
            return "Highly Suspicious"
        return "Suspicious"

    @staticmethod
    def _correlation(available: int, expected: int, positives: set[str]) -> str:
        if available == 0:
            return "No provider returned usable intelligence; an assessment could not be established."
        if len(positives) >= 2:
            return f"Independent evidence agrees across {', '.join(sorted(positives))}, increasing confidence."
        if len(positives) == 1:
            return f"Only {next(iter(positives))} reported risk evidence; provider agreement is absent and the result requires validation."
        if available < expected:
            return "No queried source returned malicious intelligence, but one or more applicable providers were unavailable."
        return "No malicious intelligence was found by the queried providers. This does not establish that the IOC is safe."
