from app.services.provider import ProviderResult
from app.services.risk_engine import Evidence, RiskEngine


def provider(name, data): return ProviderResult(name,"ok",data=data)


def test_three_source_agreement_scores_and_explains() -> None:
    providers={"virustotal":provider("virustotal",{"malicious":6,"suspicious":1}),"abuseipdb":provider("abuseipdb",{"abuse_confidence_score":82,"total_reports":47}),"threatfox":provider("threatfox",{"listed":True,"maximum_confidence":90})}
    risk=RiskEngine.from_providers(providers,expected_sources=3)
    assert risk.score==100 and risk.severity=="CRITICAL" and risk.verdict=="Confirmed Malicious"
    assert "3 independent" in risk.evidence[-1].description


def test_no_matches_is_not_safe_claim() -> None:
    providers={"virustotal":provider("virustotal",{"malicious":0,"suspicious":0}),"threatfox":provider("threatfox",{"listed":False})}
    risk=RiskEngine.from_providers(providers,expected_sources=2)
    assert risk.score==0 and risk.verdict=="No Known Threat Intelligence"
    assert "does not establish" in risk.correlation


def test_single_source_is_suspicious_not_confirmed() -> None:
    risk=RiskEngine.from_providers({"threatfox":provider("threatfox",{"listed":True,"maximum_confidence":90})},expected_sources=3)
    assert risk.verdict=="Suspicious" and risk.confidence=="low"


def test_evidence_deduplicates_and_caps() -> None:
    risk=RiskEngine.score_evidence([Evidence("a","same",70,"one","high"),Evidence("b","same",70,"two","high")])
    assert risk.score==70 and len(risk.evidence)==1
