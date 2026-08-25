from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base, create_database_engine
from app.core.exceptions import NotFound
from app.models import IOC, Investigation, RiskAssessment, ThreatResult
from app.services.investigation_service import InvestigationService


@pytest.fixture
def session(tmp_path: Path) -> Session:
    engine = create_database_engine(str(tmp_path / "investigations.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as database_session:
        yield database_session
    engine.dispose()


def test_write_read_and_json_round_trip(session: Session) -> None:
    service = InvestigationService(session)
    stored = service.record(
        target="8.8.8.8",
        target_type="ip",
        raw_result={"address": "8.8.8.8", "flags": ["public"], "nested": {"ok": True}},
        duration_ms=17,
    )

    loaded = service.get(stored.id)

    assert loaded.target == "8.8.8.8"
    assert loaded.duration_ms == 17
    assert loaded.raw_result == {
        "address": "8.8.8.8",
        "flags": ["public"],
        "nested": {"ok": True},
    }


def test_delete_cascades_to_all_child_tables(session: Session) -> None:
    service = InvestigationService(session)
    stored = service.record(
        target="example.com",
        target_type="domain",
        raw_result={"domain": "example.com"},
        iocs=[{"ioc_value": "example.com", "ioc_type": "domain"}],
        threat_results=[
            {
                "source": "test-provider",
                "status": "ok",
                "raw_response": {"score": 1},
            }
        ],
        risk_assessment={"score": 10, "verdict": "LOW", "evidence": []},
    )

    service.delete(stored.id)

    assert session.scalar(select(func.count(Investigation.id))) == 0
    assert session.scalar(select(func.count(IOC.id))) == 0
    assert session.scalar(select(func.count(ThreatResult.id))) == 0
    assert session.scalar(select(func.count(RiskAssessment.id))) == 0
    with pytest.raises(NotFound):
        service.get(stored.id)


def test_pagination_boundaries(session: Session) -> None:
    service = InvestigationService(session)
    for index in range(5):
        service.record(
            target=f"192.0.2.{index + 1}",
            target_type="ip",
            raw_result={"index": index},
        )

    first, total, pages = service.list(page=1, page_size=2)
    third, third_total, third_pages = service.list(page=3, page_size=2)
    beyond, _, _ = service.list(page=4, page_size=2)

    assert len(first) == 2
    assert len(third) == 1
    assert beyond == []
    assert total == third_total == 5
    assert pages == third_pages == 3


def test_filters_search_type_verdict_and_date(session: Session) -> None:
    service = InvestigationService(session)
    older = service.record(
        target="old.example.com",
        target_type="domain",
        raw_result={},
        risk_assessment={"score": 10, "verdict": "LOW", "evidence": []},
    )
    older.created_at = datetime.now(timezone.utc) - timedelta(days=10)
    session.commit()
    service.record(
        target="suspicious.example.com",
        target_type="domain",
        raw_result={},
        risk_assessment={"score": 80, "verdict": "CRITICAL", "evidence": []},
    )
    service.record(target="8.8.8.8", target_type="ip", raw_result={})

    domain_items, _, _ = service.list(target_type="domain")
    search_items, _, _ = service.list(search="suspicious")
    critical_items, _, _ = service.list(verdict="critical")
    recent_items, _, _ = service.list(
        date_from=datetime.now(timezone.utc) - timedelta(days=1)
    )

    assert len(domain_items) == 2
    assert [item.target for item in search_items] == ["suspicious.example.com"]
    assert [item.target for item in critical_items] == ["suspicious.example.com"]
    assert {item.target for item in recent_items} == {
        "suspicious.example.com",
        "8.8.8.8",
    }


def test_delete_missing_investigation_is_not_found(session: Session) -> None:
    with pytest.raises(NotFound):
        InvestigationService(session).delete(999)


def test_file_database_survives_engine_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "restart.db"
    first_engine = create_database_engine(str(database_path))
    Base.metadata.create_all(first_engine)
    first_factory = sessionmaker(bind=first_engine, expire_on_commit=False)
    with first_factory() as first_session:
        investigation_id = InvestigationService(first_session).record(
            target="2001:db8::1",
            target_type="ip",
            raw_result={"version": 6},
        ).id
    first_engine.dispose()

    second_engine = create_database_engine(str(database_path))
    second_factory = sessionmaker(bind=second_engine, expire_on_commit=False)
    with second_factory() as second_session:
        restored = InvestigationService(second_session).get(investigation_id)
        assert restored.target == "2001:db8::1"
        assert restored.raw_result == {"version": 6}
    second_engine.dispose()
