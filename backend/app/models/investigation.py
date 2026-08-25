from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        Index("ix_investigations_target", "target"),
        Index("ix_investigations_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(4096), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    iocs: Mapped[list["IOC"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
    )
    threat_results: Mapped[list["ThreatResult"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
    )
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
    )


from app.models.ioc import IOC  # noqa: E402
from app.models.risk_assessment import RiskAssessment  # noqa: E402
from app.models.threat_result import ThreatResult  # noqa: E402

