from collections.abc import Generator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import REPOSITORY_ROOT, get_settings


class Base(DeclarativeBase):
    pass


def _database_url(db_path: str) -> tuple[str, bool]:
    if db_path == ":memory:":
        return "sqlite+pysqlite://", True
    path = Path(db_path)
    if not path.is_absolute():
        path = REPOSITORY_ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+pysqlite:///{path.resolve().as_posix()}", False


def create_database_engine(db_path: str) -> Engine:
    """Create a SQLite engine with foreign-key enforcement enabled."""

    url, in_memory = _database_url(db_path)
    options: dict[str, object] = {
        "connect_args": {"check_same_thread": False},
    }
    if in_memory:
        options["poolclass"] = StaticPool
    engine = create_engine(url, **options)

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection: object, _: object) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


engine = create_database_engine(get_settings().db_path)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def initialize_database(target_engine: Engine = engine) -> None:
    """Create the current application schema if it does not exist."""

    from app import models  # noqa: F401

    Base.metadata.create_all(bind=target_engine)


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

