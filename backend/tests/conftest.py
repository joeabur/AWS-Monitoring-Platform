import os
from collections.abc import Generator

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-characters")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import hash_password
from app.database import get_db
from app.main import app
from app.models import User
from app.models.user import Base


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = test_session()
    session.add_all(
        [
            User(
                email="admin@example.com",
                password_hash=hash_password("correct-horse-battery"),
                role="administrator",
            ),
            User(
                email="analyst@example.com",
                password_hash=hash_password("correct-horse-battery"),
                role="security_analyst",
            ),
            User(
                email="viewer@example.com",
                password_hash=hash_password("correct-horse-battery"),
                role="read_only_viewer",
            ),
        ]
    )
    session.commit()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
