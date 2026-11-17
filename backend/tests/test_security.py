from uuid import uuid4

import pytest
from jwt.exceptions import InvalidTokenError

from app.core.config import Settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_hash_verifies_only_correct_password() -> None:
    password_hash = hash_password("a-long-test-password")

    assert password_hash != "a-long-test-password"
    assert verify_password("a-long-test-password", password_hash)
    assert not verify_password("another-password", password_hash)


def test_access_token_round_trips_user_id() -> None:
    user_id = uuid4()

    assert decode_access_token(create_access_token(user_id)) == user_id


def test_access_token_rejects_tampering() -> None:
    token = create_access_token(uuid4()) + "tampered"

    with pytest.raises(InvalidTokenError):
        decode_access_token(token)


def test_production_settings_require_postgresql_and_exact_https_origins() -> None:
    common = {
        "environment": "production",
        "jwt_secret_key": "test-secret-key-with-at-least-32-characters",
    }

    with pytest.raises(ValueError, match="PostgreSQL"):
        Settings(**common, database_url="sqlite:///./monitoring.db")

    with pytest.raises(ValueError, match="sslmode"):
        Settings(
            **common,
            database_url="postgresql+psycopg://monitor:secret@db.example.com/monitoring",
            cors_origins="https://monitor.example.com",
        )

    for origin in (
        "http://monitor.example.com",
        "https://monitor.example.com/path",
        "https://localhost",
        "https://127.0.0.1",
        "*",
    ):
        with pytest.raises(ValueError, match="HTTPS"):
            Settings(
                **common,
                database_url=(
                    "postgresql+psycopg://monitor:secret@db.example.com/monitoring"
                    "?sslmode=verify-full"
                ),
                cors_origins=origin,
            )

    settings = Settings(
        **common,
        database_url=(
            "postgresql+psycopg://monitor:secret@db.example.com/monitoring?sslmode=verify-full"
        ),
        cors_origins="https://monitor.example.com",
    )
    assert settings.allowed_origins == ["https://monitor.example.com"]
