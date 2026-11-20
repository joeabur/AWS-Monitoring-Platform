import time
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.exceptions import InvalidTokenError

from app.core.config import Settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    decode_cognito_access_token,
    hash_password,
    verify_password,
)
from app.database import resolve_database_url


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


def test_cognito_access_token_verifies_signature_issuer_client_and_token_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"
    client_id = "example-client"
    settings = Settings(
        auth_provider="cognito",
        cognito_issuer=issuer,
        cognito_client_id=client_id,
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr("app.core.security.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.core.security._cognito_jwks_client",
        lambda _: SimpleNamespace(
            get_signing_key_from_jwt=lambda _: SimpleNamespace(key=private_key.public_key())
        ),
    )
    payload = {
        "sub": "cognito-subject",
        "iss": issuer,
        "client_id": client_id,
        "token_use": "access",
        "exp": int(time.time()) + 60,
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")

    assert decode_cognito_access_token(token) == "cognito-subject"

    for claims in ({"client_id": "other-client"}, {"token_use": "id"}):
        invalid_token = jwt.encode({**payload, **claims}, private_key, algorithm="RS256")
        with pytest.raises(InvalidTokenError):
            decode_cognito_access_token(invalid_token)


def test_database_secret_is_resolved_without_losing_special_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SecretClient:
        def get_secret_value(self, *, SecretId: str) -> dict[str, str]:
            assert SecretId == "arn:aws:secretsmanager:us-east-1:123456789012:secret:db"
            return {"SecretString": '{"username":"monitor","password":"p@ss:/%word"}'}

    monkeypatch.setattr("app.database.boto3.client", lambda _: SecretClient())
    settings = Settings(
        database_host="postgres.internal",
        database_name="monitoring",
        database_password_secret_arn=("arn:aws:secretsmanager:us-east-1:123456789012:secret:db"),
    )

    from sqlalchemy.engine import make_url

    url = make_url(resolve_database_url(settings))

    assert url.password == "p@ss:/%word"
    assert url.query["sslmode"] == "verify-full"


def test_production_settings_require_postgresql_and_exact_https_origins() -> None:
    common = {
        "environment": "production",
        "auth_provider": "cognito",
        "cognito_issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
        "cognito_client_id": "example-client",
        "audit_archive_bucket": "monitoring-audit-archive",
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


def test_production_settings_accept_rds_managed_secret_connection() -> None:
    settings = Settings(
        environment="production",
        auth_provider="cognito",
        cognito_issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
        cognito_client_id="example-client",
        audit_archive_bucket="monitoring-audit-archive",
        database_host="postgres.internal",
        database_name="monitoring",
        database_password_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:db",
        cors_origins="https://monitor.example.com",
    )

    assert settings.database_host == "postgres.internal"


def test_evidence_retention_period_is_bounded_for_object_lock() -> None:
    with pytest.raises(ValueError, match="less than or equal to 36500"):
        Settings(evidence_retention_days=36501)
