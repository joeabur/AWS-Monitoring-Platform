from datetime import UTC, datetime, timedelta
from functools import lru_cache
from uuid import UUID

import jwt
from jwt import PyJWKClient
from pwdlib import PasswordHash

from app.core.config import get_settings

password_hash = PasswordHash.recommended()
ALGORITHM = "HS256"
DUMMY_PASSWORD_HASH = password_hash.hash("not-a-real-password")


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(user_id: UUID) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=settings.jwt_expire_minutes)
    return jwt.encode(
        {"sub": str(user_id), "iat": now, "exp": expires_at},
        settings.require_jwt_secret(),
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str) -> UUID:
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.require_jwt_secret(),
        algorithms=[ALGORITHM],
        options={"require": ["sub", "exp"]},
    )
    return UUID(payload["sub"])


@lru_cache(maxsize=4)
def _cognito_jwks_client(issuer: str) -> PyJWKClient:
    return PyJWKClient(
        f"{issuer}/.well-known/jwks.json",
        cache_keys=True,
        timeout=5,
    )


def decode_cognito_access_token(token: str) -> str:
    settings = get_settings()
    issuer = settings.cognito_issuer
    client_id = settings.cognito_client_id
    if issuer is None or client_id is None:
        raise ValueError("Cognito authentication is not configured")

    signing_key = _cognito_jwks_client(issuer).get_signing_key_from_jwt(token)
    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=issuer,
        options={
            "require": ["sub", "exp", "iss", "token_use", "client_id"],
            "verify_aud": False,
        },
    )
    if payload.get("token_use") != "access" or payload.get("client_id") != client_id:
        raise jwt.InvalidTokenError("Cognito access token claims do not match this application")
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject or len(subject) > 128:
        raise jwt.InvalidTokenError("Cognito token subject is invalid")
    return subject
