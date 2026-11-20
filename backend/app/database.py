import json
from collections.abc import Generator
from functools import lru_cache
from typing import Any

import boto3
import psycopg
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings


def is_postgres_database(settings: object | None = None) -> bool:
    settings = settings or get_settings()
    database_url = getattr(settings, "database_url", "")
    return database_url.startswith(("postgresql://", "postgresql+psycopg://")) or bool(
        getattr(settings, "database_password_secret_arn", None)
        and getattr(settings, "database_host", None)
        and getattr(settings, "database_name", None)
    )


def _read_database_credentials(secrets: Any, secret_arn: str) -> tuple[str, str]:
    secret = secrets.get_secret_value(SecretId=secret_arn)
    secret_value = secret.get("SecretString")
    if not isinstance(secret_value, str):
        raise TypeError("Database secret must contain a SecretString")
    secret_data = json.loads(secret_value)
    if not isinstance(secret_data, dict):
        raise TypeError("Database secret must be a JSON object")
    username = secret_data.get("username")
    password = secret_data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise TypeError("Database secret must contain username and password")
    return username, password


def resolve_database_url(settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    if not settings.database_password_secret_arn:
        return settings.database_url
    if not settings.database_host or not settings.database_name:
        raise ValueError(
            "DATABASE_HOST and DATABASE_NAME are required with a database password secret"
        )
    username, password = _read_database_credentials(
        boto3.client("secretsmanager"),
        settings.database_password_secret_arn,
    )
    from sqlalchemy.engine import URL

    return URL.create(
        "postgresql+psycopg",
        username=username,
        password=password,
        host=settings.database_host,
        port=settings.database_port,
        database=settings.database_name,
        query={
            "sslmode": "verify-full",
            "sslrootcert": settings.database_sslrootcert,
        },
    ).render_as_string(hide_password=False)


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    settings = get_settings()
    if settings.database_password_secret_arn:
        if not settings.database_host or not settings.database_name:
            raise ValueError(
                "DATABASE_HOST and DATABASE_NAME are required with a database password secret"
            )
        secrets = boto3.client("secretsmanager")

        def connect() -> psycopg.Connection:
            username, password = _read_database_credentials(
                secrets, settings.database_password_secret_arn
            )
            return psycopg.connect(
                host=settings.database_host,
                port=settings.database_port,
                dbname=settings.database_name,
                user=username,
                password=password,
                sslmode="verify-full",
                sslrootcert=settings.database_sslrootcert,
                connect_timeout=5,
            )

        engine = create_engine("postgresql+psycopg://", pool_pre_ping=True, creator=connect)
        return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    url = settings.database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
