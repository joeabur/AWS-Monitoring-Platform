from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pwdlib.exceptions import UnknownHashError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.dependencies import CurrentUser, Database, require_roles
from app.core.config import get_settings
from app.core.security import DUMMY_PASSWORD_HASH, create_access_token, verify_password
from app.models import User
from app.schemas.auth import LoginRequest, TokenResponse, UserRead, UserRole

router = APIRouter(prefix="/api/v1")


@router.get("/health")
def health(db: Database) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "unhealthy", "database": "unavailable"},
        ) from exc
    return {"status": "healthy", "database": "healthy"}


@router.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/health/ready")
def readiness(db: Database) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "unready", "database": "unavailable"},
        ) from exc
    return {"status": "ready", "database": "healthy"}


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Database) -> TokenResponse:
    if get_settings().auth_provider != "local":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password login is disabled when Cognito authentication is configured",
        )
    user = db.query(User).filter(User.email == payload.email.lower()).one_or_none()
    password_hash = (
        user.password_hash
        if user is not None and user.password_hash is not None
        else DUMMY_PASSWORD_HASH
    )
    try:
        valid_password = verify_password(payload.password, password_hash)
    except UnknownHashError:
        valid_password = False
    if user is None or not valid_password or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    settings = get_settings()
    return TokenResponse(
        access_token=create_access_token(user.id),
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.get("/auth/me", response_model=UserRead)
def current_user(user: CurrentUser) -> User:
    return user


@router.get("/users", response_model=list[UserRead])
def list_users(
    user: Annotated[User, Depends(require_roles(UserRole.ADMINISTRATOR))],
    db: Database,
) -> list[User]:
    return db.query(User).order_by(User.email).all()
