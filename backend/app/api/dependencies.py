from collections.abc import Callable
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decode_access_token, decode_cognito_access_token
from app.database import get_db
from app.models import User
from app.schemas.auth import UserRole

bearer_scheme = HTTPBearer(auto_error=False)
Database = Annotated[Session, Depends(get_db)]


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Database,
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        if get_settings().auth_provider == "cognito":
            cognito_sub = decode_cognito_access_token(credentials.credentials)
            user = db.scalar(select(User).where(User.cognito_sub == cognito_sub))
        else:
            user_id: UUID = decode_access_token(credentials.credentials)
            user = db.get(User, user_id)
    except (jwt.PyJWTError, ValueError):
        raise unauthorized from None

    if user is None or not user.is_active:
        raise unauthorized
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: UserRole) -> Callable[..., User]:
    def role_dependency(user: CurrentUser) -> User:
        if user.role not in {role.value for role in roles}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return role_dependency
