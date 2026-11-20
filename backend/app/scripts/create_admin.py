import secrets
from getpass import getpass
from uuid import uuid4

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.security import hash_password
from app.database import get_session_factory
from app.models import User
from app.schemas.auth import UserRole


def main() -> None:
    try:
        email = (
            TypeAdapter(EmailStr).validate_python(input("Administrator email: ").strip()).lower()
        )
    except ValidationError as exc:
        raise SystemExit("Enter a valid email address.") from exc
    cognito_sub = None
    if get_settings().auth_provider == "cognito":
        cognito_sub = input("Cognito user sub: ").strip()
        if not cognito_sub or len(cognito_sub) > 128:
            raise SystemExit("Enter a valid Cognito user sub.")
        password_hash = hash_password(secrets.token_urlsafe(48))
    else:
        password = getpass("Password (minimum 12 characters): ")
        confirmation = getpass("Confirm password: ")
        if len(password) < 12:
            raise SystemExit("Password must be at least 12 characters.")
        if password != confirmation:
            raise SystemExit("Passwords do not match.")
        password_hash = hash_password(password)

    session = get_session_factory()()
    try:
        if session.query(User).filter(User.email == email).one_or_none() is not None:
            raise SystemExit("That email already exists.")
        session.add(
            User(
                id=uuid4(),
                email=email,
                password_hash=password_hash,
                role=UserRole.ADMINISTRATOR.value,
                cognito_sub=cognito_sub,
            )
        )
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise SystemExit("Database rejected the administrator record.") from exc
    finally:
        session.close()
    print(f"Administrator {email} created.")


if __name__ == "__main__":
    main()
