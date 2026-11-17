from getpass import getpass
from uuid import uuid4

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy.exc import IntegrityError

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
    password = getpass("Password (minimum 12 characters): ")
    confirmation = getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    session = get_session_factory()()
    try:
        if session.query(User).filter(User.email == email).one_or_none() is not None:
            raise SystemExit("That email already exists.")
        session.add(
            User(
                id=uuid4(),
                email=email,
                password_hash=hash_password(password),
                role=UserRole.ADMINISTRATOR.value,
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
