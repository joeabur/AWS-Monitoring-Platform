import argparse
import json
import secrets
from uuid import uuid4

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.security import hash_password
from app.database import get_session_factory
from app.models import User
from app.schemas.auth import UserRole


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision an application role for an existing Cognito user."
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--cognito-sub", required=True)
    parser.add_argument("--role", required=True, choices=[role.value for role in UserRole])
    arguments = parser.parse_args()

    if get_settings().auth_provider != "cognito":
        raise SystemExit("Set AUTH_PROVIDER=cognito before provisioning Cognito users.")
    try:
        email = TypeAdapter(EmailStr).validate_python(arguments.email).lower()
    except ValidationError as exc:
        raise SystemExit("Enter a valid email address.") from exc
    cognito_sub = arguments.cognito_sub.strip()
    if not cognito_sub or len(cognito_sub) > 128:
        raise SystemExit("Enter a valid Cognito user sub.")

    session = get_session_factory()()
    try:
        existing = session.scalar(
            select(User).where((User.email == email) | (User.cognito_sub == cognito_sub))
        )
        if existing is not None:
            raise SystemExit("The email or Cognito subject is already provisioned.")
        session.add(
            User(
                id=uuid4(),
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(48)),
                role=arguments.role,
                cognito_sub=cognito_sub,
            )
        )
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise SystemExit("Database rejected the Cognito user record.") from exc
    finally:
        session.close()

    print(json.dumps({"email": email, "role": arguments.role, "provisioned": True}))


if __name__ == "__main__":
    main()
