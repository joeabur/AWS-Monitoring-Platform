from uuid import uuid4

import pytest
from jwt.exceptions import InvalidTokenError

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
