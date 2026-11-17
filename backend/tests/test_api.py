def test_health_reports_database_status(client) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "database": "healthy"}


def test_login_rejects_unknown_user(client) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "not-a-real-password"},
    )

    assert response.status_code == 401


def test_login_rejects_passwords_over_the_configured_input_limit(client) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "x" * 1025},
    )

    assert response.status_code == 422


def test_login_rate_limit_is_applied_and_429_keeps_cors_headers(client) -> None:
    responses = [
        client.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://localhost:3000"},
            json={"email": "admin@example.com", "password": ""},
        )
        for _ in range(11)
    ]

    assert all(response.status_code == 422 for response in responses[:10])
    assert responses[10].status_code == 429
    assert responses[10].headers["retry-after"].isdigit()
    assert responses[10].headers["access-control-allow-origin"] == "http://localhost:3000"


def test_profile_requires_bearer_token(client) -> None:
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_user_can_login_and_read_own_profile(client) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 200
    token = response.json()["access_token"]
    profile = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert profile.status_code == 200
    assert profile.json()["role"] == "administrator"


def test_role_dependency_restricts_user_listing_to_administrators(client) -> None:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": "correct-horse-battery"},
    )
    response = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )

    assert response.status_code == 403


def test_administrator_can_list_users(client) -> None:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "correct-horse-battery"},
    )
    response = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )

    assert response.status_code == 200
    assert [user["role"] for user in response.json()] == [
        "administrator",
        "security_analyst",
        "read_only_viewer",
    ]
