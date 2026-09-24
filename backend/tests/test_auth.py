import pytest


@pytest.mark.asyncio
async def test_user_registration_and_login(client):
    email = f"analyst_test_{pytest_random_suffix()}@phishguard.ai"
    password = "SecurePassword123!"

    # 1. Register new user
    reg_payload = {
        "email": email,
        "password": password,
        "full_name": "Test Security Analyst",
        "role": "user"
    }
    res_reg = await client.post("/api/v1/auth/register", json=reg_payload)
    assert res_reg.status_code == 201
    data_reg = res_reg.json()
    assert "access_token" in data_reg
    assert data_reg["user"]["email"] == email.lower()
    assert data_reg["user"]["role"] == "user"

    token = data_reg["access_token"]

    # 2. Check /auth/me
    res_me = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_me.status_code == 200
    data_me = res_me.json()
    assert data_me["email"] == email.lower()

    # 3. Duplicate registration should return 409 Conflict
    res_dup = await client.post("/api/v1/auth/register", json=reg_payload)
    assert res_dup.status_code == 409

    # 4. Short password should return 400 Bad Request
    res_short = await client.post(
        "/api/v1/auth/register",
        json={"email": "short@test.com", "password": "short"}
    )
    assert res_short.status_code in [400, 422]

    # 5. Login with correct credentials
    res_login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password}
    )
    assert res_login.status_code == 200
    assert "access_token" in res_login.json()

    # 6. Login with wrong password
    res_wrong = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword!"}
    )
    assert res_wrong.status_code == 401


@pytest.mark.asyncio
async def test_admin_rbac_protection(client):
    # Register regular user
    user_email = f"user_{pytest_random_suffix()}@phishguard.ai"
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"email": user_email, "password": "UserPass123!", "role": "user"}
    )
    user_token = reg_res.json()["access_token"]

    # Attempt to access admin routes with regular user token -> 403 Forbidden
    res_admin_users = await client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_admin_users.status_code == 403

    # Register or login as Admin
    admin_email = f"admin_{pytest_random_suffix()}@phishguard.ai"
    reg_admin = await client.post(
        "/api/v1/auth/register",
        json={"email": admin_email, "password": "AdminPass123!", "role": "admin"}
    )
    admin_token = reg_admin.json()["access_token"]

    # Access admin routes with admin token -> 200 OK
    res_admin_ok = await client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_admin_ok.status_code == 200
    assert isinstance(res_admin_ok.json(), list)


def pytest_random_suffix():
    import uuid
    return str(uuid.uuid4())[:8]
