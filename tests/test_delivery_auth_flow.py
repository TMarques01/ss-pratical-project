import os
import requests
import re

BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")


def _url(path: str) -> str:
    return BASE_URL.rstrip("/") + "/" + path.lstrip("/")


def test_login_logout_flow():
    """
    Delivery-stage integration test.

    Verifies the authentication flow against a running deployment:
    1. Login with valid credentials
    2. Access a protected page
    3. Logout
    4. Verify access is revoked
    """

    session = requests.Session()
    session.verify = False

# ------------------------------------------------------------
# Login
# ------------------------------------------------------------
    login_page = session.get(
        _url("/login"),
        timeout=10,
        verify=False,
    )

    csrf_token = re.search(
        r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"',
        login_page.text
    ).group(1)

    login_resp = session.post(
        _url("/login"),
        data={
            "username": "alice",
            "password": "tth1mJj5?£58",
            "csrf_token": csrf_token,
        },
        allow_redirects=False,
        timeout=10,
    )

    assert login_resp.status_code in (302, 303), (
        f"Login failed unexpectedly: {login_resp.status_code}"
    )

    # ------------------------------------------------------------
    # Access protected page
    # ------------------------------------------------------------
    documents_resp = session.get(
        _url("/documents"),
        allow_redirects=False,
        timeout=10,
    )

    assert documents_resp.status_code == 200, (
        "Authenticated user cannot access /documents"
    )

    # ------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------
    logout_resp = session.get(
        _url("/logout"),
        allow_redirects=False,
        timeout=10,
    )

    assert logout_resp.status_code in (302, 303), (
        f"Logout failed unexpectedly: {logout_resp.status_code}"
    )

    # ------------------------------------------------------------
    # Verify session is invalidated
    # ------------------------------------------------------------
    after_logout = session.get(
        _url("/documents"),
        allow_redirects=False,
        timeout=10,
    )

    assert after_logout.status_code in (302, 303), (
        "Protected page still accessible after logout"
    )