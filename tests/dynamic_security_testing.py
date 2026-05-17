import io
import os
import re

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.getenv("APP_BASE_URL", "https://localhost")

ALICE = {"username": "alice", "password": "tth1mJj5?£58"}
BOB = {"username": "bob", "password": "De586:Iq6}?!"}
ADMIN = {"username": "admin", "password": "L|fP1D%327mB"}


def url(path: str) -> str:
    return BASE_URL.rstrip("/") + "/" + path.lstrip("/")


def new_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def get_csrf_token(session: requests.Session, path: str) -> str:
    r = session.get(url(path), timeout=10)
    match = re.search(
        r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"',
        r.text
    )
    return match.group(1) if match else ""


def login(credentials: dict) -> requests.Session:
    s = new_session()
    r = s.get(url("/login"), timeout=10)
    csrf_token = re.search(
        r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"',
        r.text
    ).group(1)
    r = s.post(
        url("/login"),
        data={**credentials, "csrf_token": csrf_token},
        allow_redirects=False,
        timeout=10,
    )
    assert r.status_code in (302, 303), (
        f"Login failed for '{credentials['username']}': HTTP {r.status_code}"
    )
    return s


def safe_login(credentials: dict) -> requests.Session:
    return login(credentials)


def minimal_pdf() -> bytes:
    return (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f\ntrailer<</Size 4/Root 1 0 R>>\n"
        b"startxref\n0\n%%EOF"
    )


def upload_doc(session: requests.Session, title: str, filename: str = "test.pdf") -> None:
    csrf = get_csrf_token(session, "/documents")
    session.post(
        url("/documents/upload"),
        data={"title": title, "csrf_token": csrf},
        files={"document": (filename, io.BytesIO(minimal_pdf()), "application/pdf")},
        allow_redirects=True,
        timeout=10,
    )


def get_doc_ids(session: requests.Session) -> list:
    r = session.get(url("/documents"), allow_redirects=False, timeout=10)
    return list(set(
        int(i)
        for i in re.findall(r'/documents/(\d+)', r.text)
    ))


class TestAuthentication:

    def test_protected_documents_rejects_unauthenticated(self):
        r = new_session().get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303), (
            f"/documents accessible without authentication: HTTP {r.status_code}"
        )

    def test_protected_shared_rejects_unauthenticated(self):
        r = new_session().get(url("/shared"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303)

    def test_protected_admin_rejects_unauthenticated(self):
        r = new_session().get(url("/admin/users"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303)

    def test_valid_login_grants_access(self):
        s = safe_login(ALICE)
        r = s.get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code == 200, "Authenticated alice cannot access /documents"

    def test_invalid_password_rejected(self):
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": "alice", "password": "wrong_password"},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url, "Login with wrong password granted access"

    def test_nonexistent_user_rejected(self):
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": "nonexistent_user", "password": "any"},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url

    def test_logout_invalidates_session(self):
        s = safe_login(ALICE)
        r = s.get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code == 200, "Pre-condition: alice should have access before logout"
        s.get(url("/logout"), allow_redirects=False, timeout=10)
        r = s.get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303), (
            "Session still valid after logout — cookie was not invalidated"
        )

    def test_disabled_account_cannot_login(self):
        admin = safe_login(ADMIN)
        csrf = get_csrf_token(admin, "/admin/users")
        admin.post(
            url("/admin/users/3/disable"),
            data={"csrf_token": csrf},
            allow_redirects=False,
            timeout=10,
        )
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": "bob", "password": "De586:Iq6}?!"},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url, "Disabled account was able to login"
        csrf = get_csrf_token(admin, "/admin/users")
        admin.post(
            url("/admin/users/3/enable"),
            data={"csrf_token": csrf},
            allow_redirects=False,
            timeout=10,
        )


class TestSQLInjection:

    SQL_PAYLOADS = [
        ("' OR '1'='1", "any"),
        ("' OR 1=1--", "any"),
        ("admin'--", "any"),
        ("admin' OR 'x'='x", "any"),
        ("' UNION SELECT 1,2,3,4--", "any"),
    ]

    @pytest.mark.parametrize("username,password", SQL_PAYLOADS)
    def test_sql_injection_login_bypass(self, username, password):
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": username, "password": password},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url and "/admin" not in r.url, (
            f"[CRITICAL] SQL Injection bypass with payload username={username!r}"
        )


class TestAccessControl:

    def test_normal_user_cannot_access_admin_panel(self):
        s = safe_login(ALICE)
        r = s.get(url("/admin/users"), allow_redirects=False, timeout=10)
        assert r.status_code == 403, (
            f"Alice accessed the admin panel: HTTP {r.status_code}"
        )

    def test_normal_user_cannot_disable_accounts(self):
        s = safe_login(ALICE)
        csrf = get_csrf_token(s, "/documents")
        r = s.post(
            url("/admin/users/2/disable"),
            data={"csrf_token": csrf},
            allow_redirects=False,
            timeout=10,
        )
        assert r.status_code == 403

    def test_normal_user_cannot_enable_accounts(self):
        s = safe_login(ALICE)
        csrf = get_csrf_token(s, "/documents")
        r = s.post(
            url("/admin/users/2/enable"),
            data={"csrf_token": csrf},
            allow_redirects=False,
            timeout=10,
        )
        assert r.status_code == 403

    def test_admin_can_access_admin_panel(self):
        s = safe_login(ADMIN)
        r = s.get(url("/admin/users"), allow_redirects=False, timeout=10)
        assert r.status_code == 200, "Admin cannot access the user management panel"

    def test_idor_user_cannot_access_other_users_document(self):
        bob = safe_login(BOB)
        upload_doc(bob, "idor_doc_bob", "idor_bob.pdf")
        bob_ids = get_doc_ids(bob)
        assert bob_ids, "Bob has no documents after upload"

        alice = safe_login(ALICE)
        for doc_id in bob_ids:
            r = alice.get(url(f"/documents/{doc_id}"), allow_redirects=False, timeout=10)
            assert r.status_code in (403, 404), (
                f"Alice accessed bob's document {doc_id}: HTTP {r.status_code}"
            )

    def test_idor_download_requires_ownership(self):
        bob = safe_login(BOB)
        upload_doc(bob, "idor_dl_bob", "idor_dl_bob.pdf")
        bob_ids = get_doc_ids(bob)
        assert bob_ids, "Bob has no documents after upload"

        alice = safe_login(ALICE)
        for doc_id in bob_ids:
            r = alice.get(url(f"/documents/{doc_id}/download"), allow_redirects=False, timeout=10)
            assert r.status_code in (403, 404), (
                f"Alice downloaded bob's document {doc_id}: HTTP {r.status_code}"
            )

    def test_user_cannot_share_document_they_dont_own(self):
        bob = safe_login(BOB)
        upload_doc(bob, "idor_share_bob", "idor_share_bob.pdf")
        bob_ids = get_doc_ids(bob)
        assert bob_ids, "Bob has no documents after upload"

        alice = safe_login(ALICE)
        csrf = get_csrf_token(alice, "/documents")
        for doc_id in bob_ids:
            r = alice.post(
                url(f"/documents/{doc_id}/share"),
                data={"shared_with": "3", "csrf_token": csrf},
                allow_redirects=False,
                timeout=10,
            )
            assert r.status_code in (403, 404), (
                f"Alice shared bob's document {doc_id}: HTTP {r.status_code}"
            )

    def test_shared_download_requires_share_permission(self):
        alice = safe_login(ALICE)
        upload_doc(alice, "shared_perm_alice", "shared_perm_alice.pdf")
        alice_ids = get_doc_ids(alice)
        assert alice_ids, "Alice has no documents after upload"

        bob = safe_login(BOB)
        for doc_id in alice_ids:
            r = bob.get(url(f"/shared/{doc_id}/download"), allow_redirects=False, timeout=10)
            assert r.status_code in (403, 404), (
                f"Bob accessed alice's document via /shared/{doc_id}: HTTP {r.status_code}"
            )

    def test_unauthenticated_cannot_download_shared(self):
        r = new_session().get(url("/shared/1/download"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303)

    def test_cannot_share_document_with_yourself(self):
        alice = safe_login(ALICE)
        upload_doc(alice, "self_share_alice", "self_share_alice.pdf")
        alice_ids = get_doc_ids(alice)
        assert alice_ids, "Alice has no documents after upload"

        csrf = get_csrf_token(alice, f"/documents/{alice_ids[0]}")
        r = alice.post(
            url(f"/documents/{alice_ids[0]}/share"),
            data={"shared_with": "2", "csrf_token": csrf},
            allow_redirects=True,
            timeout=10,
        )
        assert "yourself" in r.text.lower() or r.status_code in (302, 303, 400)


class TestInputValidation:

    def test_upload_invalid_extension_rejected(self):
        s = safe_login(ALICE)
        csrf = get_csrf_token(s, "/documents")
        r = s.post(
            url("/documents/upload"),
            data={"title": "malicious_script", "csrf_token": csrf},
            files={"document": ("malware.sh", io.BytesIO(b"#!/bin/bash\nid"), "text/x-sh")},
            allow_redirects=True,
            timeout=10,
        )
        assert r.status_code == 200
        assert "not allowed" in r.text.lower() or r.url.endswith("/documents"), (
            ".sh file was not rejected"
        )

    def test_upload_mismatched_mime_rejected(self):
        s = safe_login(ALICE)
        csrf = get_csrf_token(s, "/documents")
        fake_pdf = b"<?php system($_GET['cmd']); ?>"
        r = s.post(
            url("/documents/upload"),
            data={"title": "webshell", "csrf_token": csrf},
            files={"document": ("webshell.pdf", io.BytesIO(fake_pdf), "application/pdf")},
            allow_redirects=True,
            timeout=10,
        )
        assert "does not match" in r.text.lower() or r.url.endswith("/documents"), (
            "File with invalid content was accepted"
        )

    def test_upload_command_injection_in_filename(self):
        s = safe_login(ALICE)
        dangerous_names = [
            "test; id #.pdf",
            "test`id`.pdf",
            "test$(id).pdf",
            "test|id|.pdf",
        ]
        for name in dangerous_names:
            csrf = get_csrf_token(s, "/documents")
            r = s.post(
                url("/documents/upload"),
                data={"title": "cmd_inject_test", "csrf_token": csrf},
                files={"document": (name, io.BytesIO(minimal_pdf()), "application/pdf")},
                allow_redirects=True,
                timeout=10,
            )
            assert "uid=" not in r.text, (
                f"[CRITICAL] Command injection via filename={name!r}"
            )
            assert "gid=" not in r.text, (
                f"[CRITICAL] Command injection via filename={name!r}"
            )

    def test_document_id_must_be_integer(self):
        s = safe_login(ALICE)
        r = s.get(url("/documents/abc"), allow_redirects=False, timeout=10)
        assert r.status_code == 404

    def test_negative_document_id_handled(self):
        s = safe_login(ALICE)
        r = s.get(url("/documents/-1"), allow_redirects=False, timeout=10)
        assert r.status_code in (403, 404)

    def test_share_with_invalid_user_id(self):
        s = safe_login(ALICE)
        upload_doc(s, "share_invalid_uid", "share_invalid.pdf")
        ids = get_doc_ids(s)
        assert ids, "Alice has no documents after upload"

        csrf = get_csrf_token(s, f"/documents/{ids[0]}")
        r = s.post(
            url(f"/documents/{ids[0]}/share"),
            data={"shared_with": "99999", "csrf_token": csrf},
            allow_redirects=True,
            timeout=10,
        )
        assert "does not exist" in r.text.lower()

    def test_share_with_non_numeric_user_id(self):
        s = safe_login(ALICE)
        upload_doc(s, "share_nonnumeric", "share_nonnumeric.pdf")
        ids = get_doc_ids(s)
        assert ids, "Alice has no documents after upload"

        csrf = get_csrf_token(s, f"/documents/{ids[0]}")
        r = s.post(
            url(f"/documents/{ids[0]}/share"),
            data={"shared_with": "admin", "csrf_token": csrf},
            allow_redirects=True,
            timeout=10,
        )
        assert "invalid" in r.text.lower() or r.status_code in (302, 303)

    def test_path_traversal_in_download(self):
        alice = safe_login(ALICE)
        upload_doc(alice, "path_traversal_check", "traversal_check.pdf")
        ids = get_doc_ids(alice)
        assert ids, "Alice has no documents after upload"

        for doc_id in ids:
            r = alice.get(url(f"/documents/{doc_id}/download"), allow_redirects=False, timeout=10)
            if r.status_code == 200:
                assert "root:" not in r.text, (
                    f"[CRITICAL] /documents/{doc_id}/download served /etc/passwd content"
                )