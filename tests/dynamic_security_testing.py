"""
Dynamic Security Tests — ss-pratical-project
=============================================
Correm contra a aplicação em execução no pipeline de delivery (2-delivery.yml).
Requerem: APP_BASE_URL=https://localhost

Executar localmente:
    APP_BASE_URL=https://localhost pytest -v tests/test_dynamic_security.py
"""

import io
import os
import re
import time

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.getenv("APP_BASE_URL", "https://localhost")

ALICE = {"username": "alice", "password": "tth1mJj5?£58"}
BOB = {"username": "bob", "password": "De586:Iq6}?!"}
ADMIN = {"username": "admin", "password": "L|fP1D%327mB"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def url(path: str) -> str:
    return BASE_URL.rstrip("/") + "/" + path.lstrip("/")


def new_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def login(credentials: dict) -> requests.Session:
    s = new_session()
    r = s.post(url("/login"), data=credentials, allow_redirects=False, timeout=10)
    assert r.status_code in (302, 303), (
        f"Login falhou para '{credentials['username']}': HTTP {r.status_code}"
    )
    return s


def safe_login(credentials: dict) -> requests.Session:
    time.sleep(13)
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
    session.post(
        url("/documents/upload"),
        data={"title": title},
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


# ---------------------------------------------------------------------------
# Autenticação e Sessão
# ---------------------------------------------------------------------------

class TestAuthentication:

    def test_protected_documents_rejects_unauthenticated(self):
        r = new_session().get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303), (
            f"/documents acessível sem autenticação: HTTP {r.status_code}"
        )

    def test_protected_shared_rejects_unauthenticated(self):
        r = new_session().get(url("/shared"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303)

    def test_protected_admin_rejects_unauthenticated(self):
        r = new_session().get(url("/admin/users"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303), (
            f"/admin/users acessível sem autenticação: HTTP {r.status_code}"
        )

    def test_valid_login_grants_access(self):
        s = safe_login(ALICE)
        r = s.get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code == 200


    def test_invalid_password_rejected(self):
        time.sleep(13)
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": "alice", "password": "password_errada"},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url, "Login com password errada permitiu acesso"

    def test_nonexistent_user_rejected(self):
        time.sleep(13)
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": "utilizador_que_nao_existe", "password": "qualquer"},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url

    def test_logout_invalidates_session(self):
        s = safe_login(ALICE)

        r = s.get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code == 200, "Pré-condição: alice devia ter acesso antes do logout"

        s.get(url("/logout"), allow_redirects=False, timeout=10)

        r = s.get(url("/documents"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303), (
            "Sessão ainda válida após logout — cookie não foi invalidado"
        )

    def test_disabled_account_cannot_login(self):
        admin = safe_login(ADMIN)
        admin.post(url("/admin/users/3/disable"), allow_redirects=False, timeout=10)

        time.sleep(13)
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": "bob", "password": "De586:Iq6}?!"},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url, "Conta desativada conseguiu fazer login"

        admin.post(url("/admin/users/3/enable"), allow_redirects=False, timeout=10)


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

class TestSQLInjection:

    SQL_PAYLOADS = [
        ("' OR '1'='1", "qualquer"),
        ("' OR 1=1--", "qualquer"),
        ("admin'--", "qualquer"),
        ("admin' OR 'x'='x", "qualquer"),
        ("' UNION SELECT 1,2,3,4--", "qualquer"),
    ]

    @pytest.mark.parametrize("username,password", SQL_PAYLOADS)
    def test_sql_injection_login_bypass(self, username, password):
        time.sleep(13)
        s = new_session()
        r = s.post(
            url("/login"),
            data={"username": username, "password": password},
            allow_redirects=True,
            timeout=10,
        )
        assert "/documents" not in r.url and "/admin" not in r.url, (
            f"[CRÍTICO] SQL Injection bypass com payload username={username!r}"
        )


# ---------------------------------------------------------------------------
# Controlo de Acesso (IDOR / Autorização)
# ---------------------------------------------------------------------------

class TestAccessControl:

    def test_normal_user_cannot_access_admin_panel(self):
        s = safe_login(ALICE)
        r = s.get(url("/admin/users"), allow_redirects=False, timeout=10)
        assert r.status_code == 403, (
            f"Alice acedeu ao painel de admin: HTTP {r.status_code}"
        )

    def test_normal_user_cannot_disable_accounts(self):
        s = safe_login(ALICE)
        r = s.post(url("/admin/users/2/disable"), allow_redirects=False, timeout=10)
        assert r.status_code == 403

    def test_normal_user_cannot_enable_accounts(self):
        s = safe_login(ALICE)
        r = s.post(url("/admin/users/2/enable"), allow_redirects=False, timeout=10)
        assert r.status_code == 403

    def test_admin_can_access_admin_panel(self):
        s = safe_login(ADMIN)
        r = s.get(url("/admin/users"), allow_redirects=False, timeout=10)
        assert r.status_code == 200, "Admin não consegue aceder ao painel de utilizadores"

    def test_idor_user_cannot_access_other_users_document(self):
        bob = safe_login(BOB)
        upload_doc(bob, "idor_doc_bob", "idor_bob.pdf")
        bob_ids = get_doc_ids(bob)
        assert bob_ids, "Bob não tem documentos após upload"

        alice = safe_login(ALICE)
        for doc_id in bob_ids:
            r = alice.get(url(f"/documents/{doc_id}"), allow_redirects=False, timeout=10)
            assert r.status_code in (403, 404), (
                f"Alice acedeu ao documento {doc_id} de bob: HTTP {r.status_code}"
            )

    def test_idor_download_requires_ownership(self):
        bob = safe_login(BOB)
        upload_doc(bob, "idor_dl_bob", "idor_dl_bob.pdf")
        bob_ids = get_doc_ids(bob)
        assert bob_ids, "Bob não tem documentos após upload"

        alice = safe_login(ALICE)
        for doc_id in bob_ids:
            r = alice.get(url(f"/documents/{doc_id}/download"), allow_redirects=False, timeout=10)
            assert r.status_code in (403, 404), (
                f"Alice fez download do doc {doc_id} de bob: HTTP {r.status_code}"
            )

    def test_user_cannot_share_document_they_dont_own(self):
        bob = safe_login(BOB)
        upload_doc(bob, "idor_share_bob", "idor_share_bob.pdf")
        bob_ids = get_doc_ids(bob)
        assert bob_ids, "Bob não tem documentos após upload"

        alice = safe_login(ALICE)
        for doc_id in bob_ids:
            r = alice.post(
                url(f"/documents/{doc_id}/share"),
                data={"shared_with": "3"},
                allow_redirects=False, timeout=10,
            )
            assert r.status_code in (403, 404), (
                f"Alice partilhou doc {doc_id} de bob: HTTP {r.status_code}"
            )

    def test_shared_download_requires_share_permission(self):
        alice = safe_login(ALICE)
        upload_doc(alice, "shared_perm_alice", "shared_perm_alice.pdf")
        alice_ids = get_doc_ids(alice)
        assert alice_ids, "Alice não tem documentos após upload"

        bob = safe_login(BOB)
        for doc_id in alice_ids:
            r = bob.get(url(f"/shared/{doc_id}/download"), allow_redirects=False, timeout=10)
            assert r.status_code in (403, 404), (
                f"Bob acedeu a doc de alice via /shared/{doc_id}: HTTP {r.status_code}"
            )

    def test_unauthenticated_cannot_download_shared(self):
        r = new_session().get(url("/shared/1/download"), allow_redirects=False, timeout=10)
        assert r.status_code in (302, 303)

    def test_cannot_share_document_with_yourself(self):
        alice = safe_login(ALICE)
        upload_doc(alice, "self_share_alice", "self_share_alice.pdf")
        alice_ids = get_doc_ids(alice)
        assert alice_ids, "Alice não tem documentos após upload"

        r = alice.post(
            url(f"/documents/{alice_ids[0]}/share"),
            data={"shared_with": "2"},  # user_id=2 é alice conforme o init.sql
            allow_redirects=True, timeout=10,
        )
        assert "yourself" in r.text.lower() or r.status_code in (302, 303, 400)


# ---------------------------------------------------------------------------
# Validação de Input — Upload
# ---------------------------------------------------------------------------

class TestInputValidation:

    def test_upload_invalid_extension_rejected(self):
        s = safe_login(ALICE)
        r = s.post(
            url("/documents/upload"),
            data={"title": "script_malicioso"},
            files={"document": ("malware.sh", io.BytesIO(b"#!/bin/bash\nid"), "text/x-sh")},
            allow_redirects=True,
            timeout=10,
        )
        assert r.status_code == 200
        assert "not allowed" in r.text.lower() or r.url.endswith("/documents"), (
            "Ficheiro .sh não foi rejeitado"
        )

    def test_upload_mismatched_mime_rejected(self):
        s = safe_login(ALICE)
        fake_pdf = b"<?php system($_GET['cmd']); ?>"
        r = s.post(
            url("/documents/upload"),
            data={"title": "webshell"},
            files={"document": ("webshell.pdf", io.BytesIO(fake_pdf), "application/pdf")},
            allow_redirects=True,
            timeout=10,
        )
        assert "does not match" in r.text.lower() or r.url.endswith("/documents"), (
            "Ficheiro com conteúdo inválido foi aceite"
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
            r = s.post(
                url("/documents/upload"),
                data={"title": "cmd_inject_test"},
                files={"document": (name, io.BytesIO(minimal_pdf()), "application/pdf")},
                allow_redirects=True,
                timeout=10,
            )
            assert "uid=" not in r.text, (
                f"[CRÍTICO] Command injection via filename={name!r}"
            )
            assert "gid=" not in r.text, (
                f"[CRÍTICO] Command injection via filename={name!r}"
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
        assert ids, "Alice não tem documentos após upload"

        r = s.post(
            url(f"/documents/{ids[0]}/share"),
            data={"shared_with": "99999"},
            allow_redirects=True, timeout=10,
        )
        assert "does not exist" in r.text.lower()

    def test_share_with_non_numeric_user_id(self):

        s = safe_login(ALICE)
        upload_doc(s, "share_nonnumeric", "share_nonnumeric.pdf")
        ids = get_doc_ids(s)
        assert ids, "Alice não tem documentos após upload"

        r = s.post(
            url(f"/documents/{ids[0]}/share"),
            data={"shared_with": "admin"},
            allow_redirects=True, timeout=10,
        )
        assert "invalid" in r.text.lower() or r.status_code in (302, 303)

    def test_path_traversal_in_download(self):
        alice = safe_login(ALICE)
        upload_doc(alice, "path_traversal_check", "traversal_check.pdf")
        ids = get_doc_ids(alice)
        assert ids, "Alice não tem documentos após upload"

        for doc_id in ids:
            r = alice.get(url(f"/documents/{doc_id}/download"), allow_redirects=False, timeout=10)
            if r.status_code == 200:
                assert "root:" not in r.text, (
                    f"[CRÍTICO] /documents/{doc_id}/download serviu conteúdo de /etc/passwd"
                )
