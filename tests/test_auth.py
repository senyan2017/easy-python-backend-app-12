"""
tests/test_auth.py – validation tests for auth routes.

Covers:
  • Input sanitization (empty, whitespace, missing fields)
  • Username / email / password validation rules
  • Duplicate username / email on register
  • Login with bad credentials
  • checkAuth with valid, invalid, and deleted-user tokens
  • updateProfile: missing user, duplicate username, empty/bad input
  • Unified error response shape ({"error": "..."})
"""

import json
from core.models.user import User
from werkzeug.security import generate_password_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json(resp):
    return resp.get_json()


def _register(client, username="bob", email="bob@example.com", password="Secret1"):
    return client.post("/register", data={
        "username": username,
        "email": email,
        "password": password,
    })


def _login(client, username="bob", password="Secret1"):
    return client.post("/login", data={
        "username": username,
        "password": password,
    })


# ===================================================================
# /register
# ===================================================================

class TestRegister:
    def test_register_success(self, client):
        resp = _register(client)
        assert resp.status_code == 201
        body = _json(resp)
        assert body.get("message")

    def test_error_response_has_error_key(self, client):
        """All error responses must use the unified {"error": ...} shape."""
        resp = _register(client, username="", email="x@y.com", password="Secret1")
        assert resp.status_code == 400
        body = _json(resp)
        assert "error" in body
        assert "msg" not in body

    # -- missing / empty / whitespace-only fields --------------------

    def test_missing_all_fields(self, client):
        resp = client.post("/register", data={})
        assert resp.status_code == 400

    def test_missing_password(self, client):
        resp = client.post("/register", data={
            "username": "bob", "email": "b@b.com"
        })
        assert resp.status_code == 400

    def test_empty_username(self, client):
        resp = _register(client, username="")
        assert resp.status_code == 400

    def test_whitespace_only_username(self, client):
        resp = _register(client, username="   ")
        assert resp.status_code == 400

    def test_empty_email(self, client):
        resp = _register(client, email="")
        assert resp.status_code == 400

    def test_whitespace_only_email(self, client):
        resp = _register(client, email="   ")
        assert resp.status_code == 400

    def test_empty_password(self, client):
        resp = _register(client, password="")
        assert resp.status_code == 400

    def test_whitespace_only_password(self, client):
        resp = _register(client, password="   ")
        assert resp.status_code == 400

    def test_leading_trailing_whitespace_stripped(self, client):
        """Username with surrounding whitespace should be stored stripped."""
        resp = _register(client, username="  bob  ", email="bob@example.com", password="Secret1")
        assert resp.status_code == 201
        user = User.find_one(username="bob")
        assert user is not None

    # -- validation rules -------------------------------------------

    def test_username_too_short(self, client):
        resp = _register(client, username="ab")
        assert resp.status_code == 400
        assert "at least" in _json(resp)["error"]

    def test_username_too_long(self, client):
        resp = _register(client, username="a" * 31)
        assert resp.status_code == 400

    def test_username_bad_characters(self, client):
        resp = _register(client, username="bob@!#")
        assert resp.status_code == 400

    def test_email_invalid_format(self, client):
        resp = _register(client, email="notanemail")
        assert resp.status_code == 400

    def test_email_no_at(self, client):
        resp = _register(client, email="foo.bar.com")
        assert resp.status_code == 400

    def test_password_too_short(self, client):
        resp = _register(client, password="12345")
        assert resp.status_code == 400
        assert "at least" in _json(resp)["error"]

    def test_password_stored_hashed(self, client):
        _register(client, username="charlie", email="c@c.com", password="MyPw123")
        user = User.find_one(username="charlie")
        assert user is not None
        assert user.password.startswith("pbkdf2:sha256")

    # -- duplicates --------------------------------------------------

    def test_duplicate_username(self, client):
        _register(client, username="dupe", email="a@a.com", password="Secret1")
        resp = _register(client, username="dupe", email="b@b.com", password="Secret1")
        assert resp.status_code == 400
        assert "username" in _json(resp)["error"].lower()

    def test_duplicate_email(self, client):
        _register(client, username="user_one", email="same@a.com", password="Secret1")
        resp = _register(client, username="user_two", email="same@a.com", password="Secret1")
        assert resp.status_code == 400
        assert "email" in _json(resp)["error"].lower()


# ===================================================================
# /login
# ===================================================================

class TestLogin:
    def test_login_success(self, client, seed_user):
        resp = _login(client, username=seed_user["username"], password=seed_user["password"])
        assert resp.status_code == 200
        body = _json(resp)
        assert "access_token" in body

    def test_login_missing_fields(self, client):
        resp = client.post("/login", data={})
        assert resp.status_code == 400

    def test_login_empty_username(self, client, seed_user):
        resp = _login(client, username="", password=seed_user["password"])
        assert resp.status_code == 400

    def test_login_whitespace_password(self, client, seed_user):
        resp = _login(client, username=seed_user["username"], password="   ")
        assert resp.status_code == 400

    def test_login_bad_password(self, client, seed_user):
        resp = _login(client, username=seed_user["username"], password="WrongPassword")
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        resp = _login(client, username="nobody", password="anything")
        assert resp.status_code == 401

    def test_login_error_has_error_key(self, client, seed_user):
        resp = _login(client, username=seed_user["username"], password="wrong")
        body = _json(resp)
        assert "error" in body


# ===================================================================
# /checkAuth
# ===================================================================

class TestCheckAuth:
    def test_check_auth_success(self, client, auth_header):
        resp = client.get("/checkAuth", headers=auth_header)
        assert resp.status_code == 200
        body = _json(resp)
        assert body["username"] == "alice"
        assert body["email"] == "alice@example.com"

    def test_check_auth_no_token(self, client):
        resp = client.get("/checkAuth")
        assert resp.status_code in (401, 422)

    def test_check_auth_invalid_token(self, client):
        resp = client.get("/checkAuth", headers={
            "Authorization": "Bearer not.a.real.token"
        })
        assert resp.status_code in (401, 422)

    def test_check_auth_deleted_user(self, client, seed_user):
        """Token is valid but the user has been deleted from the DB."""
        # login first to get a token
        resp = _login(client, username=seed_user["username"], password=seed_user["password"])
        token = _json(resp)["access_token"]

        # delete the user
        User.find_one(username=seed_user["username"]).delete()

        resp = client.get("/checkAuth", headers={
            "Authorization": f"Bearer {token}"
        })
        assert resp.status_code == 404
        assert "error" in _json(resp)

    def test_check_auth_malformed_identity(self, client):
        """
        Craft a token whose identity is not a valid ObjectId.
        We simulate this by creating a token with a garbage identity string.
        """
        from flask_jwt_extended import create_access_token
        from core import app as _app

        with _app.app_context():
            token = create_access_token(identity="not-a-valid-objectid")

        resp = client.get("/checkAuth", headers={
            "Authorization": f"Bearer {token}"
        })
        # Should NOT 500; should return 404 (user not found)
        assert resp.status_code == 404
        assert "error" in _json(resp)


# ===================================================================
# /updateProfile
# ===================================================================

class TestUpdateProfile:
    def test_update_success(self, client, auth_header):
        resp = client.patch("/updateProfile", headers=auth_header, data={
            "new_username": "alice_new"
        })
        assert resp.status_code == 200
        assert User.find_one(username="alice_new") is not None

    def test_update_no_token(self, client):
        resp = client.patch("/updateProfile", data={"new_username": "x"})
        assert resp.status_code in (401, 422)

    def test_update_missing_username_field(self, client, auth_header):
        resp = client.patch("/updateProfile", headers=auth_header, data={})
        assert resp.status_code == 400
        assert "error" in _json(resp)

    def test_update_empty_username(self, client, auth_header):
        resp = client.patch("/updateProfile", headers=auth_header, data={
            "new_username": ""
        })
        assert resp.status_code == 400

    def test_update_whitespace_only_username(self, client, auth_header):
        resp = client.patch("/updateProfile", headers=auth_header, data={
            "new_username": "   "
        })
        assert resp.status_code == 400

    def test_update_username_too_short(self, client, auth_header):
        resp = client.patch("/updateProfile", headers=auth_header, data={
            "new_username": "ab"
        })
        assert resp.status_code == 400

    def test_update_duplicate_username(self, client, auth_header):
        """Cannot change to a username that another user already holds."""
        # Create a second user
        from core.models.user import User as U
        u2 = U(
            username="bob_exists",
            email="bob2@example.com",
            password=generate_password_hash("Secret1", method="pbkdf2:sha256"),
        )
        u2.save()

        resp = client.patch("/updateProfile", headers=auth_header, data={
            "new_username": "bob_exists"
        })
        assert resp.status_code == 400
        assert "taken" in _json(resp)["error"].lower() or "already" in _json(resp)["error"].lower()

    def test_update_same_username_allowed(self, client, auth_header, seed_user):
        """Keeping your own username should succeed (not flagged as duplicate)."""
        resp = client.patch("/updateProfile", headers=auth_header, data={
            "new_username": seed_user["username"]
        })
        assert resp.status_code == 200

    def test_update_deleted_user(self, client, seed_user):
        """Token is valid but user has been removed from the DB."""
        resp = _login(client, username=seed_user["username"], password=seed_user["password"])
        token = _json(resp)["access_token"]
        User.find_one(username=seed_user["username"]).delete()

        resp = client.patch("/updateProfile", headers={
            "Authorization": f"Bearer {token}"
        }, data={"new_username": "ghost"})
        assert resp.status_code == 404
        assert "error" in _json(resp)

    def test_update_malformed_identity(self, client):
        from flask_jwt_extended import create_access_token
        from core import app as _app

        with _app.app_context():
            token = create_access_token(identity="garbage-id")

        resp = client.patch("/updateProfile", headers={
            "Authorization": f"Bearer {token}"
        }, data={"new_username": "whatever"})
        assert resp.status_code == 404
        assert "error" in _json(resp)
