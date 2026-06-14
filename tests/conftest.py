"""
conftest.py – shared fixtures for auth route tests.

Sets up an in-memory MongoDB (mongomock) *before* the application
blueprint is imported, so the module-level ``connect()`` call in
``auth_routes.py`` targets the mock instead of a real database.
"""

import os
import sys
import pytest

# ---------------------------------------------------------------------------
# Environment must be set BEFORE any app code is imported
# ---------------------------------------------------------------------------
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["MONGO_DB"] = "test_auth_db"
os.environ["JWT_SECRET_KEY"] = "test-secret"
os.environ["FLASK_ENV"] = "testing"

import mongomock
from mongoengine import connect as _me_connect, disconnect as _me_disconnect
from unittest.mock import patch

# Establish the mongomock connection once, before app import.
# We patch mongoengine.connect so the module-level call in auth_routes.py
# becomes a harmless no-op.
try:
    _me_disconnect(alias="default")
except Exception:
    pass

_me_connect(
    db="test_auth_db",
    mongo_client_class=mongomock.MongoClient,
    alias="default",
)

# Now patch connect so auth_routes' module-level connect() is a no-op
_patch_connect = patch("mongoengine.connect", return_value=None)
_patch_connect.start()

# Now it's safe to import the app (which imports auth_routes)
from core import app as _flask_app  # noqa: E402
from core.models.user import User  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_db():
    """Drop all user documents before each test."""
    User.drop_collection()
    yield
    User.drop_collection()


@pytest.fixture()
def app():
    _flask_app.config["TESTING"] = True
    _flask_app.config["JWT_SECRET_KEY"] = "test-secret"
    return _flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def seed_user():
    """Insert a known user and return its data dict."""
    from werkzeug.security import generate_password_hash

    user = User(
        username="alice",
        email="alice@example.com",
        password=generate_password_hash("Password1", method="pbkdf2:sha256"),
    )
    user.save()
    return {
        "id": str(user.id),
        "username": "alice",
        "email": "alice@example.com",
        "password": "Password1",
    }


@pytest.fixture()
def auth_header(client, seed_user):
    """Log in the seeded user and return an Authorization header dict."""
    resp = client.post("/login", data={
        "username": seed_user["username"],
        "password": seed_user["password"],
    })
    token = resp.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
