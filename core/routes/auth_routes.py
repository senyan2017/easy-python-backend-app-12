import re

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from core.models.user import User
from mongoengine import connect
from bson import ObjectId
from bson.errors import InvalidId
from os import environ

bp = Blueprint('user_routes', __name__)

mongo_url = environ.get('MONGO_URL', 'mongodb://localhost:27017')
database_name = environ.get('MONGO_DB', 'ggame')

connect(db=database_name, host=mongo_url, alias="default")

# --------------- helpers ---------------

EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

USERNAME_MIN_LEN = 3
USERNAME_MAX_LEN = 30
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.\-]+$')

PASSWORD_MIN_LEN = 6
PASSWORD_MAX_LEN = 128

MAX_FIELD_LEN = 255


def _error(message, status_code):
    """Unified error response body."""
    return jsonify({"error": message}), status_code


def _sanitize(value):
    """Strip whitespace; return None if the result is empty."""
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value).strip() or None
    return value.strip() or None


def _safe_objectid(value):
    """Return an ObjectId or None if the value is invalid."""
    try:
        return ObjectId(value)
    except (InvalidId, TypeError, ValueError):
        return None


def _get_current_user():
    """Resolve the JWT identity to a User document, or return None."""
    identity = get_jwt_identity()
    oid = _safe_objectid(identity)
    if oid is None:
        return None
    return User.find_one(id=oid)


def _validate_username(username):
    """Return an error message string if the username is invalid, else None."""
    if len(username) < USERNAME_MIN_LEN:
        return f"Username must be at least {USERNAME_MIN_LEN} characters"
    if len(username) > USERNAME_MAX_LEN:
        return f"Username must be at most {USERNAME_MAX_LEN} characters"
    if not USERNAME_RE.match(username):
        return "Username may only contain letters, digits, underscores, dots, and hyphens"
    return None


def _validate_email(email):
    if len(email) > MAX_FIELD_LEN:
        return f"Email must be at most {MAX_FIELD_LEN} characters"
    if not EMAIL_RE.match(email):
        return "Invalid email format"
    return None


def _validate_password(password):
    if len(password) < PASSWORD_MIN_LEN:
        return f"Password must be at least {PASSWORD_MIN_LEN} characters"
    if len(password) > PASSWORD_MAX_LEN:
        return f"Password must be at most {PASSWORD_MAX_LEN} characters"
    return None


# --------------- routes ---------------


@bp.route('/register', methods=['POST'])
def register():
    raw_username = request.form.get('username', None)
    raw_email = request.form.get('email', None)
    raw_password = request.form.get('password', None)

    username = _sanitize(raw_username)
    email = _sanitize(raw_email)
    password = _sanitize(raw_password)

    if username is None or email is None or password is None:
        return _error("Missing username, password, or email", 400)

    err = _validate_username(username)
    if err:
        return _error(err, 400)

    err = _validate_email(email)
    if err:
        return _error(err, 400)

    err = _validate_password(password)
    if err:
        return _error(err, 400)

    # Check duplicates
    if User.find_one(username=username) is not None:
        return _error("Username already exists", 400)

    if User.find_one(email=email) is not None:
        return _error("Email already exists", 400)

    user = User(
        username=username,
        password=generate_password_hash(password, method='pbkdf2:sha256'),
        email=email,
    )
    user.save()

    return jsonify({"message": "User registered successfully"}), 201


@bp.route('/login', methods=['POST'])
def login():
    raw_username = request.form.get('username', None)
    raw_password = request.form.get('password', None)

    username = _sanitize(raw_username)
    password = _sanitize(raw_password)

    if username is None or password is None:
        return _error("Missing username or password", 400)

    user = User.find_one(username=username)

    if user is None or not check_password_hash(user.password, password):
        return _error("Bad username or password", 401)

    user_id_str = str(user.id)
    return jsonify({"access_token": create_access_token(identity=user_id_str)}), 200


@bp.route('/checkAuth', methods=['GET'])
@jwt_required()
def check_auth():
    user = _get_current_user()
    if user is None:
        return _error("User not found or invalid token", 404)
    return jsonify({
        "username": user.username,
        "email": user.email,
    }), 200


@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({"message": "Successfully logged out"}), 200


@bp.route('/updateProfile', methods=['PATCH'])
@jwt_required()
def update_profile():
    raw_username = request.form.get('new_username', None)

    user = _get_current_user()
    if user is None:
        return _error("User not found or invalid token", 404)

    new_username = _sanitize(raw_username)

    if new_username is None:
        return _error("No new_username provided", 400)

    err = _validate_username(new_username)
    if err:
        return _error(err, 400)

    # Check if the new username is taken by a *different* user
    existing = User.find_one(username=new_username)
    if existing is not None and str(existing.id) != str(user.id):
        return _error("Desired username has already been taken", 400)

    user.username = new_username
    user.save()

    return jsonify({"message": "Profile updated successfully!"}), 200
