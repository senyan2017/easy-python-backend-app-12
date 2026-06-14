import re
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from core.models.user import User
from mongoengine import connect
from mongoengine.errors import NotUniqueError, ValidationError
from bson import ObjectId
from os import environ

bp = Blueprint('user_routes', __name__)

mongo_url = environ.get('MONGO_URL', 'mongodb://localhost:27017')
database_name = environ.get('MONGO_DB', 'ggame')

connect(db=database_name, host=mongo_url, alias="default")

# Validation rules
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
MIN_USERNAME_LEN = 3
MIN_PASSWORD_LEN = 6


def error_response(message, status):
    """Single, consistent error shape across every endpoint.

    flask_jwt_extended emits its own errors as {"msg": ...} (missing/invalid/
    expired token), so we standardize all of our error responses on the same
    shape to keep the frontend contract uniform.
    """
    return jsonify({"msg": message}), status


def resolve_current_user():
    """Resolve the JWT identity to a User without ever leaking a 500.

    The identity comes from a token that may be foreign, tampered, or point at
    a user that has since been deleted. Returns (user, None) on success or
    (None, error_response) describing the business failure.
    """
    identity = get_jwt_identity()
    if not isinstance(identity, str) or not ObjectId.is_valid(identity):
        return None, error_response("Invalid authentication token", 401)

    user = User.find_one(id=ObjectId(identity))
    if user is None:
        return None, error_response("User not found", 404)

    return user, None


@bp.route('/register', methods=['POST'])
def register():
    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip()
    password = request.form.get('password') or ''

    # Reject empty, whitespace-only, and padded input before it hits the DB
    if not username or not email or not password.strip():
        return error_response("Missing username, password, or email", 400)

    if len(username) < MIN_USERNAME_LEN:
        return error_response("Username must be at least 3 characters", 400)

    if not EMAIL_RE.match(email):
        return error_response("Invalid email format", 400)

    if len(password) < MIN_PASSWORD_LEN:
        return error_response("Password must be at least 6 characters", 400)

    if User.find_one(username=username) is not None:    # Checking if the username already exists
        return error_response("Username already exists", 400)

    if User.find_one(email=email) is not None:  # Checking if the email already exists
        return error_response("Email already exists", 400)

    user = User(username=username, password=password, email=email)
    try:
        user.save()
    except NotUniqueError:
        # Guards against the race between the checks above and the write
        return error_response("Username or email already exists", 409)
    except ValidationError:
        return error_response("Invalid registration data", 400)

    return jsonify({'result': 'ok'}), 201



@bp.route('/login', methods=['POST'])
def login():
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''

    # Bail out early: a present username with a missing password used to reach
    # check_password_hash(hash, None) and crash with a 500.
    if not username or not password:
        return error_response("Bad username or password", 401)

    user = User.find_one(username=username)

    if user is None or not check_password_hash(user.password, password):  # Password verification
        return error_response("Bad username or password", 401)

    # Convert the ObjectId to a string
    user_id_str = str(user.id)

    return jsonify(access_token=create_access_token(identity=user_id_str)), 200



@bp.route('/checkAuth', methods=['GET'])
@jwt_required()  # Verify that the user is logged in
def check_auth():
    user, err = resolve_current_user()
    if err:
        return err
    return jsonify({"username": user.username, "email": user.email}), 200



@bp.route('/logout', methods=['POST'])
@jwt_required()  # Verify that the user is logged in
def logout():
    return jsonify({"msg": "Successfully logged out"}), 200



@bp.route('/updateProfile', methods=['PATCH'])
@jwt_required()
def update_profile():
    current_user, err = resolve_current_user()
    if err:
        return err

    new_username = request.form.get('new_username')
    if new_username is None:
        return error_response("No fields to update", 400)

    new_username = new_username.strip()
    if not new_username:
        return error_response("Username cannot be empty", 400)

    if len(new_username) < MIN_USERNAME_LEN:
        return error_response("Username must be at least 3 characters", 400)

    # Renaming to the value you already have is a no-op, not a conflict
    if new_username == current_user.username:
        return jsonify({"msg": "Profile updated successfully!"}), 200

    existing = User.find_one(username=new_username)
    if existing is not None and str(existing.id) != str(current_user.id):
        return error_response("Desired username has already been taken", 400)

    current_user.username = new_username
    try:
        current_user.save()
    except NotUniqueError:
        return error_response("Desired username has already been taken", 409)
    except ValidationError:
        return error_response("Invalid profile data", 400)

    return jsonify({"msg": "Profile updated successfully!"}), 200