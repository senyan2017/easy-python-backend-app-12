from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from core.models.user import User
from mongoengine import connect, NotUniqueError
from bson import ObjectId
from os import environ

bp = Blueprint('user_routes', __name__)

mongo_url = environ.get('MONGO_URL', 'mongodb://localhost:27017')
database_name = environ.get('MONGO_DB', 'ggame')

connect(db=database_name, host=mongo_url, alias="default")


def _user_to_dict(user):
    """Serialize a User document to a frontend-friendly dict."""
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
@bp.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', None)
    email = request.form.get('email', None)
    password = request.form.get('password', None)

    if username is None or password is None or email is None:
        return jsonify({"msg": "Missing username, password, or email"}), 400

    if User.find_one(username=username) is not None:
        return jsonify({"msg": "Username already exists"}), 400

    if User.find_one(email=email) is not None:
        return jsonify({"msg": "Email already exists"}), 400

    user = User(username=username, password=password, email=email)
    user.save()

    return jsonify({'result': 'ok'}), 201


# ---------------------------------------------------------------------------
# Login  – returns token + full profile so the frontend doesn't need a
#          follow-up request just to populate the UI.
# ---------------------------------------------------------------------------
@bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', None)
    password = request.form.get('password', None)

    user = User.find_one(username=username)

    if user is None or not check_password_hash(user.password, password):
        return jsonify({"msg": "Bad username or password"}), 401

    user_id_str = str(user.id)
    access_token = create_access_token(identity=user_id_str)

    return jsonify({
        "access_token": access_token,
        "user": _user_to_dict(user),
    }), 200


# ---------------------------------------------------------------------------
# Check Auth – return the full profile so the account-settings page can
#              render immediately without an extra round-trip.
# ---------------------------------------------------------------------------
@bp.route('/checkAuth', methods=['GET'])
@jwt_required()
def check_auth():
    identity = get_jwt_identity()
    user = User.find_one(id=ObjectId(identity))
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify(_user_to_dict(user)), 200


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({"msg": "Successfully logged out"}), 200


# ---------------------------------------------------------------------------
# Update Profile – partial update.  Only the fields the client sends are
# touched; everything else stays untouched.
#
# Supported fields:
#   new_username  – unique-checked before save
#   new_email     – unique-checked before save
#   new_password  – requires current_password for verification
# ---------------------------------------------------------------------------
@bp.route('/updateProfile', methods=['PATCH'])
@jwt_required()
def update_profile():
    current_identity = get_jwt_identity()
    current_user = User.find_one(id=ObjectId(current_identity))

    if current_user is None:
        return jsonify({"msg": "User not found"}), 404

    new_username = request.form.get('new_username', None)
    new_email = request.form.get('new_email', None)
    new_password = request.form.get('new_password', None)
    current_password = request.form.get('current_password', None)

    updated_fields = []

    # --- Username -----------------------------------------------------------
    if new_username is not None:
        new_username = new_username.strip()
        if new_username == '':
            return jsonify({"msg": "Username cannot be empty"}), 400
        if new_username != current_user.username:
            existing = User.find_one(username=new_username)
            if existing is not None:
                return jsonify({"msg": "Username already taken"}), 409
            current_user.username = new_username
            updated_fields.append("username")

    # --- Email --------------------------------------------------------------
    if new_email is not None:
        new_email = new_email.strip()
        if new_email == '':
            return jsonify({"msg": "Email cannot be empty"}), 400
        if new_email != current_user.email:
            existing = User.find_one(email=new_email)
            if existing is not None:
                return jsonify({"msg": "Email already in use"}), 409
            current_user.email = new_email
            updated_fields.append("email")

    # --- Password -----------------------------------------------------------
    if new_password is not None:
        if new_password == '':
            return jsonify({"msg": "New password cannot be empty"}), 400
        # Require current password for security
        if current_password is None:
            return jsonify({"msg": "Current password is required to change password"}), 400
        if not check_password_hash(current_user.password, current_password):
            return jsonify({"msg": "Current password is incorrect"}), 403
        # Hash will be applied by the pre_save signal in the User model
        current_user.password = new_password
        updated_fields.append("password")

    # --- Nothing to update? -------------------------------------------------
    if not updated_fields:
        return jsonify({"msg": "No fields to update"}), 400

    # --- Save ---------------------------------------------------------------
    try:
        current_user.save()
    except NotUniqueError as e:
        # Fallback guard – in case a race condition slipped past the checks
        err_msg = str(e)
        if 'username' in err_msg:
            return jsonify({"msg": "Username already taken"}), 409
        if 'email' in err_msg:
            return jsonify({"msg": "Email already in use"}), 409
        return jsonify({"msg": "Duplicate field conflict"}), 409

    return jsonify({
        "msg": "Profile updated successfully",
        "updated_fields": updated_fields,
        "user": _user_to_dict(current_user),
    }), 200
