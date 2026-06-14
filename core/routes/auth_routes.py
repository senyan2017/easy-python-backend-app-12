from flask import Blueprint, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from core.services import auth_service
from core.services.auth_service import AuthError
from core.utils.responses import success_response, error_response

bp = Blueprint('user_routes', __name__)


@bp.route('/register', methods=['POST'])
def register():
    try:
        auth_service.register_user(
            username=request.form.get('username', None),
            email=request.form.get('email', None),
            password=request.form.get('password', None),
        )
    except AuthError as err:
        return error_response(err.message, err.status)

    return success_response({"result": "ok"}, 201)


@bp.route('/login', methods=['POST'])
def login():
    try:
        user = auth_service.authenticate(
            username=request.form.get('username', None),
            password=request.form.get('password', None),
        )
    except AuthError as err:
        return error_response(err.message, err.status)

    access_token = create_access_token(identity=str(user.id))
    return success_response({"access_token": access_token}, 200)


@bp.route('/checkAuth', methods=['GET'])
@jwt_required()  # Verify that the user is logged in
def check_auth():
    user = auth_service.get_user_by_id(get_jwt_identity())
    if not user:
        return error_response("User not found", 404)
    return success_response({"username": user.username, "email": user.email}, 200)


@bp.route('/logout', methods=['POST'])
@jwt_required()  # Verify that the user is logged in
def logout():
    return success_response({"msg": "Successfully logged out"}, 200)


@bp.route('/updateProfile', methods=['PATCH'])
@jwt_required()
def update_profile():
    try:
        auth_service.update_profile(
            user_id=get_jwt_identity(),
            new_username=request.form.get('new_username', None),
        )
    except AuthError as err:
        return error_response(err.message, err.status)

    return success_response({"msg": "Profile updated successfully!"}, 200)
