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


@bp.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', None)
    email = request.form.get('email', None)
    password = request.form.get('password', None)
    
    if username is None or password is None or email is None:
        return jsonify({"msg": "Missing username, password, or email"}), 400
    
    if User.find_one(username=username) is not None:    # Checking if the username already exists
        return jsonify({"msg": "Username already exists"}), 400
    
    if User.find_one(email=email) is not None:  # Checking if the email already exists
        return jsonify({"msg": "Email already exists"}), 400
    
    user = User(username=username, password=password, email=email)
    try:
        user.save()
    except NotUniqueError:  # Safety net in case the unique index trips despite the checks above
        return jsonify({"msg": "Username or email already exists"}), 400

    return jsonify({'result': 'ok'}), 201



@bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', None)
    password = request.form.get('password', None)

    user = User.find_one(username=username)

    if user is None or not check_password_hash(user.password, password):  # Password verification
        return jsonify({"msg": "Bad username or password"}), 401

    # Convert the ObjectId to a string
    user_id_str = str(user.id)

    access_token = create_access_token(identity=user_id_str)
    # Return basic profile alongside the token so the client doesn't need a follow-up request
    return jsonify(access_token=access_token, user=user.to_dict()), 200



@bp.route('/checkAuth', methods=['GET'])
@jwt_required()  # Verify that the user is logged in
def check_auth():
    identity = get_jwt_identity()
    user = User.find_one(id=ObjectId(identity))
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify(user.to_dict()), 200



@bp.route('/logout', methods=['POST'])
@jwt_required()  # Verify that the user is logged in
def logout():
    return jsonify({"msg": "Successfully logged out"}), 200



@bp.route('/updateProfile', methods=['PATCH'])
@jwt_required()
def update_profile():
    current_identity = get_jwt_identity()
    current_user = User.find_one(id=ObjectId(current_identity))
    if current_user is None:
        return jsonify({"msg": "User not found"}), 404

    new_username = (request.form.get('new_username') or '').strip() or None
    new_email = (request.form.get('new_email') or '').strip() or None
    new_password = request.form.get('new_password') or None  # not stripped: spaces may be intentional
    current_password = request.form.get('current_password') or None

    if new_username is None and new_email is None and new_password is None:
        return jsonify({"msg": "No fields to update"}), 400

    # Username: only touch it when a different value is supplied
    if new_username is not None and new_username != current_user.username:
        if User.find_one(username=new_username) is not None:
            return jsonify({"msg": "Desired username has already been taken"}), 400
        current_user.username = new_username

    # Email: only touch it when a different value is supplied
    if new_email is not None and new_email != current_user.email:
        if User.find_one(email=new_email) is not None:
            return jsonify({"msg": "Desired email has already been taken"}), 400
        current_user.email = new_email

    # Password: require and verify the current password before changing it
    if new_password is not None:
        if current_password is None:
            return jsonify({"msg": "Current password is required to set a new password"}), 400
        if not check_password_hash(current_user.password, current_password):
            return jsonify({"msg": "Current password is incorrect"}), 401
        current_user.password = new_password  # hashed by the pre_save signal

    try:
        current_user.save()
    except NotUniqueError:  # Guard against a race between the checks above and the unique index
        return jsonify({"msg": "Username or email already exists"}), 400

    return jsonify({"msg": "Profile updated successfully!", "user": current_user.to_dict()}), 200