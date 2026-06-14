from bson import ObjectId
from werkzeug.security import check_password_hash

from core.models.user import User


class AuthError(Exception):
    """Business-level failure carrying the message and HTTP status.

    Routes catch this and turn it into a uniform error response, which keeps
    the duplicate/validation/lookup logic out of the request handlers.
    """

    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def get_user_by_id(user_id):
    return User.find_one(id=ObjectId(user_id))


def get_user_by_username(username):
    return User.find_one(username=username)


def register_user(username, email, password):
    if username is None or password is None or email is None:
        raise AuthError("Missing username, password, or email", 400)

    if get_user_by_username(username) is not None:
        raise AuthError("Username already exists", 400)

    if User.find_one(email=email) is not None:
        raise AuthError("Email already exists", 400)

    user = User(username=username, password=password, email=email)
    user.save()
    return user


def authenticate(username, password):
    user = get_user_by_username(username)
    if user is None or not check_password_hash(user.password, password):
        raise AuthError("Bad username or password", 401)
    return user


def update_profile(user_id, new_username=None):
    user = get_user_by_id(user_id)
    if user is None:
        raise AuthError("User not found", 404)

    if new_username is not None:
        if get_user_by_username(new_username):
            raise AuthError("Desired username has already been taken", 400)
        user.username = new_username

    user.save()
    return user
