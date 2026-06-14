"""Regression tests for the auth routes.

These focus on the scenarios that used to return a 500 or silently accept bad
data: empty/whitespace/padded input, a missing password on login, JWT
identities that are malformed or point at a deleted user, and updateProfile
running without verifying the user still exists.
"""
from flask_jwt_extended import create_access_token

from core.models.user import User


# --- helpers --------------------------------------------------------------

def register(client, username='John', email='john@example.com', password='heslo123'):
    return client.post(
        '/register',
        data={'username': username, 'email': email, 'password': password},
    )


def login(client, username='John', password='heslo123'):
    return client.post('/login', data={'username': username, 'password': password})


def auth_token(client, username='John', email='john@example.com', password='heslo123'):
    register(client, username=username, email=email, password=password)
    resp = login(client, username=username, password=password)
    return resp.get_json()['access_token']


def token_for_identity(app, identity):
    with app.app_context():
        return create_access_token(identity=identity)


def auth_header(token):
    return {'Authorization': f'Bearer {token}'}


# --- register -------------------------------------------------------------

def test_register_success(client):
    resp = register(client)
    assert resp.status_code == 201
    assert resp.get_json() == {'result': 'ok'}


def test_register_missing_password(client):
    resp = client.post('/register', data={'username': 'John', 'email': 'john@example.com'})
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_register_empty_username(client):
    resp = register(client, username='')
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_register_whitespace_username(client):
    resp = register(client, username='   ')
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_register_whitespace_password(client):
    resp = register(client, password='        ')
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_register_trims_surrounding_whitespace(client):
    resp = register(client, username='  Bob  ', email='  bob@example.com  ')
    assert resp.status_code == 201
    # Stored values are the trimmed ones.
    assert User.find_one(username='Bob') is not None
    assert User.find_one(email='bob@example.com') is not None


def test_register_invalid_email(client):
    resp = register(client, email='not-an-email')
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_register_short_password(client):
    resp = register(client, password='123')
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_register_duplicate_username(client):
    register(client, username='John', email='john@example.com')
    resp = register(client, username='John', email='other@example.com')
    assert resp.status_code == 400
    assert resp.get_json()['msg'] == 'Username already exists'


def test_register_duplicate_email(client):
    register(client, username='John', email='john@example.com')
    resp = register(client, username='Other', email='john@example.com')
    assert resp.status_code == 400
    assert resp.get_json()['msg'] == 'Email already exists'


# --- login ----------------------------------------------------------------

def test_login_success(client):
    register(client)
    resp = login(client)
    assert resp.status_code == 200
    assert 'access_token' in resp.get_json()


def test_login_missing_password_does_not_500(client):
    """Valid username + no password previously crashed in check_password_hash."""
    register(client)
    resp = client.post('/login', data={'username': 'John'})
    assert resp.status_code == 401
    assert 'msg' in resp.get_json()


def test_login_wrong_password(client):
    register(client)
    resp = login(client, password='wrongpass')
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = login(client, username='Ghost', password='whatever')
    assert resp.status_code == 401


def test_login_empty_username(client):
    resp = client.post('/login', data={'username': '   ', 'password': 'heslo123'})
    assert resp.status_code == 401


# --- checkAuth ------------------------------------------------------------

def test_check_auth_success(client):
    token = auth_token(client)
    resp = client.get('/checkAuth', headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['username'] == 'John'
    assert body['email'] == 'john@example.com'


def test_check_auth_no_token(client):
    resp = client.get('/checkAuth')
    assert resp.status_code == 401
    assert 'msg' in resp.get_json()


def test_check_auth_malformed_identity(client, app):
    """A token whose identity is not a valid ObjectId must not 500."""
    token = token_for_identity(app, 'not-an-objectid')
    resp = client.get('/checkAuth', headers=auth_header(token))
    assert resp.status_code == 401
    assert resp.get_json()['msg'] == 'Invalid authentication token'


def test_check_auth_deleted_user(client, app):
    token = auth_token(client)
    User.find_one(username='John').delete()  # user vanishes after token issued
    resp = client.get('/checkAuth', headers=auth_header(token))
    assert resp.status_code == 404
    assert resp.get_json()['msg'] == 'User not found'


# --- updateProfile --------------------------------------------------------

def test_update_profile_success(client):
    token = auth_token(client)
    resp = client.patch('/updateProfile', data={'new_username': 'Patrick'}, headers=auth_header(token))
    assert resp.status_code == 200
    assert User.find_one(username='Patrick') is not None


def test_update_profile_no_token(client):
    resp = client.patch('/updateProfile', data={'new_username': 'Patrick'})
    assert resp.status_code == 401
    assert 'msg' in resp.get_json()


def test_update_profile_missing_field(client):
    token = auth_token(client)
    resp = client.patch('/updateProfile', data={}, headers=auth_header(token))
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_update_profile_whitespace_username(client):
    token = auth_token(client)
    resp = client.patch('/updateProfile', data={'new_username': '   '}, headers=auth_header(token))
    assert resp.status_code == 400
    assert 'msg' in resp.get_json()


def test_update_profile_duplicate_username(client):
    auth_token(client, username='John', email='john@example.com')
    register(client, username='Taken', email='taken@example.com')
    token = login(client, username='John').get_json()['access_token']
    resp = client.patch('/updateProfile', data={'new_username': 'Taken'}, headers=auth_header(token))
    assert resp.status_code == 400
    assert resp.get_json()['msg'] == 'Desired username has already been taken'


def test_update_profile_same_username_is_noop(client):
    """Renaming to your own current username is allowed, not a conflict."""
    token = auth_token(client, username='John')
    resp = client.patch('/updateProfile', data={'new_username': 'John'}, headers=auth_header(token))
    assert resp.status_code == 200


def test_update_profile_deleted_user(client):
    token = auth_token(client)
    User.find_one(username='John').delete()
    resp = client.patch('/updateProfile', data={'new_username': 'Patrick'}, headers=auth_header(token))
    assert resp.status_code == 404
    assert resp.get_json()['msg'] == 'User not found'


def test_update_profile_malformed_identity(client, app):
    token = token_for_identity(app, 'garbage')
    resp = client.patch('/updateProfile', data={'new_username': 'Patrick'}, headers=auth_header(token))
    assert resp.status_code == 401
    assert resp.get_json()['msg'] == 'Invalid authentication token'


# --- error shape ----------------------------------------------------------

def test_all_error_paths_use_msg_key(client):
    """Every error response shares the {"msg": ...} contract."""
    cases = [
        client.post('/register', data={}),
        client.post('/login', data={}),
        client.get('/checkAuth'),
        client.patch('/updateProfile', data={}),
    ]
    for resp in cases:
        assert resp.status_code >= 400
        body = resp.get_json()
        assert isinstance(body, dict)
        assert 'msg' in body
        assert isinstance(body['msg'], str)
