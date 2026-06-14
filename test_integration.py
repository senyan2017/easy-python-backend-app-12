"""
Integration test: register -> login -> checkAuth -> updateProfile -> re-login
Uses mongomock so no real MongoDB instance is needed.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))

# Patch mongoengine connect before importing app
os.environ.setdefault('MONGO_DB', 'test_integration')

import mongoengine
import mongomock

# Establish the mongomock connection FIRST
mongoengine.disconnect_all()
mongoengine.connect(
    db='test_integration',
    mongo_client_class=mongomock.MongoClient,
)

# Monkey-patch mongoengine.connect to be a no-op so that
# auth_routes.py's module-level connect() doesn't blow up.
import mongoengine as _me
_me.connect = lambda *a, **kw: None

from core import app

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

def assert_eq(label, actual, expected):
    ok = actual == expected
    print(f"  {'  ' + PASS if ok else '  ' + FAIL}  {label}: got {actual!r}, expected {expected!r}")
    if not ok:
        raise AssertionError(f"{label}: {actual!r} != {expected!r}")

def assert_in(label, key, d):
    ok = key in d
    print(f"  {'  ' + PASS if ok else '  ' + FAIL}  {label}: key '{key}' {'found' if ok else 'MISSING'}")
    if not ok:
        raise AssertionError(f"{label}: key '{key}' not in response")

def run():
    client = app.test_client()
    print("\n=== 1. Register ===")
    r = client.post('/register', data=dict(username='alice', email='alice@example.com', password='secret123'))
    assert_eq("register status", r.status_code, 201)

    # Duplicate username
    r2 = client.post('/register', data=dict(username='alice', email='alice2@example.com', password='x'))
    assert_eq("dup username status", r2.status_code, 400)

    # Duplicate email
    r3 = client.post('/register', data=dict(username='bob', email='alice@example.com', password='x'))
    assert_eq("dup email status", r3.status_code, 400)

    print("\n=== 2. Login ===")
    r = client.post('/login', data=dict(username='alice', password='secret123'))
    assert_eq("login status", r.status_code, 200)
    body = r.get_json()
    assert_in("login body", "access_token", body)
    assert_in("login body", "user", body)
    assert_eq("login user.username", body["user"]["username"], "alice")
    assert_eq("login user.email", body["user"]["email"], "alice@example.com")
    assert_in("login user", "created_at", body["user"])
    assert_in("login user", "updated_at", body["user"])
    token = body["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Bad login
    r_bad = client.post('/login', data=dict(username='alice', password='wrong'))
    assert_eq("bad login status", r_bad.status_code, 401)

    print("\n=== 3. CheckAuth ===")
    r = client.get('/checkAuth', headers=headers)
    assert_eq("checkAuth status", r.status_code, 200)
    body = r.get_json()
    assert_eq("checkAuth username", body["username"], "alice")
    assert_eq("checkAuth email", body["email"], "alice@example.com")
    assert_in("checkAuth", "created_at", body)
    assert_in("checkAuth", "updated_at", body)
    assert_in("checkAuth", "id", body)

    print("\n=== 4. UpdateProfile – username only ===")
    r = client.patch('/updateProfile', data=dict(new_username='alice2'), headers=headers)
    assert_eq("update username status", r.status_code, 200)
    body = r.get_json()
    assert_eq("updated_fields", body["updated_fields"], ["username"])
    assert_eq("user.username after update", body["user"]["username"], "alice2")

    # Duplicate username check
    client.post('/register', data=dict(username='bob', email='bob@example.com', password='bob123'))
    r_dup = client.patch('/updateProfile', data=dict(new_username='bob'), headers=headers)
    assert_eq("dup username in update", r_dup.status_code, 409)

    print("\n=== 5. UpdateProfile – email only ===")
    r = client.patch('/updateProfile', data=dict(new_email='alice_new@example.com'), headers=headers)
    assert_eq("update email status", r.status_code, 200)
    body = r.get_json()
    assert_eq("updated_fields", body["updated_fields"], ["email"])
    assert_eq("user.email after update", body["user"]["email"], "alice_new@example.com")

    # Duplicate email check
    r_dup = client.patch('/updateProfile', data=dict(new_email='bob@example.com'), headers=headers)
    assert_eq("dup email in update", r_dup.status_code, 409)

    print("\n=== 6. UpdateProfile – password (requires current_password) ===")
    # Missing current_password
    r_no_cur = client.patch('/updateProfile', data=dict(new_password='newpass456'), headers=headers)
    assert_eq("no current_password status", r_no_cur.status_code, 400)

    # Wrong current_password
    r_wrong = client.patch('/updateProfile', data=dict(new_password='newpass456', current_password='wrong'), headers=headers)
    assert_eq("wrong current_password status", r_wrong.status_code, 403)

    # Correct flow
    r = client.patch('/updateProfile', data=dict(new_password='newpass456', current_password='secret123'), headers=headers)
    assert_eq("change password status", r.status_code, 200)
    body = r.get_json()
    assert_eq("updated_fields", body["updated_fields"], ["password"])

    print("\n=== 7. UpdateProfile – no fields ===")
    r = client.patch('/updateProfile', data=dict(), headers=headers)
    assert_eq("no fields status", r.status_code, 400)

    print("\n=== 8. UpdateProfile – multiple fields at once ===")
    r = client.patch('/updateProfile', data=dict(
        new_username='alice_final',
        new_email='alice_final@example.com',
    ), headers=headers)
    assert_eq("multi update status", r.status_code, 200)
    body = r.get_json()
    assert_eq("updated_fields sorted", sorted(body["updated_fields"]), ["email", "username"])

    print("\n=== 9. Re-login with new credentials ===")
    r = client.post('/login', data=dict(username='alice_final', password='newpass456'))
    assert_eq("re-login status", r.status_code, 200)
    body = r.get_json()
    assert_eq("re-login user.username", body["user"]["username"], "alice_final")
    assert_eq("re-login user.email", body["user"]["email"], "alice_final@example.com")

    print("\n=== 10. CheckAuth with new token ===")
    new_headers = {"Authorization": f"Bearer {body['access_token']}"}
    r = client.get('/checkAuth', headers=new_headers)
    assert_eq("checkAuth after re-login", r.status_code, 200)
    assert_eq("checkAuth username", r.get_json()["username"], "alice_final")
    assert_eq("checkAuth email", r.get_json()["email"], "alice_final@example.com")

    print("\n" + "=" * 50)
    print(f"  {PASS}  ALL TESTS PASSED")
    print("=" * 50)

if __name__ == '__main__':
    run()
