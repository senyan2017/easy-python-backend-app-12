import os

# Keep the JWT secret deterministic and use a throwaway DB name. We deliberately
# leave MONGO_URL at its default: the connection mongoengine opens at import time
# is lazy (never actually dialed), and we swap it for an in-memory mongomock
# client below before any query runs -- so production code stays untouched.
os.environ.setdefault('JWT_SECRET_KEY', 'test-secret')
os.environ['MONGO_DB'] = 'ggame_test'

import mongoengine
import mongomock
import pytest

from core import app as flask_app
from core.models.user import User

# Replace the import-time connection with an in-memory mongomock one.
mongoengine.disconnect(alias='default')
mongoengine.connect(
    db='ggame_test',
    alias='default',
    mongo_client_class=mongomock.MongoClient,
)


@pytest.fixture(scope='session')
def app():
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def clean_db():
    """Each test starts and ends with an empty users collection."""
    User.drop_collection()
    yield
    User.drop_collection()
