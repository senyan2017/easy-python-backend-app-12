from os import environ
from mongoengine import connect

DEFAULT_MONGO_URL = 'mongodb://localhost:27017'
DEFAULT_MONGO_DB = 'ggame'


def init_db(alias="default"):
    """Open the Mongo connection.

    Called explicitly during app startup so importing a route module no
    longer triggers a database connection as a side effect.
    """
    mongo_url = environ.get('MONGO_URL', DEFAULT_MONGO_URL)
    database_name = environ.get('MONGO_DB', DEFAULT_MONGO_DB)
    return connect(db=database_name, host=mongo_url, alias=alias)
