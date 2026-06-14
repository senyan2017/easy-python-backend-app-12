from flask import Flask
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager
from os import environ
from datetime import timedelta

from core.db import init_db

# load environment variables
load_dotenv()

# Setup the Flask-JWT-Extended extension (bound to the app inside the factory)
jwt = JWTManager()


def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = environ.get('JWT_SECRET_KEY', 'super-secret')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)  # but days=30

    jwt.init_app(app)

    # Open the database connection at startup instead of on route import
    init_db()

    from core.routes.auth_routes import bp  # import blueprint
    app.register_blueprint(bp)  # register blueprint

    return app
