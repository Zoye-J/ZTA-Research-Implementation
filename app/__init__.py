from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from app.config import Config

db = SQLAlchemy()
jwt = JWTManager()
cors = CORS()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(app)

    # Initialize OPA client
    from app.policy.opa_client import init_opa_client
    init_opa_client(app)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.api.routes import api_bp
    from app.api.registration import registration_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(registration_bp, url_prefix="/api")

    # Create database tables
    with app.app_context():
        db.create_all()
        print("Government ZTA Database initialized!")

    return app
