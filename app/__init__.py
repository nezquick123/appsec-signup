import logging
from flask import Flask
from config import Config
from .extensions import db, csrf

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Extensions
    db.init_app(app)
    csrf.init_app(app)

    # Configure Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Register Blueprints
    from .routes.auth import auth_bp
    from .routes.mfa import mfa_bp
    from .routes.main import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(main_bp)

    # Create DB Tables
    with app.app_context():
        db.create_all()

    return app