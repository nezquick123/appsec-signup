from asyncio.log import logger
import logging
from urllib import response
from flask import Flask
from config import Config
from .extensions import db, csrf
from .routes.content import content_bp
from .models import User, UserRole

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Extensions
    db.init_app(app)
    csrf.init_app(app)

    @app.after_request
    def add_header(response):
    # Only apply no-cache if the response isn't a static file
        if "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response
    # Configure Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Register Blueprints
    from .routes.auth import auth_bp
    from .routes.mfa import mfa_bp
    from .routes.main import main_bp
    from .routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(content_bp)
    app.register_blueprint(admin_bp)

    # Create DB Tables
    with app.app_context():
        db.create_all()
        def initialize_owner_account():
            owner_email = app.config.get("OWNER_EMAIL", "")
            owner_password = app.config.get("OWNER_PASSWORD", "")
            if not owner_email or not owner_password:
                logger.warning("Owner email or password not set in configuration.")
                return
            
            existing_owner = db.session.get(User, owner_email)
            if existing_owner:
                logger.info("Owner account already exists.")
                return
            owner_user = User(email=owner_email, username="owner", password=owner_password)
            owner_user.is_activated = True
            owner_user.role = UserRole.OWNER
            db.session.add(owner_user)
            db.session.commit()
            logger.info("Owner account created successfully.")
        initialize_owner_account()

    return app