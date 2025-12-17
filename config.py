import os
from dotenv import load_dotenv

class Config:
    """Application configuration class."""

    load_dotenv()    
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY environment variable must be set")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/signup_db" #change to db in docker env
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Password pepper for additional security
    PASSWORD_PEPPER = os.environ.get("PASSWORD_PEPPER", "")

    # reCAPTCHA configuration
    RECAPTCHA_SITE_KEY = os.environ.get("RECAPTCHA_SITE_KEY", "")
    RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY", "")

    # Email domain restrictions (comma-separated)
    # Whitelist: Only allow these domains (if set)
    EMAIL_DOMAIN_WHITELIST = os.environ.get("EMAIL_DOMAIN_WHITELIST", "")
    # Blacklist: Block these domains
    EMAIL_DOMAIN_BLACKLIST = os.environ.get(
        "EMAIL_DOMAIN_BLACKLIST",
        "tempmail.com,throwaway.com,mailinator.com"
    )

    # Activation token expiration (in hours)
    ACTIVATION_TOKEN_EXPIRY_HOURS = int(
        os.environ.get("ACTIVATION_TOKEN_EXPIRY_HOURS", "24")
    )

    # Application URL for activation links
    APP_URL = os.environ.get("APP_URL", "http://localhost:5000")

    # HTTPS enforcement
    FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "false").lower() == "true"

    RECAPTCHA_PROJECT_ID = os.environ.get("RECAPTCHA_PROJECT_ID", "")
    ACCESS_TOKEN_EXPIRE_MINUTES = 15
    REFRESH_TOKEN_EXPIRE_DAYS = 30
    ACTIVATION_TOKEN_EXPIRY_HOURS = 24
    RESET_TOKEN_EXPIRY_HOURS = 1
