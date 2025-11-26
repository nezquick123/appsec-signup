import os


class Config:
    """Application configuration class."""

    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32).hex())
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@db:5432/signup_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
