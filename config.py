import os


class Config:
    """Application configuration class."""

    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY environment variable must be set")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@db:5432/signup_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
