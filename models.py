import secrets
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import jwt


from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import current_app
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
ph = PasswordHasher(
    time_cost=2,
    memory_cost=32 * 1024,   # 32 MiB
    parallelism=2
)



def hash_password(password: str) -> str:
    """Hash password using Argon2id with optional pepper."""
    pepper = current_app.config.get("PASSWORD_PEPPER", "")
    peppered_password = password + pepper
    return ph.hash(peppered_password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify password against Argon2id hash."""
    pepper = current_app.config.get("PASSWORD_PEPPER", "")
    peppered_password = password + pepper
    try:
        ph.verify(password_hash, peppered_password)
        return True
    except VerifyMismatchError:
        return False


class User(db.Model):
    """User model for storing signup information."""

    __tablename__ = "users"

    email = db.Column(db.String(255), primary_key=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(50), nullable=True)
    is_activated = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, username, password, phone_number=None):
        self.email = email
        self.username = username
        self.password_hash = hash_password(password)
        self.phone_number = phone_number
        self.is_activated = False

    def __repr__(self):
        return f"<User {self.username}>"

    def check_password(self, password):
        """Verify user password."""
        return verify_password(self.password_hash, password)
    
    def set_password(self, new_password):
        """Set a new password for the user."""
        self.password_hash = hash_password(new_password)
        db.session.commit()


class ActivationToken(db.Model):
    """Activation token model for email verification."""

    __tablename__ = "activation_tokens"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(
        db.String(255),
        db.ForeignKey("users.email", ondelete="CASCADE"),
        nullable=False
    )
    activation_token = db.Column(db.String(255), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    user = db.relationship(
        "User",
        backref=db.backref("activation_tokens", cascade="all, delete-orphan")
    )

    def __init__(self, email, expiry_hours=24):
        self.email = email
        # Generate a UUID token and hash it for storage
        raw_token = str(uuid.uuid4())
        self.activation_token = sha256(raw_token.encode()).hexdigest()
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
        # Store raw token temporarily for returning to user (not persisted)
        self._raw_token = raw_token

    @property
    def raw_token(self):
        """Get the raw token (only available immediately after creation)."""
        return getattr(self, "_raw_token", None)

    def is_expired(self):
        """Check if the token has expired."""
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        # Handle timezone-naive datetime from SQLite (for testing)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    @staticmethod
    def find_by_token(raw_token):
        """Find activation token by raw token value."""
        token_hash = sha256(raw_token.encode()).hexdigest()
        
        return ActivationToken.query.filter_by(activation_token=token_hash).first()

class RefreshToken(db.Model):
    """Server-side store for issued refresh tokens for revocation & rotation."""
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(64), unique=True, nullable=False)  # JWT ID
    email = db.Column(db.String(255), db.ForeignKey("users.email", ondelete="CASCADE"), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship(
        "User",
        backref=db.backref("refresh_tokens", cascade="all, delete-orphan")
    )

    def __init__(self, email, expires_days=30):
        self.jti = uuid.uuid4().hex
        self.email = email
        self.expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        self.revoked = False

    def is_expired(self):
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    @staticmethod
    def find_by_jti(jti):
        return RefreshToken.query.filter_by(jti=jti).first()\
        

class PasswordResetToken(db.Model):
    """Password reset tokens table."""

    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(
        db.String(255),
        db.ForeignKey("users.email", ondelete="CASCADE"),
        nullable=False
    )
    reset_token = db.Column(db.String(255), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    user = db.relationship(
        "User",
        backref=db.backref("password_reset_tokens", cascade="all, delete-orphan")
    )

    def __init__(self, email, expiry_hours=24):
        self.email = email
        # Generate a UUID token and hash it for storage
        raw_token = str(uuid.uuid4())
        self.reset_token = sha256(raw_token.encode()).hexdigest()
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
        # Store raw token temporarily for returning to user (not persisted)
        self._raw_token = raw_token

    @property
    def raw_token(self):
        """Get the raw token (only available immediately after creation)."""
        return getattr(self, "_raw_token", None)

    def is_expired(self):
        """Check if the token has expired."""
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        # Handle timezone-naive datetime from SQLite (for testing)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    @staticmethod
    def find_by_token(raw_token):
        """Find password reset token by raw token value."""
        token_hash = sha256(raw_token.encode()).hexdigest()
        
        return PasswordResetToken.query.filter_by(reset_token=token_hash).first()