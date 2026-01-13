from .extensions import db
from datetime import datetime, timezone, timedelta
import uuid
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum

UserRole = Enum('UserRole', [('BLOCKED', 0), ('REGULAR', 1), ('ADMIN', 2), ('OWNER', 3)])

class User(db.Model):
    __tablename__ = 'users'
    email = db.Column(db.String(120), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    is_activated = db.Column(db.Boolean, default=False)
    is_mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    role = db.Column(db.Enum(UserRole), default=UserRole.REGULAR, nullable=False)


    def __init__(self, email, username, password, phone_number=None):
        self.email = email
        self.username = username
        self.phone_number = phone_number
        self.set_password(password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ActivationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def __init__(self, email, expiry_hours=24):
        self.email = email
        self.token = secrets.token_urlsafe(32)
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

    @property
    def raw_token(self):
        return self.token

    @classmethod
    def find_by_token(cls, token_str):
        return cls.query.filter_by(token=token_str).first()

    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at.replace(tzinfo=timezone.utc)

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def __init__(self, email, expiry_hours=1):
        self.email = email
        self.token = secrets.token_urlsafe(32)
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

    @property
    def raw_token(self):
        return self.token

    @classmethod
    def find_by_token(cls, token_str):
        return cls.query.filter_by(token=token_str).first()

    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at.replace(tzinfo=timezone.utc)

class RefreshToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)

    def __init__(self, email, expires_days=30):
        self.email = email
        self.jti = str(uuid.uuid4())
        self.expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

    @classmethod
    def find_by_jti(cls, jti):
        return cls.query.filter_by(jti=jti).first()

    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at.replace(tzinfo=timezone.utc)
    

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.String(36), primary_key=True)  # UUID
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    content = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Foreign Key to User
    author_username = db.Column(db.String(80), db.ForeignKey('users.username'), nullable=False)
    
    # Relationships
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    comments = db.relationship('Comment', backref='post', cascade="all, delete-orphan", lazy=True)

    def __init__(self, title, content, author_username, description=None):
        self.id = str(uuid.uuid4())
        self.title = title
        self.content = content
        self.author_username = author_username
        self.description = description

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.String(36), primary_key=True) # UUID
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Foreign Keys
    post_id = db.Column(db.String(36), db.ForeignKey('posts.id'), nullable=False)
    author_username = db.Column(db.String(80), db.ForeignKey('users.username'), nullable=False)
    
    # Relationship
    author = db.relationship('User', backref=db.backref('comments', lazy=True))

    def __init__(self, content, post_id, author_username):
        self.id = str(uuid.uuid4())
        self.content = content
        self.post_id = post_id
        self.author_username = author_username