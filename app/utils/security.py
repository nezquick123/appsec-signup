import jwt
import logging
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, flash, redirect, url_for, current_app
from google.cloud import recaptchaenterprise_v1
from ..models import db, ActivationToken, PasswordResetToken, RefreshToken, UserRole

logger = logging.getLogger(__name__)

# --- ReCAPTCHA ---
def verify_recaptcha(recaptcha_token):
    if not recaptcha_token:
        return False
    project_id = current_app.config.get("RECAPTCHA_PROJECT_ID", "")
    site_key = current_app.config.get("RECAPTCHA_SITE_KEY", "")
    expected_action = "LOGIN"

    if not project_id or not site_key:
        return True

    client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()
    event = recaptchaenterprise_v1.Event(site_key=site_key, token=recaptcha_token)
    assessment = recaptchaenterprise_v1.Assessment(event=event)
    req = recaptchaenterprise_v1.CreateAssessmentRequest(
        parent=f"projects/{project_id}", assessment=assessment
    )
    response = client.create_assessment(req)

    if not response.token_properties.valid:
        return False
    if response.token_properties.action != expected_action:
        return False
    return response.risk_analysis.score >= 0.5

# --- Token Generators (DB Based) ---
def generate_activation_token(email):
    expiry_hours = current_app.config.get("ACTIVATION_TOKEN_EXPIRY_HOURS", 24)
    token = ActivationToken(email=email, expiry_hours=expiry_hours)
    db.session.add(token)
    db.session.commit()
    return token.raw_token

def get_activation_url(token):
    base_url = current_app.config.get("APP_URL", "http://localhost:5000")
    # Note: 'auth.activate' corresponds to the blueprint route
    return f"{base_url}/signup/activate?token={token}"

def generate_reset_token(email):
    expiry_hours = current_app.config.get("RESET_TOKEN_EXPIRY_HOURS", 1)
    token = PasswordResetToken(email=email, expiry_hours=expiry_hours)
    db.session.add(token)
    db.session.commit()
    return token.raw_token

def get_reset_url(token):
    base_url = current_app.config.get("APP_URL", "http://localhost:5000")
    return f"{base_url}/reset_password?token={token}"

# --- JWT Helpers ---
def create_access_token(email, username, role):
    expire_min = current_app.config.get("ACCESS_TOKEN_EXPIRE_MINUTES", 15)
    secret = current_app.config.get("SECRET_KEY")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=int(expire_min))
    
    payload = {
        "sub": email,
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access",
        "role": role
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def create_refresh_token(email):
    expire_days = current_app.config.get("REFRESH_TOKEN_EXPIRE_DAYS", 30)
    secret = current_app.config.get("SECRET_KEY")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=int(expire_days))
    jti = uuid.uuid4().hex
    
    payload = {
        "sub": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "type": "refresh"
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    rt = RefreshToken(email=email, expires_days=int(expire_days))
    rt.jti = jti
    rt.expires_at = exp
    db.session.add(rt)
    db.session.commit()
    return token, rt

def decode_jwt(token, verify_exp=True):
    secret = current_app.config.get("SECRET_KEY")
    options = {"verify_exp": verify_exp}
    return jwt.decode(token, secret, algorithms=["HS256"], options=options)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
        if not token:
            token = request.cookies.get("access_token")

        if not token:
            flash("Authentication required.", "error")
            return redirect(url_for("auth.login")) 

        # check if refresh token is revoked
        logger.info(f"Checking refresh token for revocation.")
        if request.cookies.get("refresh_token"):
            try:
                rt_payload = decode_jwt(request.cookies.get("refresh_token"))
                jti = rt_payload.get("jti")
                rt_db = RefreshToken.query.filter_by(jti=jti).first()
                logger.debug(f"Refresh token payload: {rt_db.revoked}")
                if rt_db and rt_db.revoked:
                   response = redirect(url_for("auth.login"))
                   response.delete_cookie("access_token") # Force clear the stale token
                   response.delete_cookie("refresh_token")
                   flash("Your session has been updated. Please log in again.", "info")
                   return response
            except Exception as e:
                logger.info(f"Error checking refresh token revocation: {e}")
                pass # Ignore errors here

        try:
            payload = decode_jwt(token)
            if payload.get("type") != "access":
                flash("Invalid token type.", "error")
                return redirect(url_for("auth.login"))
            request.user_email = payload.get("sub")
            request.username = payload.get("username")
        except jwt.ExpiredSignatureError:
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("auth.login"))
        except jwt.InvalidTokenError:
            flash("Invalid token. Please log in again.", "error")
            return redirect(url_for("auth.login"))

        return f(*args, **kwargs)
    return decorated


def get_logged_in_user():
    """
    Returns the username from the cookie if logged in, otherwise None.
    Does not enforce login or redirect.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        payload = decode_jwt(token)
        if payload.get("type") == "access":
            return payload.get("username")
    except Exception:
        pass # Invalid or expired token
        
    return None

def get_role():
    """
    Returns the username from the cookie if logged in, otherwise None.
    Does not enforce login or redirect.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        payload = decode_jwt(token)
        if payload.get("type") == "access":
            return payload.get("role")
    except Exception:
        pass # Invalid or expired token
        
    return None

def role_required(role: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1].strip()
            if not token:
                token = request.cookies.get("access_token")

            if not token:
                flash("Authentication required.", "error")
                return redirect(url_for("auth.login")) 
                    # check if refresh token is revoked
            # check if refresh token is revoked
            logger.info(f"Checking refresh token for revocation.")
            if request.cookies.get("refresh_token"):
                try:
                    rt_payload = decode_jwt(request.cookies.get("refresh_token"))
                    jti = rt_payload.get("jti")
                    rt_db = RefreshToken.query.filter_by(jti=jti).first()
                    logger.info(f"Refresh token payload: {rt_db.revoked}")
                    if rt_db and rt_db.revoked:
                       response = redirect(url_for("auth.login"))
                       response.delete_cookie("access_token") 
                       response.delete_cookie("refresh_token")
                       flash("Your session has been updated. Please log in again.", "info")
                    return response
                except Exception:
                    pass # Ignore errors here

            try:
               
                payload = decode_jwt(token)
                if payload.get("type") != "access":
                    flash("Invalid token type.", "error")
                    return redirect(url_for("auth.login"))
                
                request.user_email = payload.get("sub")
                request.username = payload.get("username")
                request.user_role = payload.get("role")

                

                if UserRole[request.user_role].value < UserRole[role].value:
                    flash("Insufficient permissions.", "error")
                    return redirect(url_for("main.dashboard"))
                    
            except jwt.ExpiredSignatureError:
                flash("Session expired. Please log in again.", "error")
                return redirect(url_for("auth.login"))
            except jwt.InvalidTokenError:
                flash("Invalid token. Please log in again.", "error")
                return redirect(url_for("auth.login"))

            return f(*args, **kwargs)
        return decorated
    return decorator
