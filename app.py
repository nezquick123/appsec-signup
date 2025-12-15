import re


from flask import Flask, render_template, request, flash, redirect, url_for
from flask_talisman import Talisman
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import IntegrityError
import logging

from config import Config
from models import db, User, ActivationToken, RefreshToken

from google.cloud import recaptchaenterprise_v1
from google.cloud.recaptchaenterprise_v1 import Assessment

import jwt
from functools import wraps
from datetime import datetime, timezone, timedelta
from flask import make_response, jsonify
import uuid

import pyotp
import qrcode
import io
import base64
from flask import session


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)


def validate_username(username):
    """Validate username format."""
    if not username or len(username) < 3 or len(username) > 80:
        return False, "Username must be between 3 and 80 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores."
    return True, ""


def validate_password(password):
    """Validate password with advanced policy."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must be less than 128 characters."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_phone_number(phone):
    """Validate phone number format."""
    if not phone:
        return True, ""  # Phone is optional
    # Allow common phone formats: +1234567890, 123-456-7890, (123) 456-7890
    if len(phone) > 20:
        return False, "Phone number is too long."
    phone_pattern = r"^[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}$"
    if not re.match(phone_pattern, phone):
        return False, "Please enter a valid phone number."
    return True, ""


def validate_user_email(email):
    """Validate email format and domain restrictions."""
    try:
        validated = validate_email(email, check_deliverability=False)
        domain = validated.domain

        # Check whitelist (if configured, only these domains are allowed)
        whitelist = app.config.get("EMAIL_DOMAIN_WHITELIST", "")
        if whitelist:
            allowed_domains = [d.strip().lower() for d in whitelist.split(",") if d.strip()]
            if domain.lower() not in allowed_domains:
                return False, f"Email domain '{domain}' is not allowed. Please use an allowed email domain."

        # Check blacklist
        blacklist = app.config.get("EMAIL_DOMAIN_BLACKLIST", "")
        if blacklist:
            blocked_domains = [d.strip().lower() for d in blacklist.split(",") if d.strip()]
            if domain.lower() in blocked_domains:
                return False, f"Email domain '{domain}' is not allowed. Please use a different email address."

        return True, ""
    except EmailNotValidError as e:
        return False, str(e)


# def verify_recaptcha(recaptcha_response):
#     """Verify reCAPTCHA response with Google's API."""
#     secret_key = app.config.get("RECAPTCHA_SECRET_KEY", "")
#     if not secret_key:
#         # If reCAPTCHA is not configured, skip verification
#         return True

#     if not recaptcha_response:
#         return False

#     try:
#         response = requests.post(
#             "https://www.google.com/recaptcha/api/siteverify",
#             data={
#                 "secret": secret_key,
#                 "response": recaptcha_response
#             },
#             timeout=5
#         )
#         result = response.json()
#         return result.get("success", False)
#     except requests.RequestException:
#         # If verification service is unavailable, fail closed
#         return False

def verify_recaptcha(recaptcha_token):
    """Verify reCAPTCHA Enterprise token."""
    # If there is no token provided from the client, fail verification
    if not recaptcha_token:
        return False

    project_id = app.config.get("RECAPTCHA_PROJECT_ID", "")
    site_key = app.config.get("RECAPTCHA_SITE_KEY", "")
    expected_action = "LOGIN"

    if not project_id or not site_key:
        return True  # Skip if not configured

    client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()

    event = recaptchaenterprise_v1.Event(
        site_key=site_key,
        token=recaptcha_token
    )

    assessment = recaptchaenterprise_v1.Assessment(event=event)

    request = recaptchaenterprise_v1.CreateAssessmentRequest(
        parent=f"projects/{project_id}",
        assessment=assessment
    )

    response = client.create_assessment(request)

    # Token invalid?
    if not response.token_properties.valid:
        logger.warning(f"reCAPTCHA invalid reason: {response.token_properties.invalid_reason}")
        return False

    # Action mismatch?
    if response.token_properties.action != expected_action:
        logger.warning(f"reCAPTCHA action mismatch: expected {expected_action}, got {response.token_properties.action}")
        return False

    logger.info(f"reCAPTCHA risk score: {response.risk_analysis.score}")
    return response.risk_analysis.score >= 0.5


def generate_activation_token(email):
    """Generate an activation token for the user."""
    expiry_hours = app.config.get("ACTIVATION_TOKEN_EXPIRY_HOURS", 24)
    token = ActivationToken(email=email, expiry_hours=expiry_hours)
    db.session.add(token)
    db.session.commit()
    return token.raw_token


def get_activation_url(token):
    """Generate the full activation URL."""
    base_url = app.config.get("APP_URL", "http://localhost:5000")
    return f"{base_url}/signup/activate?token={token}"


@app.route("/", methods=["GET", "POST"])
def signup():
    """Handle signup form display and submission."""
    recaptcha_site_key = app.config.get("RECAPTCHA_SITE_KEY", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        phone_number = request.form.get("phone_number", "").strip() or None
        recaptcha_response = request.form.get("g-recaptcha-response", "")
        #recaptcha_response = request.form.get("recaptcha_token", "")

        # Verify reCAPTCHA
        if recaptcha_site_key and not verify_recaptcha(recaptcha_response):
            flash("CAPTCHA verification failed. Please try again.", "error")
            return render_template(
                "signup.html",
                username=username,
                email=email,
                phone_number=phone_number,
                recaptcha_site_key=recaptcha_site_key
            )

        # Validate username
        valid, error = validate_username(username)
        if not valid:
            flash(error, "error")
            return render_template(
                "signup.html",
                username=username,
                email=email,
                phone_number=phone_number,
                recaptcha_site_key=recaptcha_site_key
            )

        # Validate email
        valid, error = validate_user_email(email)
        if not valid:
            flash(error, "error")
            return render_template(
                "signup.html",
                username=username,
                email=email,
                phone_number=phone_number,
                recaptcha_site_key=recaptcha_site_key
            )

        # Validate phone number
        valid, error = validate_phone_number(phone_number)
        if not valid:
            flash(error, "error")
            return render_template(
                "signup.html",
                username=username,
                email=email,
                phone_number=phone_number,
                recaptcha_site_key=recaptcha_site_key
            )

        # Validate password
        valid, error = validate_password(password)
        if not valid:
            flash(error, "error")
            return render_template(
                "signup.html",
                username=username,
                email=email,
                phone_number=phone_number,
                recaptcha_site_key=recaptcha_site_key
            )

        # Create user
        try:
            user = User(
                email=email,
                username=username,
                password=password,
                phone_number=phone_number
            )
            db.session.add(user)
            db.session.commit()

            # Generate activation token
            raw_token = generate_activation_token(email)
            activation_url = get_activation_url(raw_token)
            logger.info(f"Activation token: {activation_url}")
            # In production, send email with activation link
            # The activation_url should be sent via a secure email service
            # For development, the URL can be retrieved from the database

            return redirect(url_for("success"))
        except IntegrityError:
            db.session.rollback()
            flash("Username or email already exists.", "error")
            return render_template(
                "signup.html",
                username=username,
                email=email,
                phone_number=phone_number,
                recaptcha_site_key=recaptcha_site_key
            )

    return render_template("signup.html", recaptcha_site_key=recaptcha_site_key)


@app.route("/signup/activate", methods=["GET"])
def activate():
    """Handle account activation via token."""
    token = request.args.get("token", "")

    if not token:
        flash("Invalid activation link.", "error")
        return render_template("activation.html", success=False)

    # Find the token
    activation_token = ActivationToken.find_by_token(token)

    if not activation_token:
        flash("Invalid activation token.", "error")
        return render_template("activation.html", success=False)

    if activation_token.is_expired():
        # Delete expired token
        user = db.session.get(User, activation_token.email)
        
        
        db.session.delete(activation_token)
        if user and not user.is_activated:
            db.session.delete(user) 
            
        db.session.commit()
        flash("Activation link has expired. Please request a new activation email.", "error")
        return render_template("activation.html", success=False)

    # Activate the user
    user = db.session.get(User, activation_token.email)
    if user:
        user.is_activated = True
        db.session.delete(activation_token)
        db.session.commit()
        flash("Your account has been activated successfully!", "success")
        return render_template("activation.html", success=True)

    flash("User not found.", "error")
    return render_template("activation.html", success=False)


@app.route("/success")
def success():
    """Display success page after signup."""
    return render_template("success.html")



# JWT configuration defaults (can also be placed in Config)
ACCESS_TOKEN_EXPIRE_MINUTES = int(app.config.get("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(app.config.get("REFRESH_TOKEN_EXPIRE_DAYS", 30))
JWT_ALGORITHM = "HS256"
JWT_SECRET = app.config.get("SECRET_KEY")

# --- JWT helpers ---
def create_access_token(email, username):
    """Create a short-lived access JWT (not persisted)."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access"
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # pyjwt returns str in modern versions
    return token

def create_refresh_token(email):
    """
    Create a refresh JWT and persist its JTI in DB for revocation.
    Returns (jwt_str, RefreshToken_db_instance)
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    jti = uuid.uuid4().hex
    payload = {
        "sub": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "type": "refresh"
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Persist refresh token record with same JTI so we can revoke/validate server side
    rt = RefreshToken(email=email, expires_days=REFRESH_TOKEN_EXPIRE_DAYS)
    rt.jti = jti  # use our generated jti to match token
    rt.expires_at = exp
    db.session.add(rt)
    db.session.commit()
    return token, rt

def decode_jwt(token, verify_exp=True):
    """Decode a JWT, return payload or raise jwt exceptions."""
    options = {"verify_exp": verify_exp}
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options=options)
    return payload

# --- decorator to protect endpoints ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1) Try Authorization header
        auth = request.headers.get("Authorization", "")
        token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()

        # 2) Fallback to cookie named 'access_token' (safer if HttpOnly but header preferred)
        if not token:
            token = request.cookies.get("access_token")

        if not token:
            flash("Authentication required.", "error")
            return redirect(url_for("login"))

        try:
            payload = decode_jwt(token)
            if payload.get("type") != "access":
                flash("Invalid token type.", "error")
                return redirect(url_for("login"))
            # Attach user info to request context if needed
            request.user_email = payload.get("sub")
            request.username = payload.get("username")
        except jwt.ExpiredSignatureError:
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            flash("Invalid token. Please log in again.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    recaptcha_site_key = app.config.get("RECAPTCHA_SITE_KEY", "")

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        recaptcha_response = request.form.get("g-recaptcha-response", "")

        if recaptcha_site_key and not verify_recaptcha(recaptcha_response):
            flash("CAPTCHA verification failed. Please try again.", "error")
            return render_template("login.html", email=email, recaptcha_site_key=recaptcha_site_key)

        user = db.session.get(User, email)
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "error")
            return render_template("login.html", email=email, recaptcha_site_key=recaptcha_site_key)

        if not user.is_activated:
            flash("Your account is not activated yet. Please check your email.", "error")
            return render_template("login.html", email=email, recaptcha_site_key=recaptcha_site_key)

        if user.is_mfa_enabled:
            # Store user email in session temporarily to verify 2FA in next step
            session['2fa_user_email'] = user.email
            return redirect(url_for('verify_2fa_login'))

        # Create tokens
        access_token = create_access_token(user.email, user.username)
        refresh_token, rt_obj = create_refresh_token(user.email)

        # Set refresh token as HttpOnly Secure cookie; access token can be returned in JSON or cookie.
        # Here we set both as cookies for convenience; access_token cookie is not HttpOnly if you want JS to read it,
        # but better to keep it HttpOnly; clients use Authorization header when possible.
        resp = make_response(redirect(url_for("dashboard")))
        # HttpOnly cookie for refresh token — cannot be read by JS
        resp.set_cookie(
            "refresh_token",
            refresh_token,
            httponly=True,
            secure=app.config.get("FORCE_HTTPS", False),
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
        )
        # Short-lived access token cookie (HttpOnly so JS can't read it). You may also return it in JSON.
        resp.set_cookie(
            "access_token",
            access_token,
            httponly=True,
            secure=app.config.get("FORCE_HTTPS", False),
            samesite="Lax",
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        flash("Logged in successfully!", "success")
        return resp

    return render_template("login.html", recaptcha_site_key=recaptcha_site_key)


@app.route("/token/refresh", methods=["POST"])
def refresh_token():
    """
    Use the refresh_token cookie to issue a new access token.
    Returns redirect or JSON; here we redirect back to dashboard and set cookies.
    """
    rt_cookie = request.cookies.get("refresh_token")
    if not rt_cookie:
        flash("Missing refresh token. Please log in again.", "error")
        return redirect(url_for("login"))

    try:
        payload = decode_jwt(rt_cookie)
        if payload.get("type") != "refresh":
            flash("Invalid refresh token.", "error")
            return redirect(url_for("login"))
    except jwt.ExpiredSignatureError:
        flash("Refresh token expired. Please log in again.", "error")
        return redirect(url_for("login"))
    except jwt.InvalidTokenError:
        flash("Invalid refresh token. Please log in again.", "error")
        return redirect(url_for("login"))

    jti = payload.get("jti")
    rt_db = RefreshToken.find_by_jti(jti)
    if not rt_db or rt_db.revoked or rt_db.is_expired():
        flash("Refresh token revoked or invalid. Please log in again.", "error")
        return redirect(url_for("login"))

    # Rotate: revoke old refresh token record and issue a new one
    rt_db.revoked = True
    db.session.add(rt_db)

    # Issue new tokens
    user_email = payload.get("sub")
    user = db.session.get(User, user_email)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("login"))

    access_token = create_access_token(user.email, user.username)
    new_refresh_token, new_rt_obj = create_refresh_token(user.email)

    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie(
        "refresh_token",
        new_refresh_token,
        httponly=True,
        secure=app.config.get("FORCE_HTTPS", False),
        samesite="Lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
    )
    resp.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=app.config.get("FORCE_HTTPS", False),
        samesite="Lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    db.session.commit()
    flash("Session refreshed.", "success")
    return resp


@app.route("/dashboard")
@token_required
def dashboard():
    """Simple dashboard page for logged-in users."""
    user = db.session.get(User, request.user_email)

    return render_template(
        "dashboard.html", 
        username=getattr(request, "username", ""), 
        is_mfa_enabled=user.is_mfa_enabled
    )



@app.route("/logout")
def logout():
    """Clear session cookies and redirect to login."""
    # Optional: Revoke the refresh token in the database for better security
    rt_cookie = request.cookies.get("refresh_token")
    if rt_cookie:
        try:
            # Decode without verifying expiry so we can revoke even if expired
            payload = decode_jwt(rt_cookie, verify_exp=False)
            jti = payload.get("jti")
            if jti:
                rt_db = RefreshToken.find_by_jti(jti)
                if rt_db:
                    rt_db.revoked = True
                    db.session.add(rt_db)
                    db.session.commit()
        except Exception:
            # If token is invalid or decoding fails, just proceed to clear cookies
            pass

    # Create response to redirect to login
    resp = make_response(redirect(url_for("login")))
    
    # Clear the authentication cookies
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    
    flash("You have been logged out successfully.", "success")
    return resp


@app.route("/mfa/setup")
@token_required
def mfa_setup():
    """Generate MFA secret and QR code for the user."""
    # Retrieve user from DB using email from token (set by decorator)
    user = db.session.get(User, request.user_email)
    
    if not user.mfa_secret:
        # Generate a new random secret (32 chars base32)
        user.mfa_secret = pyotp.random_base32()
        db.session.commit()

    # Create the URI for Google Authenticator
    # format: otpauth://totp/Issuer:Account?secret=SECRET&issuer=Issuer
    totp_uri = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(
        name=user.email, 
        issuer_name="AppSecSignup"
    )

    # Generate QR Code image
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return render_template("mfa_setup.html", qr_code=img_str, secret=user.mfa_secret)


@app.route("/mfa/enable", methods=["POST"])
@token_required
def mfa_enable():
    """Verify the code and enable MFA permanently."""
    user = db.session.get(User, request.user_email)
    code = request.form.get("code")

    if not user.mfa_secret:
        flash("MFA setup not initialized.", "error")
        return redirect(url_for("dashboard"))

    # Verify the provided code
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code):
        user.is_mfa_enabled = True
        db.session.commit()
        flash("Two-Factor Authentication enabled successfully!", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid code. Please try again.", "error")
        return redirect(url_for("mfa_setup"))
    

@app.route("/login/2fa", methods=["GET", "POST"])
def verify_2fa_login():
    """Second step of login: verify TOTP code."""
    email = session.get('2fa_user_email')
    
    if not email:
        flash("Session expired or invalid. Please login again.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code")
        user = db.session.get(User, email)

        if not user or not user.mfa_secret:
            session.pop('2fa_user_email', None)
            flash("User invalid.", "error")
            return redirect(url_for("login"))

        totp = pyotp.TOTP(user.mfa_secret)
        
        if totp.verify(code):
            # Code valid! Issue tokens just like in the main login function
            session.pop('2fa_user_email', None) # Clear temp session
            
            access_token = create_access_token(user.email, user.username)
            refresh_token, rt_obj = create_refresh_token(user.email)

            resp = make_response(redirect(url_for("dashboard")))
            
            # Use your existing cookie setting logic here
            resp.set_cookie(
                "refresh_token", refresh_token, httponly=True,
                secure=app.config.get("FORCE_HTTPS", False), samesite="Lax",
                max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
            )
            resp.set_cookie(
                "access_token", access_token, httponly=True,
                secure=app.config.get("FORCE_HTTPS", False), samesite="Lax",
                max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
            )
            
            flash("Logged in successfully with MFA!", "success")
            return resp
        else:
            flash("Invalid 2FA code.", "error")

    return render_template("mfa_verify.html")


with app.app_context():
    db.create_all()