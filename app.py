import re

import requests
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_talisman import Talisman
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import IntegrityError
import logging

from config import Config
from models import db, User, ActivationToken

from google.cloud import recaptchaenterprise_v1
from google.cloud.recaptchaenterprise_v1 import Assessment


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)

# HTTPS enforcement using Flask-Talisman (configurable via FORCE_HTTPS)
if app.config.get("FORCE_HTTPS"):
    Talisman(
        app,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000
    )


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

    project_id = app.config.get("RECAPTCHA_PROJECT_ID", "")
    site_key = app.config.get("RECAPTCHA_SITE_KEY", "")
    expected_action = "submit"

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
        db.session.delete(activation_token)
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


# Initialize database tables when app starts
with app.app_context():
    db.create_all()
