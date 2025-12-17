from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response, current_app, session
from sqlalchemy.exc import IntegrityError
import logging
import jwt

from ..extensions import db
from ..models import User, ActivationToken, PasswordResetToken, RefreshToken
from ..utils.validators import validate_username, validate_password, validate_phone_number, validate_user_email
from ..utils.security import (
    verify_recaptcha, generate_activation_token, get_activation_url,
    generate_reset_token, get_reset_url, create_access_token, 
    create_refresh_token, decode_jwt
)

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

@auth_bp.route("/", methods=["GET", "POST"])
def login():
    recaptcha_site_key = current_app.config.get("RECAPTCHA_SITE_KEY", "")

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
            session['2fa_user_email'] = user.email
            return redirect(url_for('mfa.verify_2fa_login'))

        # Issue Tokens
        access_token = create_access_token(user.email, user.username)
        refresh_token, _ = create_refresh_token(user.email)

        resp = make_response(redirect(url_for("main.dashboard")))
        resp.set_cookie(
            "refresh_token", refresh_token, httponly=True,
            secure=current_app.config.get("FORCE_HTTPS", False), samesite="Lax",
            max_age=current_app.config.get("REFRESH_TOKEN_EXPIRE_DAYS") * 24 * 3600
        )
        resp.set_cookie(
            "access_token", access_token, httponly=True,
            secure=current_app.config.get("FORCE_HTTPS", False), samesite="Lax",
            max_age=current_app.config.get("ACCESS_TOKEN_EXPIRE_MINUTES") * 60
        )
        flash("Logged in successfully!", "success")
        return resp

    return render_template("login.html", recaptcha_site_key=recaptcha_site_key)

@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    recaptcha_site_key = current_app.config.get("RECAPTCHA_SITE_KEY", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        phone_number = request.form.get("phone_number", "").strip() or None
        recaptcha_response = request.form.get("g-recaptcha-response", "")

        if recaptcha_site_key and not verify_recaptcha(recaptcha_response):
            flash("CAPTCHA verification failed.", "error")
            return render_template("signup.html", username=username, email=email, phone_number=phone_number, recaptcha_site_key=recaptcha_site_key)

        # Validations
        v_user, err_user = validate_username(username)
        if not v_user:
            flash(err_user, "error")
            return render_template("signup.html", username=username, email=email, phone_number=phone_number, recaptcha_site_key=recaptcha_site_key)
        
        v_email, err_email = validate_user_email(email)
        if not v_email:
            flash(err_email, "error")
            return render_template("signup.html", username=username, email=email, phone_number=phone_number, recaptcha_site_key=recaptcha_site_key)

        v_phone, err_phone = validate_phone_number(phone_number)
        if not v_phone:
            flash(err_phone, "error")
            return render_template("signup.html", username=username, email=email, phone_number=phone_number, recaptcha_site_key=recaptcha_site_key)

        v_pass, err_pass = validate_password(password)
        if not v_pass:
            flash(err_pass, "error")
            return render_template("signup.html", username=username, email=email, phone_number=phone_number, recaptcha_site_key=recaptcha_site_key)

        try:
            user = User(email=email, username=username, password=password, phone_number=phone_number)
            db.session.add(user)
            db.session.commit()

            raw_token = generate_activation_token(email)
            activation_url = get_activation_url(raw_token)
            logger.info(f"Activation token: {activation_url}")

            return render_template("success.html", title="Account Created!", message=f"We have sent an activation email to {email}.", action_url=url_for('auth.login'), action_text="Go to Login")
        except IntegrityError:
            db.session.rollback()
            flash("Username or email already exists.", "error")
            return render_template("signup.html", username=username, email=email, phone_number=phone_number, recaptcha_site_key=recaptcha_site_key)

    return render_template("signup.html", recaptcha_site_key=recaptcha_site_key)

@auth_bp.route("/signup/activate", methods=["GET"])
def activate():
    token = request.args.get("token", "")
    if not token:
        flash("Invalid activation link.", "error")
        return render_template("activation.html", success=False)

    activation_token = ActivationToken.find_by_token(token)
    if not activation_token:
        flash("Invalid activation token.", "error")
        return render_template("activation.html", success=False)

    if activation_token.is_expired():
        user = db.session.get(User, activation_token.email)
        db.session.delete(activation_token)
        if user and not user.is_activated:
            db.session.delete(user)
        db.session.commit()
        flash("Activation link has expired.", "error")
        return render_template("activation.html", success=False)

    user = db.session.get(User, activation_token.email)
    if user:
        user.is_activated = True
        db.session.delete(activation_token)
        db.session.commit()
        flash("Your account has been activated successfully!", "success")
        return render_template("activation.html", success=True)
    
    flash("User not found.", "error")
    return render_template("activation.html", success=False)

@auth_bp.route("/logout")
def logout():
    rt_cookie = request.cookies.get("refresh_token")
    if rt_cookie:
        try:
            payload = decode_jwt(rt_cookie, verify_exp=False)
            jti = payload.get("jti")
            if jti:
                rt_db = RefreshToken.find_by_jti(jti)
                if rt_db:
                    rt_db.revoked = True
                    db.session.add(rt_db)
                    db.session.commit()
        except Exception:
            pass

    resp = make_response(redirect(url_for("auth.login")))
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    flash("You have been logged out successfully.", "success")
    return resp

@auth_bp.route("/token/refresh", methods=["POST"])
def refresh_token():
    rt_cookie = request.cookies.get("refresh_token")
    if not rt_cookie:
        flash("Missing refresh token.", "error")
        return redirect(url_for("auth.login"))

    try:
        payload = decode_jwt(rt_cookie)
        if payload.get("type") != "refresh":
            raise jwt.InvalidTokenError
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        flash("Invalid or expired refresh token.", "error")
        return redirect(url_for("auth.login"))

    rt_db = RefreshToken.find_by_jti(payload.get("jti"))
    if not rt_db or rt_db.revoked or rt_db.is_expired():
        flash("Refresh token revoked or invalid.", "error")
        return redirect(url_for("auth.login"))

    rt_db.revoked = True
    db.session.add(rt_db)

    user = db.session.get(User, payload.get("sub"))
    if not user:
        return redirect(url_for("auth.login"))

    access_token = create_access_token(user.email, user.username)
    new_refresh_token, _ = create_refresh_token(user.email)

    resp = make_response(redirect(url_for("main.dashboard")))
    resp.set_cookie("refresh_token", new_refresh_token, httponly=True, secure=current_app.config.get("FORCE_HTTPS", False), samesite="Lax", max_age=current_app.config.get("REFRESH_TOKEN_EXPIRE_DAYS") * 24 * 3600)
    resp.set_cookie("access_token", access_token, httponly=True, secure=current_app.config.get("FORCE_HTTPS", False), samesite="Lax", max_age=current_app.config.get("ACCESS_TOKEN_EXPIRE_MINUTES") * 60)
    
    db.session.commit()
    flash("Session refreshed.", "success")
    return resp

@auth_bp.route("/request_reset", methods=["GET", "POST"])
def request_reset():
    recaptcha_site_key = current_app.config.get("RECAPTCHA_SITE_KEY", "")
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        recaptcha_response = request.form.get("g-recaptcha-response", "")
        if recaptcha_site_key and not verify_recaptcha(recaptcha_response):
            flash("CAPTCHA verification failed.", "error")
            return render_template("request_reset.html", email=email, recaptcha_site_key=recaptcha_site_key)

        user = db.session.get(User, email)
        if user:
            raw_token = generate_reset_token(email)
            reset_url = get_reset_url(raw_token)
            logger.info(f"Reset link: {reset_url}")
            return render_template("success.html", title="Check Your Email", message=f"Reset instructions sent to {email}.", action_url=url_for('auth.login'), action_text="Return to Login")
    
    return render_template("request_reset.html", recaptcha_site_key=recaptcha_site_key)

@auth_bp.route("/reset_password", methods=["GET", "POST"])
def reset():
    if request.method == "GET":
        token = request.args.get("token", "")
        if not token: return redirect(url_for("auth.login"))
        
        rt = PasswordResetToken.find_by_token(token)
        if not rt or rt.is_expired():
            flash("Invalid or expired reset token.", "error")
            return render_template("reset_password.html", success=False)
        return render_template("reset_password.html", token=token, success=None)

    token = request.form.get("token", "")
    rt = PasswordResetToken.find_by_token(token)
    if not rt:
        return render_template("reset_password.html", success=False)

    user = db.session.get(User, rt.email)
    if user:
        new_pass = request.form.get("password", "")
        v_pass, err_pass = validate_password(new_pass)
        if not v_pass:
            flash(err_pass, "error")
            return render_template("reset_password.html", success=False)
        user.set_password(new_pass)
        db.session.delete(rt)
        db.session.commit()
        return redirect(url_for("auth.login"))
    
    return render_template("reset_password.html", success=False)