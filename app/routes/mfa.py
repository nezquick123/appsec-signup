from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response, current_app, session
import pyotp
import qrcode
import io
import base64
from ..models import db, User
from ..utils.security import token_required, create_access_token, create_refresh_token

mfa_bp = Blueprint('mfa', __name__)

@mfa_bp.route("/mfa/setup")
@token_required
def mfa_setup():
    user = db.session.get(User, request.user_email)
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.session.commit()

    totp_uri = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(name=user.email, issuer_name="AppSecSignup")
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return render_template("mfa_setup.html", qr_code=img_str, secret=user.mfa_secret)

@mfa_bp.route("/mfa/enable", methods=["POST"])
@token_required
def mfa_enable():
    user = db.session.get(User, request.user_email)
    code = request.form.get("code")
    if not user.mfa_secret:
        return redirect(url_for("main.dashboard"))

    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code):
        user.is_mfa_enabled = True
        db.session.commit()
        flash("Two-Factor Authentication enabled!", "success")
        return redirect(url_for("main.dashboard"))
    else:
        flash("Invalid code.", "error")
        return redirect(url_for("mfa.mfa_setup"))

@mfa_bp.route("/login/2fa", methods=["GET", "POST"])
def verify_2fa_login():
    email = session.get('2fa_user_email')
    if not email:
        flash("Session expired.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code")
        user = db.session.get(User, email)

        if not user or not user.mfa_secret:
            session.pop('2fa_user_email', None)
            return redirect(url_for("auth.login"))

        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            session.pop('2fa_user_email', None)
            access_token = create_access_token(user.email, user.username)
            refresh_token, _ = create_refresh_token(user.email)

            resp = make_response(redirect(url_for("main.dashboard")))
            resp.set_cookie("refresh_token", refresh_token, httponly=True, secure=current_app.config.get("FORCE_HTTPS", False), samesite="Lax", max_age=current_app.config.get("REFRESH_TOKEN_EXPIRE_DAYS") * 24 * 3600)
            resp.set_cookie("access_token", access_token, httponly=True, secure=current_app.config.get("FORCE_HTTPS", False), samesite="Lax", max_age=current_app.config.get("ACCESS_TOKEN_EXPIRE_MINUTES") * 60)
            flash("Logged in with MFA!", "success")
            return resp
        else:
            flash("Invalid 2FA code.", "error")

    return render_template("mfa_verify.html")

@mfa_bp.route("/mfa/disable", methods=["GET", "POST"])
@token_required
def mfa_disable():
    user = db.session.get(User, request.user_email)
    if not user.is_mfa_enabled:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        password = request.form.get("password", "")
        if user.check_password(password):
            user.is_mfa_enabled = False
            user.mfa_secret = None
            db.session.commit()
            flash("Two-Factor Authentication disabled.", "success")
            return redirect(url_for("main.dashboard"))
        else:
            flash("Incorrect password.", "error")
    
    return render_template("mfa_disable.html")