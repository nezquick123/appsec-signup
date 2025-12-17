from flask import Blueprint, render_template, request
from ..models import db, User
from ..utils.security import token_required

main_bp = Blueprint('main', __name__)

@main_bp.route("/dashboard")
@token_required
def dashboard():
    user = db.session.get(User, request.user_email)
    return render_template(
        "dashboard.html", 
        username=getattr(request, "username", ""), 
        is_mfa_enabled=user.is_mfa_enabled
    )

@main_bp.route("/success")
def success():
    title = request.args.get('title', 'Success!')
    message = request.args.get('message', 'Operation successful.')
    return render_template("success.html", title=title, message=message)