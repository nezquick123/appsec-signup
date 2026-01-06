from flask import Blueprint, render_template, request, flash, redirect, url_for
from ..models import db, User, RefreshToken
from ..utils.security import token_required, role_required
from ..models import UserRole
import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)

@admin_bp.route("/admin/owner")
@role_required(role="OWNER")
def owner_panel():
    # fetch all users email, username, role
    users = db.session.execute(db.select(User)).scalars().all()


    return render_template(
        "owner_panel.html", 
        users=users,
    )


@admin_bp.route("/admin/change_role/<string:email>", methods=["POST"])
@role_required(role="OWNER")
def change_role(email):
    new_role_name = request.form.get("new_role")

    user = db.session.get(User, email)
    
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin.owner_panel"))

    if user.email == request.user_email and new_role_name != "OWNER":
        flash("You cannot demote yourself. Another owner must do this.", "error")
        return redirect(url_for("admin.owner_panel"))

    try:
        new_role_enum = UserRole[new_role_name]

        user.role = new_role_enum
        db.session.commit()

        # revoke session if exists
        rt_db = RefreshToken.query.filter_by(email=user.email).first()
        logger.info(f"Revoking refresh token for user {user.email} due to role change.")
        if rt_db:
            rt_db.revoked = True
            db.session.add(rt_db)
            db.session.commit()

        
        flash(f"Successfully updated {user.username} to {new_role_name}.", "success")
        
    except KeyError:
        flash("Invalid role selection.", "error")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while updating the role.", "error")

    return redirect(url_for("admin.owner_panel"))