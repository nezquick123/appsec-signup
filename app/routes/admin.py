from flask import Blueprint, render_template, request, flash, redirect, url_for
from ..models import db, User
from ..utils.security import token_required, role_required
from ..models import UserRole


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
        
        flash(f"Successfully updated {user.username} to {new_role_name}.", "success")
        
    except KeyError:
        flash("Invalid role selection.", "error")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while updating the role.", "error")

    return redirect(url_for("admin.owner_panel"))