import re

from flask import Flask, render_template, request, flash, redirect, url_for
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import IntegrityError

from config import Config
from models import db, User

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)


def validate_username(username):
    """Validate username format."""
    if not username or len(username) < 3 or len(username) > 80:
        return False, "Username must be between 3 and 80 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores."
    return True, ""


def validate_password(password):
    """Validate password strength."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must be less than 128 characters."
    return True, ""


def validate_user_email(email):
    """Validate email format."""
    try:
        validate_email(email, check_deliverability=False)
        return True, ""
    except EmailNotValidError as e:
        return False, str(e)


@app.route("/", methods=["GET", "POST"])
def signup():
    """Handle signup form display and submission."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Validate username
        valid, error = validate_username(username)
        if not valid:
            flash(error, "error")
            return render_template("signup.html", username=username, email=email)

        # Validate email
        valid, error = validate_user_email(email)
        if not valid:
            flash(error, "error")
            return render_template("signup.html", username=username, email=email)

        # Validate password
        valid, error = validate_password(password)
        if not valid:
            flash(error, "error")
            return render_template("signup.html", username=username, email=email)

        # Create user
        try:
            user = User(username=username, email=email, password=password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("success"))
        except IntegrityError:
            db.session.rollback()
            flash("Username or email already exists.", "error")
            return render_template("signup.html", username=username, email=email)

    return render_template("signup.html")


@app.route("/success")
def success():
    """Display success page after signup."""
    return render_template("success.html")


def init_db():
    """Initialize the database."""
    with app.app_context():
        db.create_all()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
