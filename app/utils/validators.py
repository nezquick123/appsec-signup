import re
from email_validator import validate_email, EmailNotValidError
from flask import current_app

def validate_username(username):
    if not username or len(username) < 3 or len(username) > 80:
        return False, "Username must be between 3 and 80 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores."
    return True, ""

def validate_password(password):
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
    if not phone:
        return True, ""
    if len(phone) > 20:
        return False, "Phone number is too long."
    phone_pattern = r"^[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}$"
    if not re.match(phone_pattern, phone):
        return False, "Please enter a valid phone number."
    return True, ""

def validate_user_email(email):
    try:
        validated = validate_email(email, check_deliverability=False)
        domain = validated.domain

        whitelist = current_app.config.get("EMAIL_DOMAIN_WHITELIST", "")
        if whitelist:
            allowed_domains = [d.strip().lower() for d in whitelist.split(",") if d.strip()]
            if domain.lower() not in allowed_domains:
                return False, f"Email domain '{domain}' is not allowed."

        blacklist = current_app.config.get("EMAIL_DOMAIN_BLACKLIST", "")
        if blacklist:
            blocked_domains = [d.strip().lower() for d in blacklist.split(",") if d.strip()]
            if domain.lower() in blocked_domains:
                return False, f"Email domain '{domain}' is not allowed."

        return True, ""
    except EmailNotValidError as e:
        return False, str(e)