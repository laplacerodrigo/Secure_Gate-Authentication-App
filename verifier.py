import secrets
import string
from email.message import EmailMessage
import smtplib
import os
import re
import hashlib
import ssl

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "123456789",
    "admin",
    "admin123",
    "qwerty",
    "letmein",
    "welcome",
}


def generate_verification_token():
    return secrets.token_urlsafe(32)

def generate_verification_code():
    return "".join(secrets.choice(string.digits) for _ in range(8))


def generate_recovery_token():
    return secrets.token_urlsafe(32)


def hash_recovery_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_smtp_settings():
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "465"))
    username = os.environ.get("SMTP_USERNAME") or os.environ.get("EMAIL_USER")
    password = os.environ.get("SMTP_PASSWORD") or os.environ.get("EMAIL_PASSWORD")
    sender = os.environ.get("EMAIL_FROM") or username

    if not host or not port or not username or not password or not sender:
        raise RuntimeError("Missing SMTP email configuration")

    return host, port, username, password, sender


def send_email(to_email, subject, body):
    host, port, username, password, sender = get_smtp_settings()
    ssl_context = ssl.create_default_context()

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_email
    message.set_content(body)

    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ssl_context) as smtp:
            smtp.login(username, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port) as smtp:
            smtp.starttls(context=ssl_context)
            smtp.login(username, password)
            smtp.send_message(message)


def send_verification_email(to_email, username, verification_link, verification_code):
    body = f"""
Hello {username},

Please verify your account by clicking this link:

{verification_link}

Then enter this 8-digit verification code:

{verification_code}
"""
    send_email(to_email, "Verify your account", body)



def verify_email(email):
    if not email:
        return False, "Please enter an email"

    email = email.strip().lower()

    email_pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

    if not re.match(email_pattern, email):
        return False, "Please enter a valid email"

    return True, None



def verify_password(usuario, password, confirm_password):
    if not password or not confirm_password:
        return False, "Please fill in the password fields"

    if password != confirm_password:
        return False, "Passwords do not match"

    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if usuario and password.lower() == usuario.lower():
        return False, "Password cannot be the same as the username"

    if password.lower() in COMMON_PASSWORDS:
        return False, "That password is too common"

    return True, None


def send_recovery_email(to_email, username, reset_link):
    body = f"""
Hello {username},

Use this one-time link to reset your password:

{reset_link}

This link expires in 15 minutes. If you did not request a password reset, ignore this email.
"""
    send_email(to_email, "Account recovery", body)
