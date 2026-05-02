import secrets
import string
from email.message import EmailMessage
import smtplib
import os
import re

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

def send_verification_email(to_email, username, verification_link):
    sender = os.environ.get("EMAIL_USER")
    password = os.environ.get("EMAIL_PASSWORD")

    message = EmailMessage()
    message["Subject"] = "Verify your account"
    message["From"] = sender
    message["To"] = to_email

    message.set_content(f"""
Hello {username},

Please verify your account by clicking this link:

{verification_link}
""")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender, password)
        smtp.send_message(message)



def generate_temporary_password(length=14):
    characters = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(characters) for _ in range(length))



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


def send_recovery_email(to_email, username, temp_password):

    sender = os.environ.get("EMAIL_USER")
    password = os.environ.get("EMAIL_PASSWORD")


    print("SENDER:", sender)
    print("PASSWORD LOADED:", bool(password))
    print("PASSWORD LENGTH:", len(password) if password else 0)


    if not sender or not password:
        raise RuntimeError("Missing EMAIL_USER or EMAIL_PASSWORD")

    message = EmailMessage()
    message["Subject"] = "Account recovery"
    message["From"] = sender
    message["To"] = to_email
    message.set_content(f"""
        Hello,

        Your username is: {username}
        Your temporary password is: {temp_password}

        Please log in and change your password.
        """)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(message)
