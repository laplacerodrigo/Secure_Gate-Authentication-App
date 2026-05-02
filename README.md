# SecureGate

SecureGate is a Flask-based authentication web application that implements a complete and secure user authentication flow. Built with Python, SQLite, HTML, CSS, and JavaScript, the project covers everything from registration and email verification to password recovery and protected routes.

---

## Features

- User registration with username, email, password, and password confirmation
- Email format validation using regular expressions
- Password strength validation
- Password hashing with Werkzeug before storing credentials
- SQLite database for local storage
- Email verification required before login
- Password recovery via temporary password sent by email
- Forced password reset after using a temporary password
- Protected main page accessible only after login
- Logout functionality
- Dark mode interface with turquoise neon animations and smooth page-entry transitions
- Favicon support

---

## Technologies Used

- Python + Flask
- SQLite
- HTML / CSS / JavaScript
- Werkzeug (password hashing)
- SMTP email service

---

## How It Works

### Registration Flow

The user submits a username, email, password, and password confirmation. The application validates that the email format is correct, the password fields are not empty, both passwords match, the password has at least 12 characters, the password is not the same as the username, and the password is not a commonly used password. After validation, the password is hashed and the account is saved with `email_verified = 0`, meaning the user cannot log in until verifying their email.

![Account Registration](images\registration_page.png)

### Email Verification Flow

After registration, a secure token is generated and a verification link is sent to the user's email. The link points to `/verify-email/<token>`. When opened, the app checks the token and, if valid, updates the account to `email_verified = 1` and clears the token.

![Account Validation](images\email_verification_page.png)
![Email Authentication Sent](images\email_verification_page_1.png)
![Account finally active](images\email_verification_page_1.png)

### Login Flow

The app looks up the submitted username in the database, checks the password against the stored hash, and confirms that the email has been verified. If the user is logging in with a temporary recovery password, they are redirected to the change password screen before reaching the main page.

![Login Screen - User Ready to use credentials](images\login_page.png)

### Password Recovery Flow

The user submits their email address. If it exists, the app generates a random temporary password, hashes it, replaces the current password hash in the database, and marks the account with `must_reset_password = 1`. The username and temporary password are then sent by email. The app always returns a generic message — *"If that email exists, you will receive recovery instructions."* — to avoid exposing whether an email is registered.

![Forgotten or compromised Password](images\password_recovery.png)
![Check if the email is registered on the Database](images\password_recovery_1.png)
![Temporary Password Delivered](images\password_recovery_2.png)

### Forced Password Reset Flow

After logging in with a temporary password, the user is redirected to a change password page. They must provide the current temporary password, a new password, and a confirmation. The new password goes through the same validation rules as registration. On success, the new hash is saved and `must_reset_password` is reset to `0`.

![Temporary Password Force Change](images\password_recovery_3.png)

### Main Page

The main page is protected by Flask sessions. Any unauthenticated access attempt redirects to the login page. The page includes an animated futuristic interface and a logout option.

![Main Look of the page ;)](images\main_page.png)

---

## Database

SQLite is used as the local database. The main user table stores the following fields:

| Field | Description |
|---|---|
| `id` | Unique user ID |
| `usuario` | Username |
| `email` | Email address |
| `password_hash` | Hashed password |
| `email_verified` | `0` unverified / `1` verified |
| `verification_token` | Token for email verification |
| `must_reset_password` | `1` if a forced reset is required |

---

## Environment Variables

Before running the app, define the following environment variables:

```bash
$env:EMAIL_USER="your_email@gmail.com"
$env:EMAIL_PASSWORD="your_google_app_password"
$env:SECRET_KEY="your_secret_key"
```

> If using Gmail, `EMAIL_PASSWORD` must be a **Google App Password**, not your regular Gmail password.

---

## Running the Project

```bash
# Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# If PowerShell blocks script execution
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# Install Flask
pip install flask

# Run the application
python app.py
```

Open the app at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Security Notes

This project applies several important authentication practices: passwords are never stored as plain text, email verification is required before login, temporary passwords are randomly generated, users must reset their password after recovery, and generic recovery messages avoid exposing registered emails.

For a production deployment, the following should also be added: HTTPS, strong secret key management, rate limiting for login and recovery attempts, CSRF protection, token expiration, environment variable management via `.env`, a production-grade database, and a production WSGI server.

---

## Recommended `.gitignore`

```
venv/
__pycache__/
*.pyc
.env
data/*.db
```

---

## Future Improvements

- Rename Spanish internal variable names to English
- Add CSRF protection
- Add token expiration for email verification and password recovery
- Add rate limiting
- Add stronger password breach checking (e.g., HaveIBeenPwned API)
- Add HTML email templates
- Add user profile page
- Add admin dashboard
- Add Docker support
- Add automated tests

---

## License

This project is for educational purposes.
