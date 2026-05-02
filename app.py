from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from verifier import verify_password, generate_temporary_password, send_recovery_email, verify_email, generate_verification_token, send_verification_email


import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "data", "users.db")


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    columns = conn.execute("PRAGMA table_info(usuarios)").fetchall()
    column_names = [column["name"] for column in columns]


    if "email_verified" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN email_verified INTEGER DEFAULT 0"
    )

    if "verification_token" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN verification_token TEXT"
    )


    if "must_reset_password" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN must_reset_password INTEGER DEFAULT 0"
    )
        
    conn.commit()
    conn.close()


@app.route("/main")
def main_page():
    
    if "usuario" not in session:
        return redirect(url_for("login"))

    return render_template("main_page.html")


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        password = request.form.get("password")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM usuarios WHERE usuario = ?",
            (usuario,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            if user["email_verified"] == 0:
                return render_template(
                    "login.html",
                    error="You must verify your email before logging in"
                )

            session["usuario"] = usuario
            session["user_id"] = user["id"]

            if user["must_reset_password"] == 1:
                return redirect(url_for("change_password"))

            return redirect(url_for("main_page"))

        else:
            error = "Username or password is incorrect, please try again"
            return render_template("login.html", error=error)

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("usuario", None)
    return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot_credentials():

    if request.method == "POST":
        email = request.form.get("email")

        is_email_valid, email_error = verify_email(email)
        if not is_email_valid:
            return render_template("forgot.html", error=email_error)

        email = email.strip().lower()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM usuarios WHERE email = ?",
            (email,)
        ).fetchone()

        if user:
            temp_password = generate_temporary_password()
            temp_hash = generate_password_hash(temp_password)

            conn.execute(
                "UPDATE usuarios SET password_hash = ?, must_reset_password = 1 WHERE id = ?",
                (temp_hash, user["id"])
            )

            conn.commit()

            send_recovery_email(user["email"], user["usuario"], temp_password)

        conn.close()

        return render_template(
                "forgot.html",
                success="If that email exists, you will receive recovery instructions."
            )


    return render_template("forgot.html")


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM usuarios WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], current_password):
            conn.close()
            return render_template(
                "change_password.html",
                error="The current password is incorrect"
            )

        is_valid, error = verify_password(
            user["usuario"],
            new_password,
            confirm_password
        )

        if not is_valid:
            conn.close()
            return render_template("change_password.html", error=error)

        new_hash = generate_password_hash(new_password)

        conn.execute(
            "UPDATE usuarios SET password_hash = ?, must_reset_password = 0 WHERE id = ?",
            (new_hash, session["user_id"])
        )
        conn.commit()
        conn.close()

        return redirect(url_for("main_page"))

    return render_template("change_password.html")

@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        email = request.form.get("email")


        is_email_valid, email_error = verify_email(email)
        if not is_email_valid:
            return render_template("registro.html", error=email_error)

        email = email.strip().lower()


        if not usuario:
            return render_template("registro.html", error="Please enter a username")

        is_valid, error = verify_password(usuario, password, confirm_password)

        if not is_valid:
            return render_template("registro.html", error=error)

        password_hash = generate_password_hash(password)

        try:
            conn = get_db_connection()
            verification_token = generate_verification_token()

            conn.execute(
                """
                INSERT INTO usuarios 
                (usuario, email, password_hash, email_verified, verification_token)
                VALUES (?, ?, ?, ?, ?)
                """,
                (usuario, email, password_hash, 0, verification_token)
            )
            conn.commit()

            verification_link = url_for(
                "verify_account",
                token=verification_token,
                _external=True
            )

            send_verification_email(email, usuario, verification_link)

            conn.close()

            return render_template("reg_success.html")


        except sqlite3.IntegrityError:
            return render_template("registro.html", error="That username or email already exists")

    return render_template("registro.html")


@app.route("/verify-email/<token>")
def verify_account(token):
    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM usuarios WHERE verification_token = ?",
        (token,)
    ).fetchone()

    if not user:
        conn.close()
        return "Invalid or expired token"

    conn.execute(
        """
        UPDATE usuarios
        SET email_verified = 1, verification_token = NULL
        WHERE id = ?
        """,
        (user["id"],)
    )

    conn.commit()
    conn.close()

    return render_template("verify_success.html")



if __name__ == "__main__":
    init_db()
    app.run(debug=True)
