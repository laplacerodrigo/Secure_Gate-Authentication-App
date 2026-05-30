from flask import Flask, abort, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from verifier import verify_password, send_recovery_email, verify_email, generate_verification_token, generate_verification_code, generate_recovery_token, hash_recovery_token, send_verification_email


import os
import hmac
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

app = Flask(__name__)
secret_key = os.environ.get("LOGIN_WEB_SECRET_KEY") or os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("LOGIN_WEB_SECRET_KEY must be configured")
app.secret_key = secret_key


def env_flag(name, default="1"):
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


app.config.update(
    SESSION_COOKIE_NAME="client_session",
    SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MEDIA_DIR = os.path.join(PROJECT_ROOT, "media")
DEFAULT_DATA_DIR = os.path.join(os.path.dirname(PROJECT_ROOT), "laplace-data")
DB_NAME = os.environ.get("LAPLACE_DB_PATH", os.path.join(DEFAULT_DATA_DIR, "users.db"))
PROFILE_UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads", "profiles")
ALLOWED_PROFILE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
PUBLIC_MEDIA_FILES = {"favicon.png"}
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_IP_LIMIT = 5
ACCOUNT_LOCK_SECONDS = 30 * 60
VERIFY_WINDOW_SECONDS = 10 * 60
VERIFY_IP_LIMIT = 3
RECOVERY_WINDOW_SECONDS = 15 * 60
RECOVERY_IP_LIMIT = 5


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}


@app.before_request
def validate_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    expected = session.get("_csrf_token", "")
    submitted = request.form.get("_csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        abort(400, description="Invalid CSRF token")


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def is_rate_limited(bucket_name, key, limit, window_seconds, consume=True):
    now = int(time.time())
    bucket_key = f"{bucket_name}:{key}"
    conn = get_db_connection()
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute(
        "SELECT window_started, request_count FROM auth_rate_limits WHERE action_key = ?",
        (bucket_key,),
    ).fetchone()
    if not row or now - int(row["window_started"]) >= window_seconds:
        window_started = now
        request_count = 0
    else:
        window_started = int(row["window_started"])
        request_count = int(row["request_count"])
    limited = request_count >= limit
    if consume and not limited:
        request_count += 1
    conn.execute(
        """
        INSERT INTO auth_rate_limits (action_key, window_started, request_count)
        VALUES (?, ?, ?)
        ON CONFLICT(action_key) DO UPDATE SET
            window_started = excluded.window_started,
            request_count = excluded.request_count
        """,
        (bucket_key, window_started, request_count),
    )
    conn.commit()
    conn.close()
    return limited


def parse_timestamp(value):
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def timestamp_is_expired(value):
    parsed = parse_timestamp(value)
    return not parsed or parsed <= datetime.utcnow()


def account_is_locked(user):
    locked_until = parse_timestamp(user["locked_until"])
    return bool(locked_until and locked_until > datetime.utcnow())


def record_failed_login(conn, user):
    if not user:
        return
    failures = int(user["failed_login_attempts"] or 0) + 1
    locked_until = (datetime.utcnow() + timedelta(seconds=ACCOUNT_LOCK_SECONDS)).isoformat(timespec="seconds") if failures >= 10 else None
    conn.execute(
        "UPDATE usuarios SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
        (failures, locked_until, user["id"]),
    )
    conn.commit()


def clear_failed_logins(conn, user_id):
    conn.execute("UPDATE usuarios SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
    conn.commit()

TRANSLATIONS = {
    "en": {
        "nav.overview": "Overview",
        "nav.subscription": "My Subscription",
        "nav.contracts": "Contracts",
        "nav.invoices": "Invoices & Payments",
        "nav.tickets": "Support Tickets",
        "nav.projects": "Project Status",
        "nav.documents": "Documents",
        "nav.settings": "Settings",
        "portal.client_portal": "Client Portal",
        "portal.logout": "Log Out",
        "portal.brand": "Laplace Electric",
        "portal.your_company": "Your company",
        "portal.open_menu": "Open client menu",
        "portal.close_menu": "Close client menu",
        "metrics.projects": "Projects",
        "metrics.projects_help": "Active or visible projects",
        "metrics.contracts": "Contracts",
        "metrics.contracts_help": "Agreements on file",
        "metrics.open_tickets": "Open Tickets",
        "metrics.open_tickets_help": "Support conversations",
        "metrics.invoice_total": "Invoice Total",
        "metrics.invoice_total_help": "Visible invoices total",
        "overview.subscription": "Current Subscription",
        "overview.view": "View",
        "overview.renewal": "Renewal or next checkpoint",
        "overview.no_subscription": "No active subscription is linked to this account yet.",
        "overview.recent_tickets": "Recent Tickets",
        "overview.open_support": "Open support",
        "overview.no_tickets": "No support tickets yet.",
        "subscription.summary": "Subscription Summary",
        "subscription.plan": "Plan",
        "subscription.status": "Status",
        "subscription.next": "Next checkpoint",
        "subscription.default_title": "Website maintenance plan",
        "subscription.proposal_stage": "Proposal stage",
        "subscription.pending_approval": "Pending approval",
        "subscription.empty": "No subscription is active yet. Once a maintenance contract is approved, it will appear here.",
        "contracts.title": "Contracts",
        "contracts.fallback": "Contract",
        "contracts.see_contract": "See Contract",
        "contracts.empty": "No contracts are linked to your company yet.",
        "contract.document_title": "Service Contract",
        "contract.back_to_contracts": "Back to contracts",
        "contract.print": "Download PDF",
        "contract.client": "Client",
        "contract.date": "Contract Date",
        "contract.start_date": "Start Date",
        "contract.end_date": "End Date",
        "contract.service_description": "Service Description",
        "contract.scope_of_work": "Scope of Work",
        "contract.internal_notes": "Internal Notes",
        "contract.generated_on": "Generated on",
        "contract.electronic_copy": "This is an electronic copy of the service contract.",
        "invoices.title": "Invoices & Payments",
        "invoices.fallback": "Invoice",
        "invoices.see_invoice": "See Invoice",
        "invoices.empty": "No invoices are linked to your company yet.",
        "invoice.document_title": "INVOICE",
        "invoice.back_to_invoices": "Back to invoices",
        "invoice.print": "Print",
        "invoice.from": "From",
        "invoice.to": "Bill To",
        "invoice.date_issued": "Issue Date",
        "invoice.due_date": "Due Date",
        "invoice.status_label": "Status",
        "invoice.status_paid": "Paid",
        "invoice.status_pending": "Pending",
        "invoice.status_cancelled": "Cancelled",
        "invoice.status_partial": "Partial Payment",
        "invoice.remaining": "Remaining",
        "invoice.ref": "Invoice #",
        "invoice.description": "Description",
        "invoice.qty": "Qty",
        "invoice.unit_price": "Unit Price",
        "invoice.total": "Total",
        "invoice.subtotal": "Subtotal",
        "invoice.tax": "Tax",
        "invoice.total_due": "Total Due",
        "invoice.notes": "Notes",
        "invoice.generated_on": "Generated on",
        "invoice.footer_disclaimer": "This is an electronic copy of the original invoice issued by Laplace Electric.",
        "invoice.laplace_address": "San Jose, Costa Rica",
        "invoice.laplace_tax_id": "Tax ID: 3-101-XXXXXX",
        "pagination.previous": "Previous",
        "pagination.next": "Next",
        "pagination.page": "Page",
        "pagination.of": "of",
        "tickets.submit": "Submit Ticket",
        "tickets.created": "Ticket submitted successfully.",
        "tickets.subject": "Subject",
        "tickets.subject_placeholder": "Briefly describe the issue",
        "tickets.category": "Category",
        "tickets.priority": "Priority",
        "tickets.message": "Message",
        "tickets.message_placeholder": "Tell us what happened or what you need",
        "tickets.submit_button": "Submit Ticket",
        "tickets.your": "Your Tickets",
        "tickets.category.website": "Website Support",
        "tickets.category.subscription": "Subscription",
        "tickets.category.billing": "Billing",
        "tickets.category.technical": "Technical Issue",
        "tickets.category.general": "General Support",
        "tickets.priority.normal": "Normal",
        "tickets.priority.high": "High",
        "tickets.priority.urgent": "Urgent",
        "projects.title": "Project Status",
        "projects.empty": "No projects are linked to your company yet.",
        "documents.title": "Documents",
        "documents.proposal": "Proposal",
        "documents.invoice": "Invoice",
        "documents.commercial_proposal": "Commercial proposal",
        "documents.empty": "No documents are available yet.",
        "settings.title": "Client Settings",
        "settings.saved": "Settings saved.",
        "settings.language": "Language",
        "settings.language_en": "English",
        "settings.language_es": "Spanish",
        "settings.profile_photo": "Profile photo",
        "settings.drop_image": "Drop an image here",
        "settings.choose_image": "or click to choose PNG, JPG, WebP or GIF",
        "settings.no_file": "No file selected",
        "settings.display_name": "Display name",
        "settings.display_placeholder": "Demo Client",
        "settings.company": "Company",
        "settings.company_placeholder": "Company name",
        "settings.whatsapp": "WhatsApp",
        "settings.account_email": "Account email",
        "settings.notifications": "Notification preferences",
        "settings.notify_email": "Email updates",
        "settings.notify_tickets": "Support ticket updates",
        "settings.notify_projects": "Project status changes",
        "settings.notify_invoices": "Invoices and payments",
        "settings.save_profile": "Save Profile",
        "settings.change_password": "Change Password",
        "settings.password_saved": "Password updated.",
        "settings.password_current_error": "Current password is incorrect.",
        "settings.password_invalid_error": "New password must be valid and match confirmation.",
        "settings.current_password": "Current password",
        "settings.new_password": "New password",
        "settings.confirm_password": "Confirm new password",
        "settings.update_password": "Update Password",
        "settings.preview_alt": "Selected profile photo preview",
        "status.canceled": "Canceled",
        "status.draft": "Draft",
        "status.open": "Open",
        "status.accepted": "Accepted",
        "status.closed": "Closed",
        "status.billed": "Billed",
        "date.not_scheduled": "Not scheduled",
    },
    "es": {
        "nav.overview": "Resumen",
        "nav.subscription": "Mi Suscripción",
        "nav.contracts": "Contratos",
        "nav.invoices": "Facturas y Pagos",
        "nav.tickets": "Tickets de Soporte",
        "nav.projects": "Estado del Proyecto",
        "nav.documents": "Documentos",
        "nav.settings": "Configuración",
        "portal.client_portal": "Portal de Cliente",
        "portal.logout": "Cerrar Sesión",
        "portal.brand": "Laplace Electric",
        "portal.your_company": "Tu empresa",
        "portal.open_menu": "Abrir menú del cliente",
        "portal.close_menu": "Cerrar menú del cliente",
        "metrics.projects": "Proyectos",
        "metrics.projects_help": "Proyectos activos o visibles",
        "metrics.contracts": "Contratos",
        "metrics.contracts_help": "Acuerdos registrados",
        "metrics.open_tickets": "Tickets Abiertos",
        "metrics.open_tickets_help": "Conversaciones de soporte",
        "metrics.invoice_total": "Total Facturado",
        "metrics.invoice_total_help": "Total visible de facturas",
        "overview.subscription": "Suscripción Actual",
        "overview.view": "Ver",
        "overview.renewal": "Renovación o próximo punto de revisión",
        "overview.no_subscription": "No hay una suscripción activa vinculada a esta cuenta todavía.",
        "overview.recent_tickets": "Tickets Recientes",
        "overview.open_support": "Abrir soporte",
        "overview.no_tickets": "Aún no hay tickets de soporte.",
        "subscription.summary": "Resumen de Suscripción",
        "subscription.plan": "Plan",
        "subscription.status": "Estado",
        "subscription.next": "Próximo punto de revisión",
        "subscription.default_title": "Plan de mantenimiento web",
        "subscription.proposal_stage": "Etapa de propuesta",
        "subscription.pending_approval": "Pendiente de aprobación",
        "subscription.empty": "Aún no hay una suscripción activa. Cuando se apruebe un contrato de mantenimiento, aparecerá aquí.",
        "contracts.title": "Contratos",
        "contracts.fallback": "Contrato",
        "contracts.see_contract": "Ver Contrato",
        "contracts.empty": "Aún no hay contratos vinculados a tu empresa.",
        "contract.document_title": "Contrato de Servicio",
        "contract.back_to_contracts": "Volver a contratos",
        "contract.print": "Descargar PDF",
        "contract.client": "Cliente",
        "contract.date": "Fecha del Contrato",
        "contract.start_date": "Fecha de Inicio",
        "contract.end_date": "Fecha de Fin",
        "contract.service_description": "Descripción del Servicio",
        "contract.scope_of_work": "Alcance del Trabajo",
        "contract.internal_notes": "Notas Internas",
        "contract.generated_on": "Generado el",
        "contract.electronic_copy": "Esta es una copia electrónica del contrato de servicio.",
        "invoices.title": "Facturas y Pagos",
        "invoices.fallback": "Factura",
        "invoices.see_invoice": "Ver Factura",
        "invoices.empty": "Aún no hay facturas vinculadas a tu empresa.",
        "invoice.document_title": "FACTURA",
        "invoice.back_to_invoices": "Volver a facturas",
        "invoice.print": "Imprimir",
        "invoice.from": "De",
        "invoice.to": "Facturar a",
        "invoice.date_issued": "Fecha de Emisión",
        "invoice.due_date": "Fecha de Vencimiento",
        "invoice.status_label": "Estado",
        "invoice.status_paid": "Pagada",
        "invoice.status_pending": "Pendiente",
        "invoice.status_cancelled": "Cancelada",
        "invoice.status_partial": "Pago Parcial",
        "invoice.remaining": "Pendiente",
        "invoice.ref": "Factura #",
        "invoice.description": "Descripción",
        "invoice.qty": "Cant",
        "invoice.unit_price": "Precio Unit.",
        "invoice.total": "Total",
        "invoice.subtotal": "Subtotal",
        "invoice.tax": "IVA",
        "invoice.total_due": "Total a Pagar",
        "invoice.notes": "Notas",
        "invoice.generated_on": "Generado el",
        "invoice.footer_disclaimer": "Esta es una copia electrónica de la factura original emitida por Laplace Electric.",
        "invoice.laplace_address": "San José, Costa Rica",
        "invoice.laplace_tax_id": "Cédula Jurídica: 3-101-XXXXXX",
        "pagination.previous": "Anterior",
        "pagination.next": "Siguiente",
        "pagination.page": "Página",
        "pagination.of": "de",
        "tickets.submit": "Enviar Ticket",
        "tickets.created": "Ticket enviado correctamente.",
        "tickets.subject": "Asunto",
        "tickets.subject_placeholder": "Describe brevemente el problema",
        "tickets.category": "Categoría",
        "tickets.priority": "Prioridad",
        "tickets.message": "Mensaje",
        "tickets.message_placeholder": "Contanos qué pasó o qué necesitás",
        "tickets.submit_button": "Enviar Ticket",
        "tickets.your": "Tus Tickets",
        "tickets.category.website": "Soporte del Sitio Web",
        "tickets.category.subscription": "Suscripción",
        "tickets.category.billing": "Facturación",
        "tickets.category.technical": "Problema Técnico",
        "tickets.category.general": "Soporte General",
        "tickets.priority.normal": "Normal",
        "tickets.priority.high": "Alta",
        "tickets.priority.urgent": "Urgente",
        "projects.title": "Estado del Proyecto",
        "projects.empty": "Aún no hay proyectos vinculados a tu empresa.",
        "documents.title": "Documentos",
        "documents.proposal": "Propuesta",
        "documents.invoice": "Factura",
        "documents.commercial_proposal": "Propuesta comercial",
        "documents.empty": "Aún no hay documentos disponibles.",
        "settings.title": "Configuración del Cliente",
        "settings.saved": "Configuración guardada.",
        "settings.language": "Idioma",
        "settings.language_en": "Inglés",
        "settings.language_es": "Español",
        "settings.profile_photo": "Foto de perfil",
        "settings.drop_image": "Arrastrá una imagen aquí",
        "settings.choose_image": "o hacé click para elegir PNG, JPG, WebP o GIF",
        "settings.no_file": "Ningún archivo seleccionado",
        "settings.display_name": "Nombre visible",
        "settings.display_placeholder": "Demo Client",
        "settings.company": "Empresa",
        "settings.company_placeholder": "Nombre de la empresa",
        "settings.whatsapp": "WhatsApp",
        "settings.account_email": "Correo de la cuenta",
        "settings.notifications": "Preferencias de notificación",
        "settings.notify_email": "Actualizaciones por email",
        "settings.notify_tickets": "Actualizaciones de tickets",
        "settings.notify_projects": "Cambios de estado del proyecto",
        "settings.notify_invoices": "Facturas y pagos",
        "settings.save_profile": "Guardar Perfil",
        "settings.change_password": "Cambiar Contraseña",
        "settings.password_saved": "Contraseña actualizada.",
        "settings.password_current_error": "La contraseña actual es incorrecta.",
        "settings.password_invalid_error": "La nueva contraseña debe ser válida y coincidir con la confirmación.",
        "settings.current_password": "Contraseña actual",
        "settings.new_password": "Nueva contraseña",
        "settings.confirm_password": "Confirmar nueva contraseña",
        "settings.update_password": "Actualizar Contraseña",
        "settings.preview_alt": "Vista previa de la foto de perfil seleccionada",
        "status.canceled": "Cancelado",
        "status.draft": "Borrador",
        "status.open": "Abierto",
        "status.accepted": "Aceptado",
        "status.closed": "Cerrado",
        "status.billed": "Facturado",
        "date.not_scheduled": "Sin programar",
    },
}


def get_translator(language):
    lang = language if language in TRANSLATIONS else "en"

    def translate(key):
        return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, TRANSLATIONS["en"].get(key, key))

    return translate


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column(conn, table, column, definition):
    cols = [c["name"] for c in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    os.makedirs(os.path.dirname(DB_NAME), exist_ok=True)

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_rate_limits (
            action_key TEXT PRIMARY KEY,
            window_started INTEGER NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0
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

    if "verification_code_hash" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN verification_code_hash TEXT"
    )

    if "verification_code_expires" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN verification_code_expires TEXT"
    )

    if "verification_failed_attempts" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN verification_failed_attempts INTEGER DEFAULT 0"
    )

    if "reset_token_hash" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN reset_token_hash TEXT"
    )

    if "reset_token_expires" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN reset_token_expires TEXT"
    )

    if "failed_login_attempts" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"
    )

    if "locked_until" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN locked_until TEXT"
    )


    if "must_reset_password" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN must_reset_password INTEGER DEFAULT 0"
    )

    if "company_name" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN company_name TEXT"
    )

    if "display_name" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN display_name TEXT"
    )

    if "whatsapp" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN whatsapp TEXT"
    )

    if "profile_photo" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN profile_photo TEXT"
    )

    if "notify_email" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN notify_email INTEGER DEFAULT 1"
    )

    if "notify_tickets" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN notify_tickets INTEGER DEFAULT 1"
    )

    if "notify_projects" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN notify_projects INTEGER DEFAULT 1"
    )

    if "notify_invoices" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN notify_invoices INTEGER DEFAULT 1"
    )

    if "language" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN language TEXT DEFAULT 'en'"
    )

    if "is_admin" not in column_names:
        conn.execute(
        "ALTER TABLE usuarios ADD COLUMN is_admin INTEGER DEFAULT 0"
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            nit TEXT DEFAULT '',
            nrc TEXT DEFAULT '',
            address TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            email TEXT DEFAULT '',
            contact_name TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)
    ensure_column(conn, "companies", "reminders_enabled", "INTEGER DEFAULT 0")
    ensure_column(conn, "companies", "reminder_invoice_due", "INTEGER DEFAULT 1")
    ensure_column(conn, "companies", "reminder_project_followup", "INTEGER DEFAULT 1")
    ensure_column(conn, "companies", "reminder_invoice_status", "INTEGER DEFAULT 1")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            user_id INTEGER,
            ref TEXT NOT NULL,
            title TEXT DEFAULT '',
            description TEXT DEFAULT '',
            scope_of_work TEXT DEFAULT '',
            internal_notes TEXT DEFAULT '',
            status TEXT DEFAULT 'Draft',
            date_start TEXT DEFAULT '',
            date_end TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY(company_id) REFERENCES companies(id),
            FOREIGN KEY(user_id) REFERENCES usuarios(id)
        )
    """)
    ensure_column(conn, "contracts", "formal_attachment_path", "TEXT DEFAULT ''")
    ensure_column(conn, "contracts", "formal_attachment_name", "TEXT DEFAULT ''")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            user_id INTEGER,
            ref TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            notes TEXT DEFAULT '',
            subtotal REAL DEFAULT 0,
            tax_rate REAL DEFAULT 13,
            tax_amount REAL DEFAULT 0,
            total REAL DEFAULT 0,
            date_issued TEXT DEFAULT '',
            date_due TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY(company_id) REFERENCES companies(id),
            FOREIGN KEY(user_id) REFERENCES usuarios(id)
        )
    """)
    ensure_column(conn, "invoices", "user_id", "INTEGER")
    ensure_column(conn, "invoices", "paid_amount", "REAL DEFAULT 0")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS invoice_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            quantity REAL DEFAULT 1,
            unit_price REAL DEFAULT 0,
            total REAL DEFAULT 0,
            FOREIGN KEY(invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES usuarios(id)
        )
    """)
    ensure_column(conn, "support_tickets", "ticket_number", "TEXT DEFAULT ''")
    ensure_column(conn, "support_tickets", "internal_notes", "TEXT DEFAULT ''")
    ensure_column(conn, "support_tickets", "client_notes", "TEXT DEFAULT ''")
    ensure_column(conn, "support_tickets", "resolution_notes", "TEXT DEFAULT ''")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ticket_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            author_type TEXT NOT NULL DEFAULT 'admin',
            author_name TEXT DEFAULT '',
            note TEXT DEFAULT '',
            image_path TEXT DEFAULT '',
            image_name TEXT DEFAULT '',
            visible_to_client INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY(ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE
        )
    """)
    ensure_column(conn, "ticket_events", "author_name", "TEXT DEFAULT ''")

    rows_without_number = conn.execute(
        "SELECT id, category FROM support_tickets WHERE ticket_number IS NULL OR ticket_number = '' ORDER BY id"
    ).fetchall()
    for row in rows_without_number:
        conn.execute(
            "UPDATE support_tickets SET ticket_number = ? WHERE id = ?",
            (next_ticket_number(conn, row["category"]), row["id"])
        )

    conn.commit()
    conn.close()


@app.route("/media/<path:filename>")
def media_file(filename):
    if filename not in PUBLIC_MEDIA_FILES and not require_user():
        return redirect(url_for("login"))
    return send_from_directory(MEDIA_DIR, filename)


@app.route("/media-download/<path:filename>")
def media_download(filename):
    if not require_user():
        return redirect(url_for("login"))
    return send_from_directory(MEDIA_DIR, filename, as_attachment=True)


def require_user():
    if "user_id" not in session:
        return None

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM usuarios WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    conn.close()
    return user


def money(value):
    try:
        return f"${float(value):,.2f}"
    except (TypeError, ValueError):
        return "$0.00"


def status_label(value):
    labels = {
        "-1": "Canceled",
        "0": "Draft",
        "1": "Open",
        "2": "Accepted",
        "3": "Closed",
        "4": "Billed",
    }
    return labels.get(str(value), str(value or "Open"))


def invoice_payment_status(invoice, t):
    """Return translated payment status label for an invoice."""
    status = str(invoice.get("status", "Pending"))
    if status == "Paid":
        return t("invoice.status_paid")
    if status == "Cancelled":
        return t("invoice.status_cancelled")
    if status == "Partial":
        return t("invoice.status_partial")
    return t("invoice.status_pending")


def invoice_remaining(invoice):
    """Return remaining amount to pay."""
    total_ttc = float(invoice.get("total") or invoice.get("total_ttc") or 0)
    totalpaid = float(invoice.get("paid_amount") or invoice.get("totalpaid") or invoice.get("sumpayed") or 0)
    if invoice.get("status") == "Paid":
        return 0
    if invoice.get("status") == "Cancelled":
        return 0
    if invoice.get("status") == "Pending":
        return total_ttc
    return max(0, total_ttc - totalpaid)


def ticket_prefix(category):
    text = (category or "").lower()
    if "web" in text or "website" in text or "sitio" in text:
        return "WEB"
    if "billing" in text or "factur" in text or "pago" in text:
        return "BI"
    if "technical" in text or "técn" in text or "tecn" in text:
        return "TEC"
    if "subscription" in text or "suscrip" in text:
        return "SUB"
    return "GEN"


def next_ticket_number(conn, category):
    prefix = ticket_prefix(category)
    latest = conn.execute(
        "SELECT ticket_number FROM support_tickets WHERE ticket_number LIKE ? ORDER BY id DESC LIMIT 1",
        (f"{prefix}%",)
    ).fetchone()
    if latest and latest["ticket_number"] and latest["ticket_number"][len(prefix):].isdigit():
        number = int(latest["ticket_number"][len(prefix):]) + 1
    else:
        number = int(conn.execute("SELECT COUNT(*) FROM support_tickets").fetchone()[0] or 0) + 1
    return f"{prefix}{number:05d}"


def localized_status_label(value, language):
    t = get_translator(language)
    label = status_label(value)
    status_keys = {
        "Canceled": "status.canceled",
        "Draft": "status.draft",
        "Open": "status.open",
        "Accepted": "status.accepted",
        "Closed": "status.closed",
        "Billed": "status.billed",
    }
    direct_labels = {
        "Active": "Activo" if language == "es" else "Active",
        "Hold": "En espera" if language == "es" else "Hold",
        "Monitoring": "Monitoreando" if language == "es" else "Monitoring",
        "Closed and resolved": "Cerrado y resuelto" if language == "es" else "Closed and resolved",
        "Cancelled Contract": "Cancelado" if language == "es" else "Cancelled",
        "Completed": "Completado" if language == "es" else "Completed",
        "Pending Renewal": "Pendiente de renovación" if language == "es" else "Pending Renewal",
        "Partial": "Pago parcial" if language == "es" else "Partial Payment",
    }
    if str(value or "") in direct_labels:
        return direct_labels[str(value or "")]
    return t(status_keys.get(label, label))


def parse_date(value):
    if not value:
        return "Not scheduled"
    try:
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime("%b %d, %Y")
        return str(value)[:10]
    except (OSError, ValueError):
        return str(value)


def checkbox_value(name):
    return 1 if request.form.get(name) == "on" else 0


def is_allowed_profile_photo(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_PROFILE_EXTENSIONS


def save_profile_photo(file_storage, user_id):
    if not file_storage or not file_storage.filename:
        return None

    filename = secure_filename(file_storage.filename)
    if not filename or not is_allowed_profile_photo(filename):
        return None

    extension = filename.rsplit(".", 1)[1].lower()
    os.makedirs(PROFILE_UPLOAD_DIR, exist_ok=True)
    final_name = f"user-{user_id}-{uuid.uuid4().hex[:12]}.{extension}"
    file_storage.save(os.path.join(PROFILE_UPLOAD_DIR, final_name))
    return f"uploads/profiles/{final_name}"


def load_client_portal_data(user, t=None):
    t = t or get_translator("en")
    conn = get_db_connection()
    user_id = user["id"]

    # Load contracts for this user (from local DB)
    contracts = conn.execute("""
        SELECT ct.*, c.name as company_name, c.nit, c.nrc, c.address as company_address
        FROM contracts ct
        JOIN companies c ON ct.company_id = c.id
        WHERE ct.user_id = ?
           OR (ct.user_id IS NULL AND LOWER(c.email) = LOWER(?))
           OR (ct.user_id IS NULL AND LOWER(c.name) = LOWER(?))
        ORDER BY ct.created_at DESC
    """, (user_id, user["email"], user["company_name"] or "")).fetchall()

    # Load invoices for this user
    invoices = conn.execute("""
        SELECT i.*, c.name as company_name, c.nit, c.nrc, c.address as company_address
        FROM invoices i
        JOIN companies c ON i.company_id = c.id
        WHERE i.user_id = ?
           OR (i.user_id IS NULL AND LOWER(c.email) = LOWER(?))
           OR (i.user_id IS NULL AND LOWER(c.name) = LOWER(?))
        ORDER BY i.created_at DESC
    """, (user_id, user["email"], user["company_name"] or "")).fetchall()

    # Tickets
    tickets = conn.execute("""
        SELECT * FROM support_tickets
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,)).fetchall()

    # Company info (first company linked to this user)
    company_row = conn.execute("""
        SELECT c.* FROM companies c
        LEFT JOIN contracts ct ON ct.company_id = c.id
        LEFT JOIN invoices i ON i.company_id = c.id
        WHERE ct.user_id = ?
           OR i.user_id = ?
           OR LOWER(c.email) = LOWER(?)
           OR LOWER(c.name) = LOWER(?)
        LIMIT 1
    """, (user_id, user_id, user["email"], user["company_name"] or "")).fetchone()

    conn.close()

    company = dict(company_row) if company_row else {}

    # Active subscription (first active contract)
    active_subscription = None
    active_contracts = [c for c in contracts if c["status"] == "Active"]
    if active_contracts:
        c = active_contracts[0]
        active_subscription = {
            "title": c["title"] or c["ref"],
            "status": c["status"],
            "renewal": c["date_end"] or t("date.not_scheduled"),
        }
    elif contracts:
        c = contracts[0]
        active_subscription = {
            "title": c["title"] or c["ref"],
            "status": c["status"],
            "renewal": c["date_end"] or t("date.not_scheduled"),
        }

    totals = {
        "open_projects": 0,
        "contracts": len(contracts),
        "open_tickets": len([tk for tk in tickets if tk["status"] != "Closed and resolved"]),
        "balance": money(sum(float(inv["total"] or 0) for inv in invoices)),
    }

    documents = []
    for inv in invoices:
        documents.append({
            "type": "Invoice",
            "name": inv["ref"],
            "status": inv["status"],
            "date": inv["date_issued"] or inv["created_at"][:10],
        })
    for contract in contracts:
        documents.append({
            "type": "Contract",
            "name": contract["ref"],
            "status": contract["status"],
            "date": contract["date_start"] or contract["created_at"][:10],
        })

    # Convert sqlite3.Row to plain dicts for template compatibility
    contracts_dicts = [dict(c) for c in contracts]
    invoices_dicts = [dict(i) for i in invoices]
    tickets_dicts = [dict(tk) for tk in tickets]

    return {
        "company": company,
        "projects": [],
        "proposals": [],
        "invoices": invoices_dicts,
        "contracts": contracts_dicts,
        "tickets": tickets_dicts,
        "subscription": active_subscription,
        "totals": totals,
        "documents": documents,
    }


@app.route("/main")
def main_page():

    user = require_user()
    if not user:
        return redirect(url_for("login"))

    active_view = request.args.get("view", "overview")
    allowed_views = {
        "overview",
        "subscription",
        "contracts",
        "invoices",
        "tickets",
        "projects",
        "documents",
        "settings",
    }
    if active_view not in allowed_views:
        active_view = "overview"

    language = user["language"] if "language" in user.keys() and user["language"] in TRANSLATIONS else "en"
    t = get_translator(language)
    portal = load_client_portal_data(user, t)

    # Pagination for invoices (10 per page)
    invoice_page = 1
    per_page = 10
    if active_view == "invoices":
        try:
            invoice_page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            invoice_page = 1
        all_invoices = portal.get("invoices", [])
        total_invoices = len(all_invoices)
        total_pages = max(1, (total_invoices + per_page - 1) // per_page)
        invoice_page = min(invoice_page, total_pages)
        start = (invoice_page - 1) * per_page
        portal["invoices"] = all_invoices[start:start + per_page]
        portal["invoice_pagination"] = {
            "page": invoice_page,
            "total_pages": total_pages,
            "total_items": total_invoices,
            "per_page": per_page,
        }
    else:
        portal["invoice_pagination"] = None

    company_name = (
        portal["company"].get("name")
        or portal["company"].get("nom")
        or user["company_name"]
        or t("portal.your_company")
    )

    def invoice_status(inv):
        return invoice_payment_status(inv, t)

    return render_template(
        "main_page.html",
        user=user,
        company_name=company_name,
        portal=portal,
        active_view=active_view,
        language=language,
        t=t,
        money=money,
        status_label=status_label,
        status_text=lambda value: localized_status_label(value, language),
        parse_date=parse_date,
        invoice_status=invoice_status,
        invoice_remaining=invoice_remaining,
    )


@app.route("/dashboard")
def dashboard():
    return redirect(url_for("main_page"))


@app.route("/tickets/new", methods=["POST"])
def create_ticket():
    user = require_user()
    if not user:
        return redirect(url_for("login"))

    subject = request.form.get("subject", "").strip()
    category = request.form.get("category", "General Support").strip()
    priority = request.form.get("priority", "Normal").strip()
    message = request.form.get("message", "").strip()

    if not subject or not message:
        return redirect(url_for("main_page", view="tickets", error="ticket_required"))

    now = datetime.utcnow().isoformat(timespec="seconds")
    conn = get_db_connection()
    ticket_number = next_ticket_number(conn, category)
    conn.execute(
        """
        INSERT INTO support_tickets
        (user_id, ticket_number, subject, category, priority, status, message, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            ticket_number,
            subject[:160],
            category[:80],
            priority[:40],
            "Active",
            message[:4000],
            now,
            now,
        )
    )
    conn.commit()
    conn.close()

    return redirect(url_for("main_page", view="tickets", created="1"))


@app.route("/settings", methods=["POST"])
def update_settings():
    user = require_user()
    if not user:
        return redirect(url_for("login"))

    action = request.form.get("settings_action", "profile")

    if action == "password":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not check_password_hash(user["password_hash"], current_password):
            return redirect(url_for("main_page", view="settings", password_error="current"))

        display_name = user["display_name"] or user["usuario"]
        is_valid, error = verify_password(display_name, new_password, confirm_password)
        if not is_valid:
            return redirect(url_for("main_page", view="settings", password_error="invalid"))

        conn = get_db_connection()
        conn.execute(
            "UPDATE usuarios SET password_hash = ?, must_reset_password = 0 WHERE id = ?",
            (generate_password_hash(new_password), user["id"])
        )
        conn.commit()
        conn.close()
        return redirect(url_for("main_page", view="settings", password_saved="1"))

    display_name = request.form.get("display_name", "").strip()
    company_name = request.form.get("company_name", "").strip()
    whatsapp = request.form.get("whatsapp", "").strip()
    language = request.form.get("language", "en")
    if language not in TRANSLATIONS:
        language = "en"
    profile_photo = save_profile_photo(request.files.get("profile_photo"), user["id"])

    conn = get_db_connection()
    if profile_photo:
        conn.execute(
            """
            UPDATE usuarios
            SET display_name = ?,
                company_name = ?,
                whatsapp = ?,
                profile_photo = ?,
                notify_email = ?,
                notify_tickets = ?,
                notify_projects = ?,
                notify_invoices = ?,
                language = ?
            WHERE id = ?
            """,
            (
                display_name[:120],
                company_name[:160],
                whatsapp[:40],
                profile_photo,
                checkbox_value("notify_email"),
                checkbox_value("notify_tickets"),
                checkbox_value("notify_projects"),
                checkbox_value("notify_invoices"),
                language,
                user["id"],
            )
        )
    else:
        conn.execute(
            """
            UPDATE usuarios
            SET display_name = ?,
                company_name = ?,
                whatsapp = ?,
                notify_email = ?,
                notify_tickets = ?,
                notify_projects = ?,
                notify_invoices = ?,
                language = ?
            WHERE id = ?
            """,
            (
                display_name[:120],
                company_name[:160],
                whatsapp[:40],
                checkbox_value("notify_email"),
                checkbox_value("notify_tickets"),
                checkbox_value("notify_projects"),
                checkbox_value("notify_invoices"),
                language,
                user["id"],
            )
        )
    conn.commit()
    conn.close()

    return redirect(url_for("main_page", view="settings", saved="1"))



@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")

        if is_rate_limited("login", get_client_ip(), LOGIN_IP_LIMIT, LOGIN_WINDOW_SECONDS, consume=False):
            return render_template("login.html", error="Too many login attempts. Please try again later."), 429

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM usuarios WHERE LOWER(usuario) = LOWER(?)",
            (usuario,)
        ).fetchone()

        if user and account_is_locked(user):
            conn.close()
            return render_template("login.html", error="Account temporarily locked. Please try again later."), 429

        if user and check_password_hash(user["password_hash"], password):
            clear_failed_logins(conn, user["id"])
            conn.close()
            if user["email_verified"] == 0:
                return render_template(
                    "login.html",
                    error="You must verify your email before logging in"
                )

            session["usuario"] = user["usuario"]
            session["user_id"] = user["id"]

            if user["must_reset_password"] == 1:
                return redirect(url_for("change_password"))

            return redirect(url_for("main_page"))

        else:
            is_rate_limited("login", get_client_ip(), LOGIN_IP_LIMIT, LOGIN_WINDOW_SECONDS)
            record_failed_login(conn, user)
            conn.close()
            error = "Username or password is incorrect, please try again"
            return render_template("login.html", error=error)

    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot_credentials():

    if request.method == "POST":
        if is_rate_limited("recovery", get_client_ip(), RECOVERY_IP_LIMIT, RECOVERY_WINDOW_SECONDS):
            return render_template("forgot.html", error="Too many recovery attempts. Please try again later."), 429

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
            reset_token = generate_recovery_token()
            reset_token_hash = hash_recovery_token(reset_token)
            reset_token_expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat(timespec="seconds")

            conn.execute(
                "UPDATE usuarios SET reset_token_hash = ?, reset_token_expires = ? WHERE id = ?",
                (reset_token_hash, reset_token_expires, user["id"])
            )

            conn.commit()

            reset_link = url_for("reset_password", token=reset_token, _external=True)
            send_recovery_email(user["email"], user["usuario"], reset_link)

        conn.close()

        return render_template(
                "forgot.html",
                success="If that email exists, you will receive recovery instructions."
            )


    return render_template("forgot.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hash_recovery_token(token)
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM usuarios WHERE reset_token_hash = ?", (token_hash,)).fetchone()

    if not user or timestamp_is_expired(user["reset_token_expires"]):
        conn.close()
        return render_template("verify_error.html"), 400

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        is_valid, error = verify_password(user["usuario"], new_password, confirm_password)
        if not is_valid:
            conn.close()
            return render_template("reset_password.html", error=error)

        conn.execute(
            """
            UPDATE usuarios
            SET password_hash = ?,
                must_reset_password = 0,
                reset_token_hash = NULL,
                reset_token_expires = NULL,
                failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = ?
            """,
            (generate_password_hash(new_password), user["id"]),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("login", password_reset="1"))

    conn.close()
    return render_template("reset_password.html")


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
        usuario = request.form.get("usuario", "").strip()
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
            existing_user = conn.execute(
                "SELECT id FROM usuarios WHERE LOWER(usuario) = LOWER(?) OR email = ?",
                (usuario, email)
            ).fetchone()

            if existing_user:
                conn.close()
                return render_template("registro.html", error="That username or email already exists")

            verification_token = generate_verification_token()
            verification_code = generate_verification_code()
            verification_code_hash = generate_password_hash(verification_code)
            verification_code_expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat(timespec="seconds")

            conn.execute(
                """
                INSERT INTO usuarios
                (usuario, email, password_hash, email_verified, verification_token, verification_code_hash,
                 verification_code_expires, verification_failed_attempts)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (usuario, email, password_hash, 0, verification_token, verification_code_hash, verification_code_expires)
            )
            conn.commit()

            verification_link = url_for(
                "verify_account",
                token=verification_token,
                _external=True
            )

            send_verification_email(email, usuario, verification_link, verification_code)

            conn.close()

            return render_template("reg_success.html")


        except sqlite3.IntegrityError:
            return render_template("registro.html", error="That username or email already exists")

    return render_template("registro.html")


@app.route("/verify-email/<token>", methods=["GET", "POST"])
def verify_account(token):
    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM usuarios WHERE verification_token = ?",
        (token,)
    ).fetchone()

    if not user:
        conn.close()
        return render_template("verify_error.html")

    if not user["verification_code_hash"] or timestamp_is_expired(user["verification_code_expires"]):
        conn.close()
        return render_template("verify_error.html")

    if request.method == "POST":
        if is_rate_limited("verify", f"{get_client_ip()}:{token}", VERIFY_IP_LIMIT, VERIFY_WINDOW_SECONDS):
            conn.close()
            return render_template("verify_error.html"), 429

        verification_code = request.form.get("verification_code", "").strip()

        if not verification_code.isdigit() or len(verification_code) != 8:
            conn.close()
            return render_template(
                "verify_code.html",
                error="Please enter the 8-digit verification code."
            )

        if not user["verification_code_hash"] or not check_password_hash(user["verification_code_hash"], verification_code):
            failed_attempts = int(user["verification_failed_attempts"] or 0) + 1
            if failed_attempts >= 3:
                conn.execute(
                    """
                    UPDATE usuarios
                    SET verification_token = NULL,
                        verification_code_hash = NULL,
                        verification_code_expires = NULL,
                        verification_failed_attempts = ?
                    WHERE id = ?
                    """,
                    (failed_attempts, user["id"]),
                )
            else:
                conn.execute(
                    "UPDATE usuarios SET verification_failed_attempts = ? WHERE id = ?",
                    (failed_attempts, user["id"]),
                )
            conn.commit()
            conn.close()
            return render_template(
                "verify_code.html",
                error="The verification code is incorrect."
            )

        conn.execute(
            """
            UPDATE usuarios
            SET email_verified = 1,
                verification_token = NULL,
                verification_code_hash = NULL,
                verification_code_expires = NULL,
                verification_failed_attempts = 0
            WHERE id = ?
            """,
            (user["id"],)
        )

        conn.commit()
        conn.close()

        return render_template("verify_success.html")

    conn.close()
    return render_template("verify_code.html")



@app.route("/invoice/<int:invoice_id>/view")
def view_invoice(invoice_id):
    user = require_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_db_connection()
    # Load invoice with company info from local DB
    invoice_data = conn.execute("""
        SELECT i.*, c.name as company_name, c.nit, c.nrc, c.address as company_address
        FROM invoices i
        JOIN companies c ON i.company_id = c.id
        WHERE i.id = ?
          AND (
            i.user_id = ?
            OR (i.user_id IS NULL AND LOWER(c.email) = LOWER(?))
            OR (i.user_id IS NULL AND LOWER(c.name) = LOWER(?))
          )
    """, (invoice_id, user["id"], user["email"], user["company_name"] or "")).fetchone()

    if not invoice_data:
        conn.close()
        return "Invoice not found", 404

    # Load line items
    items = [dict(item) for item in conn.execute("SELECT * FROM invoice_items WHERE invoice_id = ?", (invoice_id,)).fetchall()]
    conn.close()

    invoice = dict(invoice_data)
    language = user["language"] if user["language"] in TRANSLATIONS else "en"
    t = get_translator(language)
    now_text = datetime.now().strftime("%B %d, %Y")

    return render_template(
        "invoice_view.html",
        invoice=invoice,
        items=items,
        language=language,
        t=t,
        parse_date=parse_date,
        money=money,
        invoice_remaining=invoice_remaining,
        now_text=now_text,
    )


@app.route("/contract/<int:contract_id>/view")
def view_contract(contract_id):
    user = require_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_db_connection()
    contract_data = conn.execute("""
        SELECT ct.*, c.name as company_name, c.nit, c.nrc, c.address as company_address
        FROM contracts ct
        JOIN companies c ON ct.company_id = c.id
        WHERE ct.id = ?
          AND (
            ct.user_id = ?
            OR (ct.user_id IS NULL AND LOWER(c.email) = LOWER(?))
            OR (ct.user_id IS NULL AND LOWER(c.name) = LOWER(?))
          )
    """, (contract_id, user["id"], user["email"], user["company_name"] or "")).fetchone()

    if not contract_data:
        conn.close()
        return "Contract not found", 404

    conn.close()

    contract = dict(contract_data)
    language = user["language"] if user["language"] in TRANSLATIONS else "en"
    t = get_translator(language)
    now_text = datetime.now().strftime("%B %d, %Y")

    return render_template(
        "contract_view.html",
        contract=contract,
        language=language,
        t=t,
        parse_date=parse_date,
        money=money,
        now_text=now_text,
    )


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
