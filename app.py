import os
import sqlite3
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_SECRET = os.environ.get("FLASK_SECRET_KEY")
ENCRYPTION_KEY_HEX = os.environ.get("AES256_KEY")
CAPABILITY_CODE = os.environ.get("CAPABILITY_CODE")
DATABASE = os.environ.get("DATABASE_PATH", "security_demo.db")

app = Flask(__name__)
if not APP_SECRET:
    raise RuntimeError("Set FLASK_SECRET_KEY in your environment before starting the app.")
if not ENCRYPTION_KEY_HEX:
    raise RuntimeError("Set AES256_KEY to a 64-character hex key.")
if not CAPABILITY_CODE:
    raise RuntimeError("Set CAPABILITY_CODE in your environment.")
app.secret_key = APP_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
if os.environ.get("COOKIE_SECURE", "0") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("security_demo")

try:
    AES_KEY = bytes.fromhex(ENCRYPTION_KEY_HEX)
except ValueError as exc:
    raise RuntimeError("AES256_KEY must be a valid 64-character hex string.") from exc
if len(AES_KEY) != 32:
    raise RuntimeError("AES256_KEY must decode to exactly 32 bytes (AES-256).")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            encrypted_note BLOB NOT NULL,
            note_nonce BLOB NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    db.commit()
    db.close()

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def encrypt_text(plain_text):
    # AES-GCM uses AES-256 when supplied a 32-byte key.
    nonce = secrets.token_bytes(12)  # unique random nonce for each encryption
    ciphertext = AESGCM(AES_KEY).encrypt(nonce, plain_text.encode("utf-8"), None)
    return ciphertext, nonce

def decrypt_text(ciphertext, nonce):
    return AESGCM(AES_KEY).decrypt(bytes(nonce), bytes(ciphertext), None).decode("utf-8")

def log_event(event_type, username, details):
    # Do not log passwords, capability codes, or decrypted sensitive values.
    db = get_db()
    db.execute(
        "INSERT INTO security_events (event_type, username, details, created_at) VALUES (?, ?, ?, ?)",
        (event_type, username, details[:250], now_utc())
    )
    db.commit()
    logger.info("%s user=%s details=%s", event_type, username or "anonymous", details[:150])

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        private_note = request.form.get("private_note", "").strip()

        if not username or len(username) < 3 or len(username) > 40:
            flash("Username must be 3–40 characters.", "danger")
            return render_template("register.html")
        if len(password) < 12:
            flash("Use a password of at least 12 characters.", "danger")
            return render_template("register.html")
        if len(private_note) > 1000:
            flash("Private note must be 1000 characters or fewer.", "danger")
            return render_template("register.html")

        encrypted_note, nonce = encrypt_text(private_note)
        db = get_db()
        try:
            # Parameterized SQL prevents user input from becoming executable SQL.
            db.execute(
                "INSERT INTO users (username, password_hash, encrypted_note, note_nonce, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, generate_password_hash(password), encrypted_note, nonce, now_utc())
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username is already registered.", "danger")
            return render_template("register.html")

        log_event("REGISTER_SUCCESS", username, "New account created")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        # Always use placeholders; never build SQL with string concatenation.
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_event("LOGIN_SUCCESS", username, "Valid credentials")
            return redirect(url_for("dashboard"))

        log_event("LOGIN_FAILURE", username or None, "Invalid login attempt")
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute(
        "SELECT username, created_at FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    return render_template("dashboard.html", user=user)

@app.route("/reveal-note", methods=["GET", "POST"])
@login_required
def reveal_note():
    revealed = None
    if request.method == "POST":
        supplied_code = request.form.get("capability_code", "")
        # The code is an authorization check, not SQL. Compare in constant time.
        if not secrets.compare_digest(supplied_code, CAPABILITY_CODE):
            log_event("CAPABILITY_DENIED", session.get("username"), "Invalid capability code")
            flash("Access denied. The capability code was not accepted.", "danger")
        else:
            db = get_db()
            user = db.execute(
                "SELECT encrypted_note, note_nonce FROM users WHERE id = ?",
                (session["user_id"],)
            ).fetchone()
            try:
                revealed = decrypt_text(user["encrypted_note"], user["note_nonce"])
                log_event("CAPABILITY_GRANTED", session.get("username"), "Private note decrypted after authorization")
            except Exception:
                log_event("DECRYPTION_ERROR", session.get("username"), "Could not decrypt stored note")
                flash("Unable to decrypt this data. Check the configured encryption key.", "danger")
    return render_template("reveal.html", revealed=revealed)

@app.route("/security-events")
@login_required
def security_events():
    # A real deployment should add a separate administrator role and authorization.
    db = get_db()
    events = db.execute(
        "SELECT event_type, username, details, created_at FROM security_events ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return render_template("events.html", events=events)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.errorhandler(400)
def bad_request(error):
    log_event("BAD_REQUEST", session.get("username"), "Bad request rejected")
    return render_template("error.html", message="Bad request rejected."), 400

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", message="Page not found."), 404

@app.errorhandler(500)
def server_error(error):
    logger.exception("Unhandled server error")
    return render_template("error.html", message="An internal error occurred."), 500

init_db()

if __name__ == "__main__":
    # Local development only. Use a production WSGI server when deployed.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
