import os
import re
import secrets
import sqlite3
import subprocess
from functools import wraps

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, render_template_string, redirect, session, abort
from markupsafe import escape

app = Flask(_name_)

# SEC-HARDCODED-SECRET fix: load secrets from environment, never hardcode them.
# Generate one with python -c "import secrets; print(secrets.token_hex(32))"
# and store it in your deployment environment (e.g. a secrets manager), not in source.
app.secret_key = os.environ["FLASK_SECRET_KEY"]

DB_PATH = os.environ.get("NOTEVAULT_DB_PATH", "notevault.db")
EXPORT_DIR = os.path.abspath("exports")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT)""")
    conn.commit()
    conn.close()


def login_required(view):
    # SEC-BROKEN-ACCESS-CONTROL fix: require an authenticated session for
    # any route that touches user or admin data.
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"].strip()
    password = request.form["password"]

    if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
        abort(400, "Invalid username")
    if len(password) < 12:
        abort(400, "Password must be at least 12 characters")

    # SEC-WEAK-HASH fix: use a salted, slow KDF (PBKDF2/bcrypt/argon2 via werkzeug)
    # instead of a single fast hash like MD5.
    password_hash = generate_password_hash(password)

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        abort(409, "Username already taken")
    return "Registered", 201


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()

    # SEC-SQLI fix: always use parameterized queries — never concatenate
    # user input into SQL strings.
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session["user_id"] = user["id"]
        return redirect("/notes")

    # Generic message — don't reveal whether the username or password was wrong.
    return "Invalid credentials", 401


@app.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    conn = get_db()
    # SEC-IDOR fix: scope the query to the current session's user, so a
    # user can never fetch another user's note by guessing an ID.
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()
    if not note:
        abort(404)

    # SEC-XSS fix: let Jinja2 autoescape the values instead of hand-building
    # HTML with .format()/f-strings (which skips escaping entirely).
    return render_template_string(
        "<h2>{{ title }}</h2><p>{{ body }}</p>",
        title=note["title"], body=note["body"],
    )


ALLOWED_EXPORT_FORMATS = {"txt", "md"}


@app.route("/export")
@login_required
def export_notes():
    note_id = request.args.get("id", "")
    fmt = request.args.get("format", "txt")

    # SEC-PATH-TRAVERSAL fix: validate inputs against an allow-list/pattern,
    # then resolve the final path and confirm it's still inside EXPORT_DIR.
    if not note_id.isdigit() or fmt not in ALLOWED_EXPORT_FORMATS:
        abort(400, "Invalid export request")

    filename = f"export_{note_id}.{fmt}"
    full_path = os.path.realpath(os.path.join(EXPORT_DIR, filename))
    if not full_path.startswith(EXPORT_DIR + os.sep):
        abort(400, "Invalid path")

    if not os.path.isfile(full_path):
        abort(404)
    with open(full_path, "r") as f:
        return f.read()


# SEC-DESERIAL fix: the /restore endpoint accepting arbitrary pickle data
# has been removed entirely. If session-restore is genuinely needed, use a
# safe, schema-validated format (e.g. JSON) instead of pickle.


@app.route("/ping")
@login_required
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    # SEC-CMD-INJ fix: validate the input strictly (IPv4-only allow-list
    # shown here), and call subprocess with an argument list and
    # shell=False so there's no shell interpretation step at all.
    if not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        abort(400, "Invalid host")

    result = subprocess.run(
        ["ping", "-c", "1", host], shell=False, capture_output=True, timeout=5
    )
    return result.stdout


@app.route("/admin/reset-db", methods=["POST"])
@login_required
@admin_required
def reset_db():
    # SEC-BROKEN-ACCESS-CONTROL fix: now requires authentication AND an
    # admin role, and only accepts POST (not a bare GET link).
    conn = get_db()
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM notes")
    conn.commit()
    return "Database reset"


if _name_ == "_main_":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)