import os
import sqlite3
import hashlib
import pickle
import subprocess

from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# --- VULN-01: Hardcoded secret key & credentials ---
app.secret_key = "supersecret123"
DB_ADMIN_PASSWORD = "Admin@123"

DB_PATH = "notevault.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT)""")
    conn.commit()
    conn.close()


def hash_password(password):
    # --- VULN-02: Weak hashing algorithm for passwords ---
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    conn.commit()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()

    # --- VULN-03: SQL Injection via string concatenation ---
    query = "SELECT * FROM users WHERE username = '" + username + \
        "' AND password = '" + hash_password(password) + "'"
    user = conn.execute(query).fetchone()

    if user:
        session["user_id"] = user["id"]
        return redirect("/notes")
    return "Invalid credentials"


@app.route("/notes/<note_id>")
def view_note(note_id):
    conn = get_db()
    # --- VULN-04: Insecure Direct Object Reference (IDOR) ---
    # Any logged-in user can view any note by guessing/incrementing the ID;
    # there is no check that note_id belongs to session["user_id"].
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if not note:
        return "Not found"

    # --- VULN-05: Reflected XSS via unescaped template rendering ---
    template = "<h2>{title}</h2><p>{body}</p>".format(
        title=note["title"], body=note["body"]
    )
    return render_template_string(template)


@app.route("/export")
def export_notes():
    note_id = request.args.get("id")
    fmt = request.args.get("format", "txt")
    filename = f"export_{note_id}.{fmt}"

    # --- VULN-06: Path Traversal ---
    # filename is built from user input without sanitizing "../" sequences,
    # so a crafted id or format value can escape the exports directory.
    path = os.path.join("exports", filename)
    with open(path, "r") as f:
        return f.read()


@app.route("/restore", methods=["POST"])
def restore_session_data():
    # --- VULN-07: Insecure Deserialization ---
    # Untrusted, attacker-controlled bytes are passed straight into pickle.loads,
    # which can execute arbitrary code during unpickling.
    blob = request.data
    data = pickle.loads(blob)
    session.update(data)
    return "Restored"


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # --- VULN-08: OS Command Injection ---
    # host is interpolated directly into a shell command.
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


@app.route("/admin/reset-db")
def reset_db():
    # --- VULN-09: Broken access control ---
    # Destructive admin action with no authentication/authorization check at all.
    conn = get_db()
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM notes")
    conn.commit()
    return "Database reset"


if __name__ == "__main__":
    init_db()
    # --- VULN-10: Debug mode enabled / binds to all interfaces ---
    app.run(host="0.0.0.0", port=5000, debug=True)