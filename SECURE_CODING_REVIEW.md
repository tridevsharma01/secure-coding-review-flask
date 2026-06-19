# Secure Coding Review: NoteVault (Python / Flask)

**Reviewer:** Tridev Sharma
**Application audited:** `app.py` — a small Flask web app for user accounts and personal notes/file export
**Language / Framework:** Python 3, Flask, SQLite
**Review type:** Static analysis (custom AST-based scanner) + manual source code review
**Files:** `app.py` (audit target), `app_fixed.py` (remediated version), `simple_security_scanner.py` (analysis tool)

---

## 1. Methodology

Two complementary techniques were used, matching how real-world secure code reviews are typically run:

1. **Static analysis.** A lightweight, dependency-free Python static analyzer (`simple_security_scanner.py`) was built using the `ast` module to walk the syntax tree of `app.py` and flag known-risky patterns: dynamic shell commands, `pickle.loads()` on untrusted data, weak hash functions, hardcoded secrets, and insecure Flask debug settings.
2. **Manual code review.** Every route handler was read line-by-line to evaluate authentication, authorization, input handling, and output encoding — catching business-logic flaws (like missing ownership checks) that pattern-matching tools structurally cannot detect.

This two-pass approach matters because the tool and the manual review caught *different, non-overlapping* issues — neither alone would have found everything.

### Static analyzer output

```
Static Analysis Report: app.py
============================================================
[    High] SEC-HARDCODED-SECRET line 21   Hardcoded credential/secret (CWE-798)
           > app.secret_key = "supersecret123"
[    High] SEC-HARDCODED-SECRET line 22   Hardcoded credential/secret (CWE-798)
           > DB_ADMIN_PASSWORD = "Admin@123"
[  Medium] SEC-WEAK-HASH        line 45   Weak Hashing Algorithm (CWE-327)
           > return hashlib.md5(password.encode()).hexdigest()
[Critical] SEC-DESERIAL         line 117  Insecure Deserialization (pickle) (CWE-502)
           > data = pickle.loads(blob)
[Critical] SEC-CMD-INJ          line 127  Possible OS Command Injection (CWE-78)
           > result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
[     Low] SEC-BIND-ALL         line 145  Server bound to all network interfaces (CWE-200)
           > app.run(host="0.0.0.0", port=5000, debug=True)
[    High] SEC-DEBUG            line 145  Debug mode enabled in app.run() (CWE-489)
           > app.run(host="0.0.0.0", port=5000, debug=True)
============================================================
Total findings: 7  |  Critical: 2  High: 3  Medium: 1  Low: 1
```

The scanner missed 3 of the 10 vulnerabilities ultimately documented below — the SQL injection (because the tainted string was built one line before the `.execute()` call, not inline), the IDOR, and the broken access control on `/admin/reset-db`. All three are **logic-level** flaws: the code is syntactically unremarkable, but it's missing a check a human reviewer recognizes is necessary. This is the central limitation of static analysis tools in general, regardless of which one is used — they're strong at pattern-matching known-bad API usage and weak at reasoning about intent.

---

## 2. Findings Summary

| ID | Title | Severity | CWE | Location | Found By |
|----|-------|----------|-----|----------|----------|
| F01 | Hardcoded secret key & credentials | High | CWE-798 | `app.py:21-22` | Tool |
| F02 | Weak password hashing (MD5) | Medium | CWE-327 | `app.py:45` | Tool |
| F03 | SQL Injection in login query | Critical | CWE-89 | `app.py:68-70` | Manual |
| F04 | Insecure Direct Object Reference (IDOR) on notes | High | CWE-639 | `app.py:78-86` | Manual |
| F05 | Reflected XSS via unescaped template string | High | CWE-79 | `app.py:90-94` | Manual |
| F06 | Path traversal in file export | High | CWE-22 | `app.py:97-108` | Manual |
| F07 | Insecure deserialization via `pickle.loads` | Critical | CWE-502 | `app.py:111-117` | Tool |
| F08 | OS command injection in `/ping` | Critical | CWE-78 | `app.py:122-127` | Tool |
| F09 | Missing authentication/authorization on admin route | Critical | CWE-862 | `app.py:131-137` | Manual |
| F10 | Debug mode enabled / bound to all interfaces | High / Low | CWE-489 / CWE-200 | `app.py:145` | Tool |

**Severity distribution:** 4 Critical · 5 High · 1 Medium

---

## 3. Detailed Findings

### F01 — Hardcoded Secret Key & Credentials (High, CWE-798)

Flask's `secret_key` and an admin password are committed directly in source:

```python
app.secret_key = "supersecret123"
DB_ADMIN_PASSWORD = "Admin@123"
```

Anyone with read access to the repository (or a leaked copy of it) can forge signed session cookies or log in as an administrator. Secrets committed to version control history are also extremely difficult to fully purge later.

**Recommendation:** load secrets from environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) at startup, and fail loudly if they're missing rather than falling back to a default. Add `.env` and any credential files to `.gitignore`. Rotate any secret that was ever committed, since rotation — not just removal — is what actually neutralizes a leaked credential.

---

### F02 — Weak Password Hashing: MD5 (Medium, CWE-327)

```python
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

MD5 is fast and unsalted, which makes it practical to brute-force or reverse via precomputed rainbow tables if the database is ever exposed. It was never designed for password storage.

**Recommendation:** use a purpose-built password hashing function with a built-in per-password salt and tunable work factor — `werkzeug.security.generate_password_hash` (PBKDF2 by default), `bcrypt`, or `argon2`. `app_fixed.py` switches to `generate_password_hash` / `check_password_hash`.

---

### F03 — SQL Injection in Login Query (Critical, CWE-89)

```python
query = "SELECT * FROM users WHERE username = '" + username + \
    "' AND password = '" + hash_password(password) + "'"
user = conn.execute(query).fetchone()
```

The username is concatenated directly into the SQL string. An input like `' OR '1'='1` lets an attacker bypass authentication entirely, and more advanced payloads could extract or modify arbitrary data in the database.

**Recommendation:** always use parameterized queries / prepared statements, passing user input as bound parameters rather than interpolating it into the SQL text:

```python
user = conn.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()
```

This was the most severe finding in the review and the one a static pattern-matcher is most likely to miss when the tainted string isn't built inline.

---

### F04 — Insecure Direct Object Reference on Notes (High, CWE-639)

```python
@app.route("/notes/<note_id>")
def view_note(note_id):
    note = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
```

Any authenticated (or, combined with F09's pattern elsewhere, even unauthenticated) user can view **any** note by simply changing the ID in the URL — there's no check that the note belongs to the requesting user.

**Recommendation:** every object lookup keyed by an ID from user input must also filter by the current session's ownership: `WHERE id = ? AND user_id = ?`. As a defense-in-depth measure, consider non-sequential IDs (UUIDs) so IDs can't be enumerated even if an authorization check were ever accidentally dropped.

---

### F05 — Reflected XSS via Unescaped Template String (High, CWE-79)

```python
template = "<h2>{title}</h2><p>{body}</p>".format(title=note["title"], body=note["body"])
return render_template_string(template)
```

Note title/body are stored and replayed as raw HTML with no escaping. If a user can enter `<script>...</script>` into a note's title (their own, or — combined with F04 — someone else's), that script executes in the browser of whoever views the note.

**Recommendation:** pass user data as template *variables*, not as pre-built HTML strings, and let Jinja2's autoescaping do its job:

```python
return render_template_string("<h2>{{ title }}</h2><p>{{ body }}</p>", title=note["title"], body=note["body"])
```

---

### F06 — Path Traversal in File Export (High, CWE-22)

```python
filename = f"export_{note_id}.{fmt}"
path = os.path.join("exports", filename)
with open(path, "r") as f:
    return f.read()
```

`note_id` and `fmt` are attacker-controlled and inserted into a file path with no validation. A value like `fmt=../../etc/passwd%00` (or simpler traversal sequences depending on OS/Python version behavior) could be used to read files outside the intended `exports/` directory.

**Recommendation:** validate both inputs against a strict allow-list (`note_id` must be numeric, `fmt` must be one of a fixed set of extensions), then resolve the final path with `os.path.realpath()` and verify it's still located inside the intended base directory before opening it.

---

### F07 — Insecure Deserialization via `pickle.loads` (Critical, CWE-502)

```python
blob = request.data
data = pickle.loads(blob)
```

`pickle` can execute arbitrary code as a side effect of deserializing a crafted object. Accepting raw `pickle` bytes directly from an HTTP request body means any unauthenticated client can potentially achieve remote code execution on the server.

**Recommendation:** never unpickle data from an untrusted source. If session/state restoration is genuinely required, use a safe, schema-validated format like JSON, and validate the structure/types of the parsed data before using it.

---

### F08 — OS Command Injection in `/ping` (Critical, CWE-78)

```python
result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
```

The `host` query parameter is interpolated directly into a shell command string with `shell=True`. An input like `host=8.8.8.8; rm -rf /` (or a reverse shell payload) executes arbitrary commands on the server with the privileges of the Flask process.

**Recommendation:** never build shell command strings from user input. Validate `host` against a strict pattern (e.g. IPv4 only), then call `subprocess.run()` with an **argument list** and `shell=False`, which passes arguments directly to the OS without a shell interpreting them.

---

### F09 — Missing Authentication/Authorization on Admin Route (Critical, CWE-862)

```python
@app.route("/admin/reset-db")
def reset_db():
    conn = get_db()
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM notes")
```

This destructive endpoint has **no** authentication check at all — anyone who discovers or guesses the URL (a simple GET request) can wipe the entire database.

**Recommendation:** require authentication on every state-changing route by default (a `@login_required` decorator applied consistently), add a role check for admin-only actions (`@admin_required`), and restrict destructive operations to `POST`/`DELETE` so they can't be triggered by a bare link, an `<img>` tag, or a crawler.

---

### F10 — Debug Mode Enabled & Bound to All Interfaces (High / Low, CWE-489 / CWE-200)

```python
app.run(host="0.0.0.0", port=5000, debug=True)
```

Flask's debug mode exposes an interactive in-browser Python debugger on unhandled exceptions — which, on many setups, lets a remote visitor execute arbitrary Python on the server. `host="0.0.0.0"` additionally makes the dev server reachable from any network interface, not just localhost.

**Recommendation:** never run `debug=True` outside local development. Use a production WSGI server (gunicorn, uWSGI) behind a reverse proxy, bind to `127.0.0.1` for local-only services, and gate any debug flag behind an environment variable that defaults to `False`.

---

## 4. General Secure Coding Best Practices

Beyond the specific fixes above, the following habits prevent most of this class of vulnerability from being introduced in the first place:

- **Treat all user input as untrusted** — query parameters, form fields, headers, cookies, and file uploads alike — and validate it against an allow-list (expected format/type/range) rather than trying to block known-bad patterns.
- **Use parameterized queries / ORMs** for all database access; never build SQL by string concatenation or f-strings.
- **Let templating engines handle escaping** (Jinja2 autoescape, etc.) instead of hand-assembling HTML strings.
- **Default to deny.** Every route that touches user-specific or sensitive data should require authentication, and authorization (ownership/role checks) should be enforced server-side on every request, not assumed from the UI.
- **Never deserialize untrusted data with formats that support code execution** (`pickle`, `yaml.load` without `SafeLoader`, etc.) — prefer JSON with explicit schema validation.
- **Avoid shell=True and string-built shell commands.** Pass argument lists to `subprocess` and let the OS handle them directly.
- **Keep secrets out of source control** entirely — environment variables, `.env` files excluded via `.gitignore`, or a dedicated secrets manager.
- **Use modern password hashing** (bcrypt/argon2/PBKDF2) with per-password salts, never a single fast general-purpose hash.
- **Disable debug/verbose error modes in production**, and avoid leaking stack traces or internal paths in API responses.
- **Run both automated and manual review** — they catch different classes of bugs, as this audit demonstrated directly.

---

## 5. Remediation Status

All 10 findings have corresponding fixes implemented in `app_fixed.py`, each annotated inline with the finding ID it addresses. Re-running the static analyzer against the remediated file returns zero findings:

```
Static Analysis Report: app_fixed.py
============================================================
============================================================
Total findings: 0
```

(A clean static-analysis pass doesn't guarantee the absence of all logic-level issues — F03, F04, and F09 prove the tool alone wouldn't have caught those — so the manual review checklist in Section 4 should still be applied to any future changes, not just the scanner.)

---

## 6. Conclusion

This review combined a custom AST-based static analyzer with manual line-by-line inspection across all eight route handlers in `app.py`, identifying 10 distinct vulnerabilities spanning injection (SQL, OS command), broken access control (IDOR, missing auth), insecure deserialization, weak cryptography, path traversal, XSS, and insecure configuration. The split between tool-found and manually-found issues (7 vs. 3) reinforces that static analysis is a strong first pass but not a substitute for human review of authentication and authorization logic. All findings have been remediated in `app_fixed.py` and verified against the same scanner used in the initial audit.
