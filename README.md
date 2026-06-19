# Secure Coding Review — Flask Application (NoteVault)

A complete secure coding review of a small Flask web application, combining a *custom-built static analysis tool* with *manual code review* to identify, document, and remediate 10 real-world security vulnerabilities.

## 📁 What's in this repo

| File | Description |
|------|--------------|
| app.py | The audit target — a small Flask notes app intentionally containing 10 common vulnerabilities (SQL injection, XSS, command injection, etc.) |
| simple_security_scanner.py | A lightweight, dependency-free static analyzer built using Python's ast module to detect insecure code patterns |
| app_fixed.py | The fully remediated version of the app, with every finding fixed and annotated |
| SECURE_CODING_REVIEW.md | The full written report — findings, severity ratings, CWE references, and remediation steps |

## 🛠️ How to run it

Install dependencies:
```bash
pip install flask

Run the static analyzer against the vulnerable app:
python simple_security_scanner.py app.py
