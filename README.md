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

python simple_security_scanner.py app_fixed.py

Static Analysis Report: app.py
============================================================
[    High] SEC-HARDCODED-SECRET line 21   Hardcoded credential/secret (CWE-798)
[  Medium] SEC-WEAK-HASH        line 45   Weak Hashing Algorithm (CWE-327)
[Critical] SEC-DESERIAL         line 117  Insecure Deserialization (pickle) (CWE-502)
[Critical] SEC-CMD-INJ          line 127  Possible OS Command Injection (CWE-78)
[    High] SEC-DEBUG            line 145  Debug mode enabled in app.run() (CWE-489)
============================================================
Total findings: 7  |  Critical: 2  High: 3  Medium: 1  Low: 1
