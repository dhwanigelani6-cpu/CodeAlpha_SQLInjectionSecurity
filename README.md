# CodeAlpha Task 2 — SQL Injection Detection and Data Leak Prevention

A Flask learning project demonstrating parameterized SQL queries, password hashing, AES-256-GCM encryption for a private note, capability-code authorization, security event logging, and basic HTTP security headers.

## Features
- Registration and login using parameterized SQL statements
- Passwords stored as one-way password hashes (not reversible encryption)
- User private note encrypted/decrypted with AES-256-GCM using a 32-byte AES-256 key
- Capability code required before decrypting the note
- Security events for successful/failed login and capability-code checks
- Basic security headers
- Browser-based UI suitable for a small cloud-hosted demo

## Requirements
- Python 3.10+
- pip

## Run locally (Windows PowerShell)

1. Open this project folder in VS Code.
2. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Generate secrets (run in PowerShell; keep these private):

   ```powershell
   $env:FLASK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
   $env:AES256_KEY = python -c "import secrets; print(secrets.token_hex(32))"
   $env:CAPABILITY_CODE = python -c "import secrets; print(secrets.token_urlsafe(24))"
   ```

   Save the generated values in a password manager so you can enter the same values whenever restarting the app. Never commit them to GitHub.

4. Start the app:

   ```powershell
   python app.py
   ```

5. Open `http://127.0.0.1:5000`.

## Linux/macOS shell example

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export AES256_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export CAPABILITY_CODE="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
python app.py
```

Keep the generated values for subsequent restarts. Changing `AES256_KEY` makes previously encrypted notes unreadable.

## Test plan
1. Register a demo user with a password of at least 12 characters and a sample private note.
2. Log in with the correct password: the dashboard should appear.
3. Try a wrong password: login should fail with a generic error.
4. In the username field, try the harmless SQL-injection test string `' OR '1'='1' --` using a random password. Login should fail because the query is parameterized.
5. Open **Reveal private note** and enter an incorrect capability code: access should be denied.
6. Enter the configured capability code: only your own encrypted note should be decrypted and displayed.
7. Open **Security events** to review login and capability-code events.
8. Log out and verify that protected pages redirect to login.

Only test this application or systems for which you have permission.

## Deployment notes (Render example)
- Push the project to GitHub.
- Create a new **Web Service** on Render and connect the repository.
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Add environment variables in the hosting dashboard:
  - `FLASK_SECRET_KEY` = long random secret
  - `AES256_KEY` = 64-character hex string (32 bytes)
  - `CAPABILITY_CODE` = long random secret code
  - `DATABASE_PATH` = `/var/data/security_demo.db` if you attach a persistent disk mounted at `/var/data`
  - `COOKIE_SECURE` = `1` when using HTTPS
- If using a persistent disk, attach it to the service at `/var/data`. Confirm that the hosting plan supports persistent disks. Without persistent storage, local SQLite data may be lost when the service restarts or redeploys.
- For a multi-user/production deployment, use a managed database such as PostgreSQL, restrict event-log access to administrators, add CSRF protection and rate limiting, rotate keys securely, and arrange backups. This starter is an educational demo, not a security-audited production system.

## Security explanation for the report
- Parameterized queries separate SQL code from user-supplied values, mitigating SQL injection.
- Password hashing protects passwords without storing the original password.
- AES-256-GCM encrypts the private note and authenticates it against tampering.
- The capability code is a second authorization check before decryption. It is not a mechanism for injecting SQL.
- Security logs record relevant events without storing passwords, capability codes, or decrypted note contents.

## Suggested GitHub repository name
`CodeAlpha_SQLInjectionSecurity`
