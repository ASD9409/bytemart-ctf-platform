# ByteMart CTF Platform

A complete **Capture-The-Flag (CTF) security competition platform** with a deliberately vulnerable web app and a secure competition management portal.

## Components

| Folder | Description | Port |
|---|---|---|
| `bytemart-organizer/` | Vulnerable target (with answer key) | 5000 |
| `bytemart-participants/` | Vulnerable target (without answers) | 5000 |
| `ctf-portal/` | Secure competition management portal | 7000 |

## Quick Start

```bash
# Install dependencies
pip install flask

# Terminal 1 — Start the vulnerable target
cd bytemart-organizer/bytemart
python app.py  # → http://localhost:5000

# Terminal 2 — Start the CTF portal
cd ctf-portal/ctf-portal
python app.py  # → http://localhost:7000
```

## Default Credentials

| App | Username | Password | URL |
|---|---|---|---|
| ByteMart (admin) | `admin` | `SuperSecret!2024` | `http://localhost:5000/login` |
| CTF Portal (organizer) | `ASD9409` | `RGPS` | `http://localhost:7000/admin/login` |

## How It Works

1. **Organizer** logs into CTF Portal → adds participants → starts the timer
2. **Participants** log in with generated credentials → attack ByteMart → submit findings
3. **Organizer** monitors live dashboard → exports results as CSV

## 20 Intentional Vulnerabilities

ByteMart contains 20 intentional security flaws including SQL Injection, XSS, Command Injection, Path Traversal, IDOR, CSRF, and more. See `bytemart-organizer/bytemart/SOLUTIONS.md` for the full answer key.

## Deployment

Deployed on [Render](https://render.com) — see `render.yaml` for the blueprint.

> ⚠️ **Warning**: ByteMart executes real shell commands and file reads. Only deploy in isolated environments.
