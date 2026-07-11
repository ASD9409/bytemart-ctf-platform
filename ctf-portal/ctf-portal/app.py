"""
CTF Portal — participant login + recon/vulnerability submission form,
with a live organizer dashboard, timer control, and CSV export.

This is real competition infrastructure (not the vulnerable target), so
unlike ByteMart it is built securely: hashed passwords, escaped output,
parameterized queries throughout.
"""
import csv
import io
import json
import os
import random
import re
import string
import sqlite3
from datetime import datetime, timedelta

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, g, jsonify, Response
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "portal.db")

app = Flask(__name__)

# secret key persists across restarts (written once, reused after)
KEY_PATH = os.path.join(APP_DIR, ".secret_key")
if os.path.exists(KEY_PATH):
    app.secret_key = open(KEY_PATH).read()
else:
    app.secret_key = os.urandom(32).hex()
    with open(KEY_PATH, "w") as f:
        f.write(app.secret_key)

# organizer login — change this before a real event
ORGANIZER_USERNAME = "ASD9409"
ORGANIZER_PASSWORD_HASH = generate_password_hash("RGPS")

TARGET_URL = "http://TARGET-IP-OR-DOMAIN:5000"  # point this at your ByteMart instance


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS participants (
            id INTEGER PRIMARY KEY,
            name TEXT,
            username TEXT UNIQUE,
            password_hash TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY,
            participant_id INTEGER UNIQUE,
            recon_json TEXT DEFAULT '{}',
            findings_json TEXT DEFAULT '[]',
            submitted INTEGER DEFAULT 0,
            submitted_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    db.commit()
    db.close()


def get_setting(key, default=None):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    db.commit()


# ---------------------------------------------------------------- helpers
def current_participant():
    pid = session.get("participant_id")
    if not pid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM participants WHERE id = ?", (pid,)).fetchone()


def ensure_submission_row(participant_id):
    db = get_db()
    row = db.execute(
        "SELECT id FROM submissions WHERE participant_id = ?", (participant_id,)
    ).fetchone()
    if not row:
        db.execute(
            "INSERT INTO submissions (participant_id, updated_at) VALUES (?, NULL)",
            (participant_id,),
        )
        db.commit()


def is_organizer():
    return session.get("is_organizer") is True


def require_organizer():
    return is_organizer()


def gen_username(name, existing):
    base = re.sub(r"[^a-z0-9]", "", name.lower().replace(" ", ""))[:12] or "user"
    candidate = base
    n = 1
    while candidate in existing:
        n += 1
        candidate = f"{base}{n}"
    existing.add(candidate)
    return candidate


def gen_password():
    return "".join(random.choices(string.ascii_letters + string.digits, k=8))


def deadline_dt():
    raw = get_setting("deadline")
    if not raw:
        return None
    return datetime.fromisoformat(raw)


# ---------------------------------------------------------------- participant routes
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT * FROM participants WHERE username = ?", (username,)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["participant_id"] = row["id"]
            ensure_submission_row(row["id"])
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    participant = current_participant()
    if not participant:
        return redirect(url_for("login"))
    db = get_db()
    sub = db.execute(
        "SELECT * FROM submissions WHERE participant_id = ?", (participant["id"],)
    ).fetchone()
    if not sub:
        db.execute(
            "INSERT INTO submissions (participant_id, updated_at) VALUES (?, ?)",
            (participant["id"], datetime.utcnow().isoformat()),
        )
        db.commit()
        sub = db.execute(
            "SELECT * FROM submissions WHERE participant_id = ?", (participant["id"],)
        ).fetchone()

    dl = deadline_dt()
    seconds_left = max(0, int((dl - datetime.utcnow()).total_seconds())) if dl else None

    return render_template(
        "dashboard.html",
        participant=participant,
        recon=json.loads(sub["recon_json"]),
        findings=json.loads(sub["findings_json"]),
        submitted=bool(sub["submitted"]),
        submitted_at=sub["submitted_at"],
        seconds_left=seconds_left,
        target_url=TARGET_URL,
    )


@app.route("/api/timer")
def api_timer():
    if not current_participant() and not is_organizer():
        return jsonify({"error": "unauthorized"}), 401
    dl = deadline_dt()
    seconds_left = max(0, int((dl - datetime.utcnow()).total_seconds())) if dl else None
    return jsonify({"seconds_left": seconds_left, "active": get_setting("round_active") == "1"})


@app.route("/autosave", methods=["POST"])
def autosave():
    participant = current_participant()
    if not participant:
        return jsonify({"error": "unauthorized"}), 401
    ensure_submission_row(participant["id"])
    data = request.get_json(force=True, silent=True) or {}
    recon = data.get("recon", {})
    findings = data.get("findings", [])
    db = get_db()
    row = db.execute(
        "SELECT submitted FROM submissions WHERE participant_id = ?", (participant["id"],)
    ).fetchone()
    if row and row["submitted"]:
        return jsonify({"error": "already submitted"}), 409
    db.execute(
        "UPDATE submissions SET recon_json = ?, findings_json = ?, updated_at = ? "
        "WHERE participant_id = ?",
        (json.dumps(recon), json.dumps(findings), datetime.utcnow().isoformat(), participant["id"]),
    )
    db.commit()
    return jsonify({"ok": True, "saved_at": datetime.utcnow().strftime("%H:%M:%S")})


@app.route("/submit", methods=["POST"])
def submit():
    participant = current_participant()
    if not participant:
        return jsonify({"error": "unauthorized"}), 401
    ensure_submission_row(participant["id"])
    data = request.get_json(force=True, silent=True) or {}
    recon = data.get("recon", {})
    findings = data.get("findings", [])
    db = get_db()
    db.execute(
        "UPDATE submissions SET recon_json = ?, findings_json = ?, submitted = 1, "
        "submitted_at = ?, updated_at = ? WHERE participant_id = ?",
        (
            json.dumps(recon), json.dumps(findings),
            datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
            participant["id"],
        ),
    )
    db.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------- organizer routes
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == ORGANIZER_USERNAME and check_password_hash(ORGANIZER_PASSWORD_HASH, p):
            session.clear()
            session["is_organizer"] = True
            return redirect(url_for("admin_dashboard"))
        error = "Invalid organizer credentials."
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin_dashboard():
    if not require_organizer():
        return redirect(url_for("admin_login"))
    dl = deadline_dt()
    seconds_left = max(0, int((dl - datetime.utcnow()).total_seconds())) if dl else None
    return render_template(
        "admin_dashboard.html",
        seconds_left=seconds_left,
        round_active=get_setting("round_active") == "1",
    )


@app.route("/admin/api/status")
def admin_api_status():
    if not require_organizer():
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    rows = db.execute(
        """
        SELECT p.id, p.name, p.username, s.submitted, s.submitted_at, s.updated_at
        FROM participants p LEFT JOIN submissions s ON s.participant_id = p.id
        ORDER BY p.name COLLATE NOCASE
        """
    ).fetchall()
    out = []
    for r in rows:
        status = "not started"
        if r["updated_at"] and not r["submitted"]:
            status = "draft in progress"
        if r["submitted"]:
            status = "submitted"
        out.append({
            "id": r["id"], "name": r["name"], "username": r["username"],
            "status": status, "updated_at": r["updated_at"], "submitted_at": r["submitted_at"],
        })
    return jsonify({"participants": out})


@app.route("/admin/timer/set", methods=["POST"])
def admin_timer_set():
    if not require_organizer():
        return jsonify({"error": "unauthorized"}), 401
    minutes = int(request.form.get("minutes", 0))
    new_deadline = datetime.utcnow() + timedelta(minutes=minutes)
    set_setting("deadline", new_deadline.isoformat())
    set_setting("round_active", "1")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/timer/extend", methods=["POST"])
def admin_timer_extend():
    if not require_organizer():
        return jsonify({"error": "unauthorized"}), 401
    extra_minutes = int(request.form.get("extra_minutes", 5))
    dl = deadline_dt() or datetime.utcnow()
    new_deadline = dl + timedelta(minutes=extra_minutes)
    set_setting("deadline", new_deadline.isoformat())
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/participants")
def admin_participants():
    if not require_organizer():
        return redirect(url_for("admin_login"))
    db = get_db()
    rows = db.execute("SELECT * FROM participants ORDER BY name COLLATE NOCASE").fetchall()
    return render_template("admin_participants.html", participants=rows)


@app.route("/admin/participants/add", methods=["POST"])
def admin_participants_add():
    if not require_organizer():
        return redirect(url_for("admin_login"))
    names_raw = request.form.get("names", "")
    names = [n.strip() for n in names_raw.splitlines() if n.strip()]
    db = get_db()
    existing = {r["username"] for r in db.execute("SELECT username FROM participants").fetchall()}
    created = []
    for name in names:
        username = gen_username(name, existing)
        password = gen_password()
        db.execute(
            "INSERT INTO participants (name, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (name, username, generate_password_hash(password), datetime.utcnow().isoformat()),
        )
        db.commit()
        new_id = db.execute("SELECT id FROM participants WHERE username = ?", (username,)).fetchone()["id"]
        ensure_submission_row(new_id)
        created.append((name, username, password))
    db.commit()
    return render_template("admin_participants_created.html", created=created)


@app.route("/admin/participants/delete/<int:pid>", methods=["POST"])
def admin_participants_delete(pid):
    if not require_organizer():
        return redirect(url_for("admin_login"))
    db = get_db()
    db.execute("DELETE FROM submissions WHERE participant_id = ?", (pid,))
    db.execute("DELETE FROM participants WHERE id = ?", (pid,))
    db.commit()
    return redirect(url_for("admin_participants"))


@app.route("/admin/export.csv")
def admin_export_csv():
    if not require_organizer():
        return redirect(url_for("admin_login"))
    db = get_db()
    rows = db.execute(
        """
        SELECT p.name, p.username, s.recon_json, s.findings_json, s.submitted, s.submitted_at
        FROM participants p LEFT JOIN submissions s ON s.participant_id = p.id
        ORDER BY p.name COLLATE NOCASE
        """
    ).fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "username", "submitted", "submitted_at", "recon", "findings"])
    for r in rows:
        writer.writerow([
            r["name"], r["username"], bool(r["submitted"]), r["submitted_at"] or "",
            r["recon_json"] or "{}", r["findings_json"] or "[]",
        ])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=submissions.csv"},
    )


@app.route("/admin/download/<username>")
def admin_download_one(username):
    if not require_organizer():
        return redirect(url_for("admin_login"))
    db = get_db()
    row = db.execute(
        """
        SELECT p.name, p.username, s.recon_json, s.findings_json, s.submitted, s.submitted_at
        FROM participants p LEFT JOIN submissions s ON s.participant_id = p.id
        WHERE p.username = ?
        """,
        (username,),
    ).fetchone()
    if not row:
        return "Not found", 404
    recon = json.loads(row["recon_json"] or "{}")
    findings = json.loads(row["findings_json"] or "[]")
    lines = [
        f"Participant: {row['name']} ({row['username']})",
        f"Submitted: {'Yes at ' + row['submitted_at'] if row['submitted'] else 'No'}",
        "", "=== RECONNAISSANCE ===",
    ]
    for k, v in recon.items():
        lines.append(f"- {k}: {v}")
    lines += ["", "=== VULNERABILITY / SCOPE FINDINGS ==="]
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] Location: {f.get('location','')}")
        lines.append(f"    Attack type: {f.get('attack_type','')}")
        lines.append(f"    Evidence/justification: {f.get('evidence','')}")
        lines.append("")
    content = "\n".join(lines)
    return Response(
        content, mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={row['username']}_submission.txt"},
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 7000)), debug=True)
