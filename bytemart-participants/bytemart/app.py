"""
ByteMart — deliberately vulnerable practice target for a CTF.
Every insecure line here is INTENTIONAL. See SOLUTIONS.md for the answer key.
Do not deploy this outside an isolated competition environment.
"""
import os
import sqlite3
import subprocess
import platform

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, g, make_response, send_from_directory
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "bytemart.db")
UPLOAD_DIR = os.path.join(APP_DIR, "static", "uploads")

app = Flask(__name__)
# ponytail: hardcoded, guessable secret key — intentional (weak session signing)
app.secret_key = "bytemart123"
# --- VULNERABLE: session cookie is readable by JavaScript on purpose.
#     Flask sets HttpOnly=True by default; flipping it off here means any
#     XSS on the site (see /search, /guestbook) can steal document.cookie
#     and hijack another user's logged-in session. ---
app.config["SESSION_COOKIE_HTTPONLY"] = False


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
    fresh = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            card_number TEXT,
            avatar TEXT
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            address TEXT
        );
        CREATE TABLE IF NOT EXISTS guestbook (
            id INTEGER PRIMARY KEY,
            name TEXT,
            message TEXT
        );
        """
    )
    if fresh:
        # plaintext passwords stored on purpose — weak credential storage
        db.executescript(
            """
            INSERT INTO users (username, password, email, role, card_number) VALUES
                ('admin', 'SuperSecret!2024', 'admin@bytemart.local', 'admin', '4111-1111-1111-1111'),
                ('alice', 'alice123', 'alice@example.com', 'user', '4222-2222-2222-2222'),
                ('bob', 'bobpass', 'bob@example.com', 'user', '4333-3333-3333-3333');

            INSERT INTO products (name, description, price) VALUES
                ('Mechanical Keyboard', 'Clicky switches, RGB backlight.', '89.99'),
                ('Webcam Cover', 'Because paranoia is a feature.', '4.50'),
                ('USB Rubber Ducky Sticker', 'For flavor, not for hacking. Allegedly.', '2.00'),
                ('Faraday Phone Pouch', 'Blocks all the signals.', '19.99');

            INSERT INTO guestbook (name, message) VALUES
                ('visitor1', 'Nice store! Prices are fair.'),
                ('visitor2', 'Shipping was quick, thanks ByteMart.');
            """
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------- helpers
def current_user():
    if "username" in session:
        db = get_db()
        return db.execute(
            "SELECT * FROM users WHERE username = ?", (session["username"],)
        ).fetchone()
    return None


# ---------------------------------------------------------------- pages
@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        db = get_db()
        # --- VULNERABLE: string-built SQL query (SQL injection) ---
        query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
        try:
            row = db.execute(query).fetchone()
        except sqlite3.OperationalError as e:
            # --- VULNERABLE: verbose error leaks query / schema info ---
            return render_template("error.html", error=str(e), query=query), 500

        if row:
            session["username"] = row["username"]
            # --- VULNERABLE: role trusted from a client-editable cookie ---
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("role", row["role"])
            return resp
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("role")
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, email, role, card_number) "
                "VALUES (?, ?, ?, 'user', ?)",
                (
                    request.form.get("username", ""),
                    request.form.get("password", ""),  # stored in plaintext, on purpose
                    request.form.get("email", ""),
                    request.form.get("card_number", ""),
                ),
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Username already taken."
    return render_template("register.html", error=error)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    results = []
    if q:
        # --- VULNERABLE: string-built SQL query (UNION-based SQLi possible) ---
        query = f"SELECT name, description, price FROM products WHERE name LIKE '%{q}%'"
        try:
            results = db.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            return render_template("error.html", error=str(e), query=query), 500
    # --- VULNERABLE: q reflected back unescaped (reflected XSS) ---
    return render_template("search.html", q=q, results=results)


@app.route("/profile")
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # --- VULNERABLE: IDOR — any logged-in user can view any user_id ---
    target_id = request.args.get("user_id", user["id"])
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
    orders = db.execute("SELECT * FROM orders WHERE user_id = ?", (target_id,)).fetchall()
    return render_template("profile.html", user=user, target=target, orders=orders)


@app.route("/profile/picture", methods=["POST"])
def profile_picture():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    f = request.files.get("picture")
    if f and f.filename:
        # --- VULNERABLE: no extension / content-type allow-list — any file
        #     (including .html/.svg/.js with embedded scripts) is accepted
        #     and saved directly into the public static folder ---
        save_path = os.path.join(UPLOAD_DIR, f.filename)
        f.save(save_path)
        db = get_db()
        db.execute("UPDATE users SET avatar = ? WHERE id = ?", (f.filename, user["id"]))
        db.commit()
    return redirect(url_for("profile"))


@app.route("/update_email", methods=["POST"])
def update_email():
    # --- VULNERABLE: no CSRF token on a state-changing POST ---
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    db.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (request.form.get("email", ""), user["id"]),
    )
    db.commit()
    return redirect(url_for("profile"))


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO guestbook (name, message) VALUES (?, ?)",
            (request.form.get("name", "anon"), request.form.get("message", "")),
        )
        db.commit()
        return redirect(url_for("guestbook"))
    entries = db.execute("SELECT * FROM guestbook ORDER BY id DESC").fetchall()
    # --- VULNERABLE: message rendered with |safe in template (stored XSS) ---
    return render_template("guestbook.html", entries=entries)


@app.route("/admin")
def admin():
    # --- VULNERABLE: authorization decided by a client-controlled cookie,
    #     not by the server-side session/role in the database ---
    role = request.cookies.get("role", "user")
    if role != "admin":
        return render_template("error.html", error="403 Forbidden — admin only.", query=None), 403
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/tools", methods=["GET", "POST"])
def tools():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        flag = "-n" if platform.system() == "Windows" else "-c"
        # --- VULNERABLE: shell=True with unsanitized input (command injection) ---
        cmd = f"ping {flag} 1 {host}"
        try:
            output = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT, timeout=5, text=True
            )
        except Exception as e:
            output = str(e)
    return render_template("tools.html", output=output, host=host)


@app.route("/download")
def download():
    # --- VULNERABLE: filename taken from user input, no path sanitization
    #     (path traversal / arbitrary file read) ---
    filename = request.args.get("file", "welcome.txt")
    path = os.path.join(APP_DIR, "reports", filename)
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        content = f"Could not read file: {e}"
    return render_template("download.html", content=content, filename=filename)


@app.route("/redirect")
def open_redirect():
    # --- VULNERABLE: unvalidated redirect target (open redirect) ---
    target = request.args.get("url", "/")
    return redirect(target)


@app.route("/robots.txt")
def robots():
    return send_from_directory(APP_DIR, "robots.txt")


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(os.path.join(APP_DIR, "reports"), exist_ok=True)
    init_db()
    # --- VULNERABLE: debug mode on (stack traces / interactive debugger exposed) ---
    app.run(host="0.0.0.0", port=5000, debug=True)
