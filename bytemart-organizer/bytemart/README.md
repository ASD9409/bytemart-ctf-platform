# ByteMart — Vulnerable Web App for a Security CTF

A small, self-contained Flask store built for a "spot the vulnerability"
competition. Participants get a URL and a scoring sheet; they browse the
site, find the flaws, and write up **what the vulnerability is and where
it lives**.

This repo is the **organizer** copy — it includes `SOLUTIONS.md`, the
answer key. Don't hand that file to participants.

## Run it

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Visit `http://localhost:5000`. The SQLite database (`bytemart.db`) is
created and seeded automatically on first run — delete it to reset.

To run it for a live competition, host it on an isolated VM or container
that participants can reach but that has no access to anything sensitive
(it runs real `subprocess`/file-read calls against its own host, by design).
A Docker one-liner:

```bash
docker run -p 5000:5000 -v $(pwd):/app -w /app python:3.12-slim \
  bash -c "pip install -r requirements.txt && python3 app.py"
```

## Format ideas

- **Jeopardy-style**: give points per vulnerability class found, bonus
  points for a working proof-of-concept payload.
- **Report-only**: participants submit a short write-up per finding
  (location, vulnerability type, impact, one-line fix) — no exploitation
  required, good for a beginner-friendly track.
- **Time-boxed**: 60–90 minutes is enough for ~16 findings at a
  basic/intermediate pace.

## Reset between teams/rounds

```bash
rm bytemart.db && rm -rf static/uploads/* && python3 app.py
```

## Safety notes

- Every vulnerability here is intentional and documented in `SOLUTIONS.md`.
- The file-upload and command-injection routes execute real actions on the
  host filesystem/shell — only run this inside a disposable, network-isolated
  environment (VM, container, or sandboxed cloud instance), never on a
  machine with anything you care about.
- Don't expose this to the public internet outside the competition window.
