# CTF Portal — Participant Login & Submission System

Sits in front of the actual target (ByteMart). Participants log in here with
credentials you generate, see the target link + a recon tool guide, and fill
in an autosaving recon/vulnerability form. You get a live dashboard of who's
submitted, a countdown timer you can extend on the fly, and per-participant
or bulk CSV export.

This is real competition infrastructure, not a vulnerable target — it's
built with hashed passwords, parameterized queries, and escaped output
throughout (unlike ByteMart, which is deliberately insecure).

## Before you run it

1. Open `app.py` and change:
   ```python
   ORGANIZER_USERNAME = "organizer"
   ORGANIZER_PASSWORD_HASH = generate_password_hash("changeme123")  # <-- change this password
   TARGET_URL = "http://TARGET-IP-OR-DOMAIN:5000"  # point this at your running ByteMart instance
   ```

## Run it

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Runs on port 7000 (port 6000 is blocked by most browsers as an unsafe port,
so don't switch back to it). Visit:
- `http://localhost:7000/login` — participant login
- `http://localhost:7000/admin/login` — organizer login

The database (`portal.db`) and a session secret key (`.secret_key`) are
created automatically on first run.

## Running the actual event

1. **Log in as organizer** (`/admin/login`).
2. **Add participants**: Participants page → paste one name per line →
   Generate accounts. Copy the generated username/password table — it's
   shown once and not stored anywhere retrievable afterward (only the
   hash is kept in the database).
3. **Distribute credentials** to each participant (however you'd like —
   email, printed slips, etc).
4. **Start the timer**: Dashboard → "Start round" → enter minutes → this
   sets the deadline and marks the round active. Participants' countdown
   starts reflecting this the next time their page syncs (within ~15s).
5. **Watch the live dashboard** — status per participant updates every
   ~4 seconds: *not started* → *draft in progress* → *submitted*.
6. **Extend if needed**: "Extend deadline by (minutes)" — works at any
   point, including right before time runs out. Participants don't lose
   anything either way, since their form autosaves continuously as they
   type (every ~1.2s after a change, plus every 20s as a failsafe) —
   independent of the timer.
7. **Export results**: "Export all (CSV)" for everyone at once, or
   "download" next to an individual participant's row for just theirs
   (saved as `<username>_submission.txt`).

## Resetting between events

```bash
rm portal.db
python3 app.py
```

## Notes

- Once a participant submits, their form locks — further autosave/submit
  attempts are rejected (HTTP 409). There's currently no "reopen" button;
  if you need to let someone resubmit, that has to be added or done
  directly in the database.
- Deleting a participant (Participants page) also deletes their submission.
- For under ~30 participants over a single round, SQLite + polling is
  more than sufficient — no need for a heavier database or websockets.
