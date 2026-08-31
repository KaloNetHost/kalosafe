# KALOSAFE

A confidential intelligence and case-management platform for the Kalopsia
community, built as a real working full-stack application: Python/Flask
backend, PostgreSQL database, server-rendered HTML/CSS frontend. It is
completely independent of Discord — no OAuth, bots, or webhooks are used
anywhere; Discord usernames/IDs are plain manually-entered text fields.

## Deploying it for free (Render + Supabase)

This is the path most people reading this will want. It costs $0 and
your case data — **and now evidence files too** — survive restarts
(unlike plain free-tier hosting on its own — see "Why Postgres" and
"Why Supabase Storage" below).

1. Create a free project at **supabase.com** (no credit card).
2. Get your database connection string: Project Settings → Database →
   Connection string → **URI**. Copy it.
3. Get your storage keys: Project Settings → API → copy the **Project URL**
   and the **service_role secret key** (not the "anon" key — the service
   role key is the one the backend uses to read/write files privately).
4. Create three private storage buckets: Storage → New bucket, create
   each of `kalosafe-originals`, `kalosafe-watermarked`, and
   `kalosafe-reports`, leaving "Public bucket" **unchecked** for all three.
5. Push this code to a GitHub repo (Replit's Git panel can do this for
   you with no terminal needed — Tools → Git → Create a Git Repository
   → Connect to GitHub → Push).
6. Create a free Web Service at **render.com**, pointed at that repo.
   - Build command: `pip install -r requirements.txt`
   - Start command: `python app.py`
   - Add these environment variables under the service's "Environment" tab:
     - `DATABASE_URL` — the Supabase connection URI from step 2
     - `SUPABASE_URL` — the Project URL from step 3
     - `SUPABASE_SERVICE_KEY` — the service_role key from step 3
7. Once it deploys, open Render's Shell tab for the service and run
   `python seed.py` once, to create the tables and demo accounts.
8. Visit the `.onrender.com` URL Render gives you.

With all three environment variables set, **everything** — case
records, accounts, messages, the audit log, original evidence files,
watermarked evidence copies, and anonymous-report attachments — is
stored in your free Supabase project and survives Render restarts,
redeploys, and sleep/wake cycles.

If you skip the `SUPABASE_URL`/`SUPABASE_SERVICE_KEY` variables (only
`DATABASE_URL`), the app still runs fine — it just falls back to
storing evidence files on Render's local disk, which means those
specific files (not the case records referencing them) can still be
lost on restart. Set all three for full protection.

## Running it locally

Requirements: Python 3.10+, `pip install -r requirements.txt`, and a
Postgres database (the same free Supabase project works fine for local
testing too).

```bash
cd kalosafe
export DATABASE_URL="postgresql://...."     # from Supabase (or any Postgres)
export SUPABASE_URL="https://xxxx.supabase.co"   # optional locally — omit to use local disk for evidence
export SUPABASE_SERVICE_KEY="...."               # optional locally
python3 seed.py       # creates the KaloSafe tables + fictional demo data
python3 app.py         # runs on http://127.0.0.1:5055 (or $PORT if set)
```

### Why Postgres instead of SQLite

The app was originally built against a single SQLite file — simpler for
a first pass, but on free hosting tiers (Render's free web service, for
example) the disk isn't persistent: that file gets silently wiped on
every restart/redeploy, losing every case, account, and message. This
build instead talks to Postgres via the standard `DATABASE_URL`
environment variable, so you can point it at a **free Supabase
project** (free forever, no credit card, Postgres included) and case
data survives restarts. Supabase free projects pause after a week with
no traffic, but pausing is not deleting — the data is still there the
next time the app is used, it just takes a few seconds to wake up.

### Why Supabase Storage for evidence

Same underlying problem, different kind of file: uploaded screenshots
and PDFs used to live on the same ephemeral local disk as the old
SQLite file. `storage.py` now uploads/downloads that evidence through
Supabase's Storage API (three private buckets — originals, watermarked
copies, and anonymous-report attachments), using the same free
Supabase project as the database. Evidence is still only ever served
back to a browser through KaloSafe's own authenticated routes — the
buckets themselves stay private, so KaloSafe's permission rules (who
can see the original vs. the watermarked copy) are enforced exactly as
before; Supabase is just where the bytes now live instead of Render's
disk.

Demo accounts (change these — they exist only to let you explore the app):

| Codename  | Password             | Rank        |
|-----------|-----------------------|-------------|
| Crown     | CoordinatorDemo123!   | Coordinator |
| Moonlight | ManagerDemo123!       | Manager     |
| Meridian  | ManagerDemo123!       | Manager     |
| Amber     | AnalystDemo123!       | Analyst     |
| Aster     | AnalystDemo123!       | Analyst     |
| Atlas     | AnalystDemo123!       | Analyst     |

Run the automated permission boundary tests (start the server first,
against a database you don't mind `seed.py` wiping):

```bash
python3 test_permissions.py
```

All 13 boundary checks (the 10 required in the spec, plus a couple of
supporting checks) passed against the original SQLite build. The logic
being tested (`auth.py`'s permission functions, and the route
decorators in `app.py`) is unchanged by the Postgres migration — only
the storage layer (`db.py`) and the `?` → `%s` placeholder syntax
changed — but this hasn't been re-run against a live Postgres instance
(the sandbox this was built in has no network access to reach one). If
anything behaves unexpectedly after you deploy it, tell me exactly what
you see and I'll fix it immediately.

## What's implemented

- **Public area**: landing page, anonymous report form (no account/email/
  phone required, no reporter identity stored), public Watchlist (names
  only), login. Nothing else is reachable without a session.
- **Auth & RBAC**: Analyst / Manager / Coordinator ranks, codenames enforced
  server-side (`A…` / `M…` / `Crown`), scrypt password hashing via
  Werkzeug, session cookies (httpOnly, SameSite=Lax), CSRF tokens on every
  form, basic login rate-limiting.
- **Case classification model** (Level 1 Green → Level X Black) with the
  exact visibility/open/contribute rules from the spec, all enforced in
  `auth.py` and re-checked on every route — not just hidden in the UI.
- **Anonymous report → Manager review queue → Accept/Postpone/Reject →
  case creation**, with a Rejected Reports Archive that never appears in
  active case lists.
- **Person of Interest workflow**: Analyst recommends, Manager+ decides;
  an Analyst has no route capable of deciding at all, and a Manager cannot
  approve their own recommendation.
- **Evidence**: original file stored untouched and restricted to
  Manager+; a separate watermarked JPEG copy (Pillow) is generated for
  Analysts, stamped top-right with case number / analyst codename /
  "PROPERTY OF KALOSAFE" without cropping or obscuring the rest of the
  image. Both original and watermarked downloads are audit-logged.
  Files are served through authenticated routes, never from a public
  static/uploads path, and stored under randomised filenames. With
  `SUPABASE_URL`/`SUPABASE_SERVICE_KEY` set, the files themselves live
  in Supabase Storage rather than on Render's disk — see "Deploying it
  for free" above.
- **Messaging**: global channel, 1:1 private messages, per-case chat
  (access to a case's chat follows the same permission function as
  opening the case).
- **Search**: single query box across case number/subject/Discord
  username/ID/classification/status, filtered through the same
  visibility function used for the case list — a search can never
  surface more than opening `/cases` would.
- **Audit log**: immutable (no update/delete route exists anywhere —
  verified by `test_permissions.py`), Coordinator-only, filterable by
  codename, action, case, and date range.
- **Personnel**: Manager creates Analyst accounts (manual codename +
  password, must start with "A"); only the Coordinator creates Manager
  accounts (must start with "M"); a `real_identity` column exists but is
  rendered only on the Coordinator's Personnel Directory page.
- **Security headers**: `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, a restrictive CSP, and `no-store` cache headers on
  every authenticated page so nothing sensitive is cached by the browser
  or an intermediary.
- **Demo data**: entirely fictional (`seed.py`) — no real people, no real
  Discord IDs, no real screenshots.

## Documented limitations (please read before relying on this for anything real)

- **Postgres/Supabase Storage migration hasn't been tested against a live
  Supabase project** — see the note in "Running it locally" above. The
  code follows standard, well-documented patterns for both, but this was
  built in a sandbox with no internet access to actually connect to one.
  If something errors after deployment, send me the exact message and
  I'll fix it right away.
- **Dev server only.** `app.run()` is Flask's development server.
  Render runs it directly, which is fine at small scale, but for
  serious traffic run it behind gunicorn/uWSGI, and set
  `KALOSAFE_HTTPS=1` once you're on HTTPS so session cookies get the
  `Secure` flag.
- **Rate limiting is in-process and in-memory** — fine for a single
  instance, not once you scale to multiple workers. Swap in
  Flask-Limiter with a shared Redis backend if that becomes relevant.
- **CSRF protection is a minimal hand-rolled token check**, not a
  hardened library. Flask-WTF/Flask-SeaSurf would be the more
  battle-tested choice for a real deployment.
- **No email/2FA**, no password-reset flow (by design, per the spec:
  Analysts cannot change their own password — a Manager must
  communicate new credentials out-of-band). A production system should
  still give the Coordinator a way to force a password reset without
  seeing the plaintext.
- **Audit log immutability is enforced by "no route exists to mutate
  it,"** not by database-level write-once storage or hash-chaining —
  meaningful if someone ever got raw database access. A hardened
  deployment should add e.g. an append-only table, periodic export to
  WORM storage, or a hash chain over rows.
- **File-type validation is extension-based.** A hardened deployment
  should additionally sniff file content/magic bytes and run uploads
  through malware scanning.
- **Contribution/attribution model for Level 2/3 cases** is implemented
  as specified (unassigned Analysts can add a contribution without
  reading the case or other analysts' contributions), but a real
  deployment should decide a retention/review policy for these
  contributions (who triages them into the case record, and when).

## Structure

```
kalosafe/
  app.py            All routes
  auth.py           RBAC + case-permission functions (single source of truth)
  db.py             Postgres schema + connection + audit logging helper
  storage.py        Supabase Storage helper (with local-disk fallback)
  watermark.py       Evidence watermarking (Pillow)
  seed.py           Fictional demo data (idempotent — safe to re-run)
  test_permissions.py   Automated boundary tests
  templates/        Jinja2 templates (public/, auth/, dashboard/, cases/, personnel/, messages/)
  static/css/style.css
  uploads/          local fallback only — used when Supabase Storage env vars aren't set
```
