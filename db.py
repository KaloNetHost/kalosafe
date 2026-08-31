"""
KALOSAFE — Database layer (PostgreSQL edition)
------------------------------------------------
Originally written against SQLite for local testing; migrated to
PostgreSQL so case data survives restarts/redeploys on free hosting
tiers (SQLite's single file gets wiped by Render's free plan on every
restart — a real Postgres database, e.g. a free Supabase project,
does not).

Set the DATABASE_URL environment variable (Supabase gives you this
under Project Settings -> Database -> Connection string -> URI) and
everything else here is unchanged in spirit from the SQLite version:
plain parameterised SQL, no ORM, so every query is visible and
auditable. All queries use %s placeholders and bound parameters
(never string-formatted SQL) to prevent injection.
"""
import os
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    codename TEXT UNIQUE NOT NULL,
    rank TEXT NOT NULL CHECK(rank IN ('ANALYST','MANAGER','COORDINATOR')),
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    real_identity TEXT DEFAULT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    ref_number TEXT UNIQUE NOT NULL,
    subject_name TEXT NOT NULL,
    discord_username TEXT,
    discord_id TEXT,
    category TEXT,
    incident_datetime TEXT,
    description TEXT NOT NULL,
    additional_info TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','ACCEPTED','POSTPONED','REJECTED')),
    submitted_at TEXT NOT NULL,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    review_note TEXT,
    resulting_case_id INTEGER
);

CREATE TABLE IF NOT EXISTS report_evidence (
    id SERIAL PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id),
    stored_path TEXT NOT NULL,
    original_filename TEXT,
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id SERIAL PRIMARY KEY,
    case_number TEXT UNIQUE NOT NULL,
    subject_name TEXT NOT NULL,
    discord_username TEXT,
    discord_id TEXT,
    classification TEXT NOT NULL DEFAULT 'LEVEL1' CHECK(classification IN ('LEVEL1','LEVEL2','LEVEL3','LEVELX')),
    designation TEXT DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','REPORTED','DROPPED')),
    assigned_analyst_id INTEGER REFERENCES users(id),
    manager_id INTEGER REFERENCES users(id),
    source_report_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_notes (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    author_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_contributions (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    author_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attach_requests (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    analyst_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','DENIED')),
    requested_at TEXT NOT NULL,
    decided_by INTEGER,
    decided_at TEXT
);

CREATE TABLE IF NOT EXISTS poi_records (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    recommended_by INTEGER NOT NULL,
    reason TEXT NOT NULL,
    requested_designation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','REJECTED')),
    decided_by INTEGER,
    decided_at TEXT,
    decision_note TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    uploaded_by INTEGER NOT NULL,
    original_path TEXT NOT NULL,
    watermarked_path TEXT,
    original_filename TEXT NOT NULL,
    content_type TEXT,
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlist (
    id SERIAL PRIMARY KEY,
    display_name TEXT NOT NULL,
    case_id INTEGER,
    added_by INTEGER NOT NULL,
    added_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    channel_type TEXT NOT NULL CHECK(channel_type IN ('GLOBAL','PRIVATE','CASE')),
    case_id INTEGER,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    ts TEXT NOT NULL,
    user_id INTEGER,
    user_codename TEXT,
    user_rank TEXT,
    action TEXT NOT NULL,
    case_ref TEXT,
    target TEXT,
    result TEXT,
    details TEXT
);
"""


class _DictRowConnection:
    """
    Thin wrapper so the rest of the app (written against sqlite3.Row's
    dict-like access, e.g. case["classification"]) doesn't need to
    change at all — psycopg2's RealDictCursor already returns
    dict-like rows, so this just standardises execute()/commit()/close().
    """
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur

    def executescript(self, sql):
        cur = self._conn.cursor()
        cur.execute(sql)
        cur.close()

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. Add it in Render's Environment tab "
            "(Supabase Project Settings -> Database -> Connection string -> URI)."
        )
    conn = psycopg2.connect(DATABASE_URL)
    return _DictRowConnection(conn)


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log_audit(conn, user, action, case_ref=None, target=None, result="SUCCESS", details=None):
    """
    Immutable audit entry. There is deliberately no UPDATE/DELETE route
    for this table anywhere in the application. `user` may be None for
    unauthenticated events (e.g. failed login, anonymous report submission).
    """
    conn.execute(
        "INSERT INTO audit_log (ts, user_id, user_codename, user_rank, action, case_ref, target, result, details) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            now(),
            user["id"] if user else None,
            user["codename"] if user else "ANONYMOUS",
            user["rank"] if user else "PUBLIC",
            action,
            case_ref,
            target,
            result,
            details,
        ),
    )
    conn.commit()
