"""
KALOSAFE — demo data seeding.

Everything here is fictional: no real people, no real allegations, no
real Discord IDs, no real screenshots. Run with `python3 seed.py`.
Safe to re-run any time — it wipes and recreates the KaloSafe tables
in whatever Postgres database DATABASE_URL points to (it does NOT
touch anything else in that database, in case you're sharing a
Supabase project with something else).
"""
from werkzeug.security import generate_password_hash
from db import get_db, init_db, now

init_db()
conn = get_db()

# Make this script idempotent: safe to run again against the same
# database without hitting "codename already exists" errors.
conn.execute(
    "TRUNCATE case_notes, case_contributions, attach_requests, poi_records, "
    "evidence, watchlist, messages, audit_log, report_evidence, reports, "
    "cases, users RESTART IDENTITY CASCADE"
)
conn.commit()

# --- Users -----------------------------------------------------------------
def add_user(codename, rank, password, real_identity=None):
    conn.execute(
        "INSERT INTO users (codename, rank, password_hash, active, created_at, real_identity) "
        "VALUES (%s,%s,%s,1,%s,%s)",
        (codename, rank, generate_password_hash(password), now(), real_identity),
    )
    return conn.execute("SELECT id FROM users WHERE codename=%s", (codename,)).fetchone()["id"]

crown_id = add_user("Crown", "COORDINATOR", "CoordinatorDemo123!")
moonlight_id = add_user("Moonlight", "MANAGER", "ManagerDemo123!")
meridian_id = add_user("Meridian", "MANAGER", "ManagerDemo123!")
amber_id = add_user("Amber", "ANALYST", "AnalystDemo123!")
aster_id = add_user("Aster", "ANALYST", "AnalystDemo123!")
atlas_id = add_user("Atlas", "ANALYST", "AnalystDemo123!")
conn.commit()

# --- Fictional cases ---------------------------------------------------------
def add_case(number, subject, discord_username, discord_id, classification, designation, analyst_id, manager_id):
    conn.execute(
        "INSERT INTO cases (case_number, subject_name, discord_username, discord_id, classification, "
        "designation, status, assigned_analyst_id, manager_id, created_at, updated_at) "
        "VALUES (%s,%s,%s,%s,%s,%s, 'OPEN', %s,%s,%s,%s)",
        (number, subject, discord_username, discord_id, classification, designation,
         analyst_id, manager_id, now(), now()),
    )
    return conn.execute("SELECT id FROM cases WHERE case_number=%s", (number,)).fetchone()["id"]

c1 = add_case("CASE-0001", "Example Subject A", "example_subject_a", "111111111111111111", "LEVEL1", None, amber_id, moonlight_id)
c2 = add_case("CASE-0002", "Example Subject B", "example_subject_b", "222222222222222222", "LEVEL2", "MONITOR", aster_id, moonlight_id)
c3 = add_case("CASE-0003", "Example Subject C", "example_subject_c", "333333333333333333", "LEVEL3", "EXTREME_POI", atlas_id, meridian_id)
c4 = add_case("CASE-0004", "Example Subject D", "example_subject_d", "444444444444444444", "LEVELX", None, None, moonlight_id)
c5 = add_case("CASE-0005", "Example Subject E", "example_subject_e", "555555555555555555", "LEVEL1", None, None, None)  # unassigned

conn.execute("INSERT INTO case_notes (case_id, author_id, content, created_at) VALUES (%s,%s,%s,%s)",
             (c1, amber_id, "Initial fictional note for demo purposes only.", now()))
conn.execute("INSERT INTO case_notes (case_id, author_id, content, created_at) VALUES (%s,%s,%s,%s)",
             (c3, atlas_id, "Demo note: subject flagged for elevated monitoring (fictional).", now()))

# Pending PoI recommendation awaiting a Manager decision
conn.execute(
    "INSERT INTO poi_records (case_id, recommended_by, reason, requested_designation, status, created_at) "
    "VALUES (%s,%s,%s,%s, 'PENDING', %s)",
    (c1, amber_id, "Fictional demo justification for review workflow.", "PERSON_OF_INTEREST", now()),
)

# Pending attach request
conn.execute(
    "INSERT INTO attach_requests (case_id, analyst_id, status, requested_at) VALUES (%s,%s, 'PENDING', %s)",
    (c5, aster_id, now()),
)

# --- Watchlist (public — names only) ---------------------------------------
conn.execute("INSERT INTO watchlist (display_name, case_id, added_by, added_at) VALUES (%s,%s,%s,%s)",
             ("Example Subject C", c3, moonlight_id, now()))
conn.execute("INSERT INTO watchlist (display_name, case_id, added_by, added_at) VALUES (%s,%s,%s,%s)",
             ("Fictional Flagged User", None, moonlight_id, now()))

# --- A pending anonymous report in the review queue -------------------------
conn.execute(
    "INSERT INTO reports (ref_number, subject_name, discord_username, discord_id, category, "
    "incident_datetime, description, additional_info, status, submitted_at) "
    "VALUES ('RPT-DEMO0001', 'Example Subject F', 'example_subject_f', '666666666666666666', "
    "'Harassment', '2026-08-20T18:00', 'Fictional demo report description for testing the review queue.', "
    "NULL, 'PENDING', %s)",
    (now(),),
)

# --- A rejected report already in the archive -------------------------------
conn.execute(
    "INSERT INTO reports (ref_number, subject_name, category, description, status, submitted_at, reviewed_by, reviewed_at, review_note) "
    "VALUES ('RPT-DEMO0002', 'Example Subject G', 'Other', 'Fictional demo report, insufficient information.', "
    "'REJECTED', %s, %s, %s, 'Demo: insufficient detail to proceed.')",
    (now(), moonlight_id, now()),
)

conn.commit()
conn.close()

print("Demo data seeded.")
print("Login codenames (password shown for demo only — change/rotate in real use):")
print("  Crown       / CoordinatorDemo123!   (Coordinator)")
print("  Moonlight   / ManagerDemo123!       (Manager)")
print("  Meridian    / ManagerDemo123!       (Manager)")
print("  Amber       / AnalystDemo123!       (Analyst)")
print("  Aster       / AnalystDemo123!       (Analyst)")
print("  Atlas       / AnalystDemo123!       (Analyst)")
