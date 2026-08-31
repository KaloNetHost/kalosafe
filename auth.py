"""
KALOSAFE — Authorisation core.

Every permission decision that matters lives HERE, in server-side
Python, and every route in app.py calls into these functions before
touching the database or returning data. The frontend hides buttons
too, but that is cosmetic only — these checks are what actually
protect the data, and they run identically no matter how the request
was constructed (browser click, curl, modified form, edited URL).
"""
from functools import wraps
from flask import session, redirect, url_for, abort, g
from db import get_db

RANKS = ("ANALYST", "MANAGER", "COORDINATOR")
RANK_LEVEL = {"ANALYST": 1, "MANAGER": 2, "COORDINATOR": 3}


def current_user():
    if "user_id" not in session:
        return None
    if getattr(g, "_user_cache", None):
        return g._user_cache
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE id=%s AND active=1", (session["user_id"],)
    ).fetchone()
    conn.close()
    if row is None:
        session.clear()
        return None
    g._user_cache = row
    return row


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def rank_required(min_rank):
    """Require the session user to hold at least `min_rank`."""
    def deco(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for("login"))
            if RANK_LEVEL[user["rank"]] < RANK_LEVEL[min_rank]:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return deco


def coordinator_only(f):
    return rank_required("COORDINATOR")(f)


def manager_or_above(f):
    return rank_required("MANAGER")(f)


# ---------------------------------------------------------------------------
# Case-level permission model. This is the single source of truth for
# "can this user see/open/act on this case" — used by every case route
# AND by search, so results can never leak past what a direct open
# would allow.
# ---------------------------------------------------------------------------

def can_see_case_exists(user, case):
    """Whether the case may appear at all in a list/search result."""
    if user["rank"] in ("MANAGER", "COORDINATOR"):
        return True
    # ANALYST
    if case["classification"] == "LEVELX":
        return False  # Level X is invisible to Analysts entirely, even existence-wise
    return True  # Level 1/2/3 existence is visible to all analysts


def can_open_case(user, case):
    """Whether the user may view full case contents (evidence, notes, chat, history)."""
    if user["rank"] in ("MANAGER", "COORDINATOR"):
        return True
    # ANALYST
    if case["classification"] == "LEVELX":
        return False
    if case["classification"] == "LEVEL1":
        return case["assigned_analyst_id"] == user["id"]
    if case["classification"] == "LEVEL2":
        return case["assigned_analyst_id"] == user["id"]
    if case["classification"] == "LEVEL3":
        # All analysts may view Level 3 (encouraged to contribute / stay aware),
        # but full sensitive contents still require assignment.
        return case["assigned_analyst_id"] == user["id"]
    return False


def can_view_level3_summary(user, case):
    """Level 3 cases appear as priority items to ALL analysts even if not opened."""
    return case["classification"] == "LEVEL3"


def can_contribute(user, case):
    """Whether an unassigned analyst may submit info/evidence without gaining read access."""
    if user["rank"] in ("MANAGER", "COORDINATOR"):
        return True
    if case["classification"] == "LEVELX":
        return False
    if case["classification"] in ("LEVEL2", "LEVEL3"):
        return True
    return case["assigned_analyst_id"] == user["id"]


def can_access_original_evidence(user):
    return user["rank"] in ("MANAGER", "COORDINATOR")


def can_view_real_identity(user):
    return user["rank"] == "COORDINATOR"
