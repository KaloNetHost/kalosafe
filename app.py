import os
import re
import io
import time
import uuid
import secrets
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    abort, send_file, flash, g, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from db import get_db, init_db, now, log_audit
from auth import (
    current_user, login_required, rank_required, coordinator_only,
    manager_or_above, can_see_case_exists, can_open_case,
    can_view_level3_summary, can_contribute, can_access_original_evidence,
    can_view_real_identity, RANK_LEVEL,
)
from watermark import make_watermarked_copy
from storage import upload as storage_upload, download as storage_download, REMOTE_ENABLED as STORAGE_REMOTE

BASE_DIR = os.path.dirname(__file__)
UPLOAD_ORIGINAL = os.path.join(BASE_DIR, "uploads", "original")
UPLOAD_WATERMARK = os.path.join(BASE_DIR, "uploads", "watermarked")
UPLOAD_REPORTS = os.path.join(BASE_DIR, "uploads", "reports")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10MB

app = Flask(__name__)
app.secret_key = os.environ.get("KALOSAFE_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set to True when served over HTTPS in production.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("KALOSAFE_HTTPS", "0") == "1"

os.makedirs(UPLOAD_ORIGINAL, exist_ok=True)
os.makedirs(UPLOAD_WATERMARK, exist_ok=True)
os.makedirs(UPLOAD_REPORTS, exist_ok=True)

CLASS_LABELS = {
    "LEVEL1": "LEVEL 1 — GREEN",
    "LEVEL2": "LEVEL 2 — ORANGE",
    "LEVEL3": "LEVEL 3 — RED",
    "LEVELX": "LEVEL X — MANAGER RESTRICTED",
}

# ---------------------------------------------------------------------------
# Security headers + no-cache for authenticated pages (section 24: no
# accidental disclosure via cached pages / metadata leakage)
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    if session.get("user_id") or request.path.startswith(("/cases", "/audit", "/personnel", "/messages", "/reports")):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        resp.headers["Pragma"] = "no-cache"
    return resp


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="ACCESS DENIED — insufficient clearance for this resource."), 403


@app.errorhandler(404)
def notfound(e):
    return render_template("error.html", code=404, message="RESOURCE NOT FOUND."), 404


@app.errorhandler(500)
def servererr(e):
    # Never leak stack traces / internals to the client.
    return render_template("error.html", code=500, message="An internal error occurred. The event has been logged."), 500


@app.context_processor
def inject_globals():
    return dict(current_user=current_user(), class_labels=CLASS_LABELS, csrf_token=get_csrf_token)


# ---------------------------------------------------------------------------
# CSRF protection (minimal, dependency-free)
# ---------------------------------------------------------------------------
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)
    return session["csrf_token"]


def require_csrf():
    token = request.form.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
        abort(400)


# ---------------------------------------------------------------------------
# Basic in-memory rate limiting for login (per-process; adequate for a
# single dev instance, documented limitation for production — see README)
# ---------------------------------------------------------------------------
_login_attempts = {}


def rate_limited(key, limit=8, window=300):
    bucket = _login_attempts.setdefault(key, [])
    cutoff = time.time() - window
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= limit:
        return True
    bucket.append(time.time())
    return False


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def gen_case_number(conn):
    row = conn.execute("SELECT COUNT(*) c FROM cases").fetchone()
    return f"CASE-{row['c'] + 1:04d}"


def gen_ref_number(conn):
    return "RPT-" + secrets.token_hex(4).upper()


# ===========================================================================
# PUBLIC AREA
# ===========================================================================
@app.route("/")
def landing():
    return render_template("public/landing.html")


@app.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "GET":
        return render_template("public/report_form.html", csrf=get_csrf_token())

    require_csrf()
    subject_name = request.form.get("subject_name", "").strip()
    discord_username = request.form.get("discord_username", "").strip()
    discord_id = request.form.get("discord_id", "").strip()
    category = request.form.get("category", "").strip()
    incident_dt = request.form.get("incident_datetime", "").strip()
    description = request.form.get("description", "").strip()
    additional_info = request.form.get("additional_info", "").strip()

    if not subject_name or not description:
        flash("Subject name and description are required.", "error")
        return render_template("public/report_form.html", csrf=get_csrf_token()), 400

    conn = get_db()
    ref = gen_ref_number(conn)
    conn.execute(
        "INSERT INTO reports (ref_number, subject_name, discord_username, discord_id, category, "
        "incident_datetime, description, additional_info, status, submitted_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s, 'PENDING', %s)",
        (ref, subject_name, discord_username or None, discord_id or None, category or None,
         incident_dt or None, description, additional_info or None, now()),
    )
    report_id = conn.execute("SELECT id FROM reports WHERE ref_number=%s", (ref,)).fetchone()["id"]

    files = request.files.getlist("evidence")
    for f in files:
        if f and f.filename and allowed_file(f.filename):
            ext = f.filename.rsplit(".", 1)[1].lower()
            stored_name = f"{uuid.uuid4().hex}.{ext}"
            local_path = os.path.join(UPLOAD_REPORTS, stored_name)
            f.save(local_path)
            if STORAGE_REMOTE:
                with open(local_path, "rb") as fh:
                    storage_upload("kalosafe-reports", stored_name, fh.read(), f.mimetype or "application/octet-stream")
                try:
                    os.remove(local_path)
                except OSError:
                    pass
            conn.execute(
                "INSERT INTO report_evidence (report_id, stored_path, original_filename, uploaded_at) VALUES (%s,%s,%s,%s)",
                (report_id, stored_name, None, now()),  # original_filename intentionally not retained (metadata minimisation)
            )
    conn.commit()
    # No identifying info about the reporter (no IP, account, email) is stored.
    log_audit(conn, None, "REPORT_SUBMITTED", target=ref, details="Anonymous submission")
    conn.close()
    return redirect(url_for("report_confirmation", ref=ref))


@app.route("/report/confirmation/<ref>")
def report_confirmation(ref):
    if not re.fullmatch(r"RPT-[A-F0-9]{8}", ref):
        abort(404)
    return render_template("public/report_confirmation.html", ref=ref)


@app.route("/watchlist")
def watchlist_public():
    conn = get_db()
    rows = conn.execute(
        "SELECT display_name FROM watchlist WHERE active=1 ORDER BY LOWER(display_name)"
    ).fetchall()
    conn.close()
    names = [r["display_name"] for r in rows]
    return render_template("public/watchlist.html", names=names)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth/login.html", csrf=get_csrf_token())

    require_csrf()
    ip = request.remote_addr or "unknown"
    if rate_limited(f"login:{ip}"):
        flash("Too many attempts. Try again later.", "error")
        return render_template("auth/login.html", csrf=get_csrf_token()), 429

    codename = request.form.get("codename", "").strip()
    password = request.form.get("password", "")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE codename=%s AND active=1", (codename,)).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session["user_id"] = user["id"]
        session["csrf_token"] = secrets.token_hex(24)
        log_audit(conn, user, "LOGIN", result="SUCCESS")
        conn.close()
        return redirect(url_for("dashboard"))

    log_audit(conn, None, "LOGIN_FAILED", target=codename, result="FAILURE")
    conn.close()
    flash("Invalid codename or password.", "error")
    return render_template("auth/login.html", csrf=get_csrf_token()), 401


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    conn = get_db()
    log_audit(conn, current_user(), "LOGOUT")
    conn.close()
    session.clear()
    return redirect(url_for("landing"))


# ===========================================================================
# DASHBOARD
# ===========================================================================
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user["rank"] == "ANALYST":
        return redirect(url_for("dashboard_analyst"))
    if user["rank"] == "MANAGER":
        return redirect(url_for("dashboard_manager"))
    return redirect(url_for("dashboard_coordinator"))


@app.route("/dashboard/analyst")
@login_required
def dashboard_analyst():
    user = current_user()
    conn = get_db()
    assigned = conn.execute(
        "SELECT * FROM cases WHERE assigned_analyst_id=%s AND status='OPEN' ORDER BY updated_at DESC",
        (user["id"],),
    ).fetchall()
    priority3 = conn.execute(
        "SELECT * FROM cases WHERE classification='LEVEL3' AND status='OPEN' ORDER BY updated_at DESC"
    ).fetchall()
    my_requests = conn.execute(
        "SELECT ar.*, c.case_number, c.subject_name FROM attach_requests ar "
        "JOIN cases c ON c.id=ar.case_id WHERE ar.analyst_id=%s ORDER BY ar.requested_at DESC LIMIT 10",
        (user["id"],),
    ).fetchall()
    conn.close()
    return render_template(
        "dashboard/analyst.html", assigned=assigned, priority3=priority3, my_requests=my_requests
    )


@app.route("/dashboard/manager")
@manager_or_above
def dashboard_manager():
    conn = get_db()
    incoming = conn.execute("SELECT * FROM reports WHERE status='PENDING' ORDER BY submitted_at DESC").fetchall()
    active = conn.execute("SELECT * FROM cases WHERE status='OPEN' ORDER BY updated_at DESC LIMIT 15").fetchall()
    pending_poi = conn.execute(
        "SELECT p.*, c.case_number, c.subject_name FROM poi_records p JOIN cases c ON c.id=p.case_id "
        "WHERE p.status='PENDING' ORDER BY p.created_at DESC"
    ).fetchall()
    pending_attach = conn.execute(
        "SELECT ar.*, c.case_number, c.subject_name FROM attach_requests ar JOIN cases c ON c.id=ar.case_id "
        "WHERE ar.status='PENDING' ORDER BY ar.requested_at DESC"
    ).fetchall()
    deferred = conn.execute("SELECT * FROM reports WHERE status='POSTPONED' ORDER BY submitted_at DESC").fetchall()
    conn.close()
    return render_template(
        "dashboard/manager.html", incoming=incoming, active=active,
        pending_poi=pending_poi, pending_attach=pending_attach, deferred=deferred,
    )


@app.route("/dashboard/coordinator")
@coordinator_only
def dashboard_coordinator():
    conn = get_db()
    stats = {
        "managers": conn.execute("SELECT COUNT(*) c FROM users WHERE rank='MANAGER' AND active=1").fetchone()["c"],
        "analysts": conn.execute("SELECT COUNT(*) c FROM users WHERE rank='ANALYST' AND active=1").fetchone()["c"],
        "open_cases": conn.execute("SELECT COUNT(*) c FROM cases WHERE status='OPEN'").fetchone()["c"],
        "levelx": conn.execute("SELECT COUNT(*) c FROM cases WHERE classification='LEVELX'").fetchone()["c"],
        "deferred": conn.execute("SELECT COUNT(*) c FROM reports WHERE status='POSTPONED'").fetchone()["c"],
    }
    levelx_cases = conn.execute("SELECT * FROM cases WHERE classification='LEVELX' ORDER BY updated_at DESC").fetchall()
    deferred = conn.execute("SELECT * FROM reports WHERE status='POSTPONED' ORDER BY submitted_at DESC").fetchall()
    recent_audit = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 12").fetchall()
    conn.close()
    return render_template(
        "dashboard/coordinator.html", stats=stats, levelx_cases=levelx_cases,
        deferred=deferred, recent_audit=recent_audit,
    )


# ===========================================================================
# ANONYMOUS REPORT REVIEW QUEUE (Manager+)
# ===========================================================================
@app.route("/reports")
@manager_or_above
def reports_queue():
    conn = get_db()
    rows = conn.execute("SELECT * FROM reports WHERE status='PENDING' ORDER BY submitted_at DESC").fetchall()
    evidence_by_report = {}
    for r in rows:
        ev = conn.execute(
            "SELECT id, original_filename, uploaded_at FROM report_evidence WHERE report_id=%s ORDER BY uploaded_at",
            (r["id"],),
        ).fetchall()
        evidence_by_report[r["id"]] = ev
    conn.close()
    return render_template("cases/reports_queue.html", reports=rows, evidence_by_report=evidence_by_report)


@app.route("/reports/evidence/<int:evidence_id>")
@manager_or_above
def report_evidence_download(evidence_id):
    user = current_user()
    conn = get_db()
    ev = conn.execute("SELECT * FROM report_evidence WHERE id=%s", (evidence_id,)).fetchone()
    if not ev:
        conn.close()
        abort(404)
    rpt = conn.execute("SELECT * FROM reports WHERE id=%s", (ev["report_id"],)).fetchone()
    log_audit(conn, user, "REPORT_EVIDENCE_VIEWED", target=rpt["ref_number"] if rpt else str(ev["report_id"]))
    conn.close()

    data = storage_download("kalosafe-reports", ev["stored_path"]) if STORAGE_REMOTE else None
    if data is not None:
        return send_file(io.BytesIO(data), as_attachment=True, download_name=f"evidence-{evidence_id}")
    local_path = os.path.join(UPLOAD_REPORTS, ev["stored_path"])
    if not os.path.exists(local_path):
        abort(404)
    return send_file(local_path, as_attachment=True)


@app.route("/reports/rejected")
@manager_or_above
def reports_rejected():
    conn = get_db()
    rows = conn.execute("SELECT * FROM reports WHERE status='REJECTED' ORDER BY reviewed_at DESC").fetchall()
    conn.close()
    return render_template("cases/reports_rejected.html", reports=rows)


@app.route("/reports/<int:report_id>/accept", methods=["POST"])
@manager_or_above
def report_accept(report_id):
    require_csrf()
    user = current_user()
    classification = request.form.get("classification", "LEVEL1")
    analyst_id = request.form.get("analyst_id") or None
    if classification not in CLASS_LABELS:
        abort(400)
    conn = get_db()
    rpt = conn.execute("SELECT * FROM reports WHERE id=%s AND status='PENDING'", (report_id,)).fetchone()
    if not rpt:
        abort(404)
    case_number = gen_case_number(conn)
    conn.execute(
        "INSERT INTO cases (case_number, subject_name, discord_username, discord_id, classification, "
        "status, assigned_analyst_id, manager_id, source_report_id, created_at, updated_at) "
        "VALUES (%s,%s,%s,%s,%s, 'OPEN', %s, %s, %s, %s, %s)",
        (case_number, rpt["subject_name"], rpt["discord_username"], rpt["discord_id"], classification,
         analyst_id, user["id"], report_id, now(), now()),
    )
    case_id = conn.execute("SELECT id FROM cases WHERE case_number=%s", (case_number,)).fetchone()["id"]
    conn.execute(
        "UPDATE reports SET status='ACCEPTED', reviewed_by=%s, reviewed_at=%s, resulting_case_id=%s WHERE id=%s",
        (user["id"], now(), case_id, report_id),
    )
    conn.commit()
    log_audit(conn, user, "CASE_CREATED", case_ref=case_number, target=f"from report {rpt['ref_number']}")
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/reports/<int:report_id>/postpone", methods=["POST"])
@manager_or_above
def report_postpone(report_id):
    require_csrf()
    user = current_user()
    conn = get_db()
    conn.execute(
        "UPDATE reports SET status='POSTPONED', reviewed_by=%s, reviewed_at=%s, review_note=%s WHERE id=%s AND status='PENDING'",
        (user["id"], now(), request.form.get("note", ""), report_id),
    )
    conn.commit()
    log_audit(conn, user, "REPORT_POSTPONED", target=str(report_id))
    conn.close()
    return redirect(url_for("reports_queue"))


@app.route("/reports/<int:report_id>/reject", methods=["POST"])
@manager_or_above
def report_reject(report_id):
    require_csrf()
    user = current_user()
    conn = get_db()
    conn.execute(
        "UPDATE reports SET status='REJECTED', reviewed_by=%s, reviewed_at=%s, review_note=%s WHERE id=%s AND status='PENDING'",
        (user["id"], now(), request.form.get("note", ""), report_id),
    )
    conn.commit()
    log_audit(conn, user, "REPORT_REJECTED", target=str(report_id))
    conn.close()
    return redirect(url_for("reports_queue"))


# ===========================================================================
# CASES
# ===========================================================================
def _visible_case_row(user, case):
    """Redact a case row down to what `user` is allowed to see in a LIST."""
    base = {"id": case["id"], "case_number": case["case_number"], "classification": case["classification"],
            "status": case["status"]}
    if not can_see_case_exists(user, case):
        return None
    base["subject_name"] = case["subject_name"]
    base["can_open"] = can_open_case(user, case)
    base["is_priority3"] = case["classification"] == "LEVEL3"
    base["assigned_to_me"] = case["assigned_analyst_id"] == user["id"]
    base["unassigned"] = case["assigned_analyst_id"] is None
    return base


@app.route("/cases")
@login_required
def case_list():
    user = current_user()
    conn = get_db()
    rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
    conn.close()
    visible = [v for v in (_visible_case_row(user, r) for r in rows) if v is not None]
    return render_template("cases/list.html", cases=visible)


@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id):
    user = current_user()
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_see_case_exists(user, case):
        conn.close()
        abort(404)  # 404 not 403 — do not confirm existence of restricted cases

    if not can_open_case(user, case):
        conn.close()
        # Still allow rendering the limited "exists" card for L1-L3.
        return render_template("cases/limited.html", case=case, can_contribute=can_contribute(user, case))

    notes = conn.execute(
        "SELECT n.*, u.codename FROM case_notes n JOIN users u ON u.id=n.author_id "
        "WHERE n.case_id=%s ORDER BY n.created_at DESC", (case_id,)
    ).fetchall()
    evidence = conn.execute("SELECT e.*, u.codename FROM evidence e JOIN users u ON u.id=e.uploaded_by WHERE e.case_id=%s ORDER BY e.uploaded_at DESC", (case_id,)).fetchall()
    poi = conn.execute("SELECT * FROM poi_records WHERE case_id=%s ORDER BY created_at DESC", (case_id,)).fetchall()
    attach_reqs = conn.execute(
        "SELECT ar.*, u.codename FROM attach_requests ar JOIN users u ON u.id=ar.analyst_id WHERE ar.case_id=%s ORDER BY ar.requested_at DESC",
        (case_id,),
    ).fetchall()
    contributions = conn.execute(
        "SELECT cc.*, u.codename FROM case_contributions cc JOIN users u ON u.id=cc.author_id WHERE cc.case_id=%s ORDER BY cc.created_at DESC",
        (case_id,),
    ).fetchall() if user["rank"] in ("MANAGER", "COORDINATOR") else []
    analysts = conn.execute("SELECT id, codename FROM users WHERE rank='ANALYST' AND active=1 ORDER BY codename").fetchall()
    log_audit(conn, user, "CASE_OPENED", case_ref=case["case_number"])
    conn.close()
    return render_template(
        "cases/detail.html", case=case, notes=notes, evidence=evidence, poi=poi,
        attach_reqs=attach_reqs, contributions=contributions, analysts=analysts,
        can_original=can_access_original_evidence(user),
    )


@app.route("/cases/<int:case_id>/action", methods=["POST"])
@login_required
def case_action(case_id):
    require_csrf()
    user = current_user()
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_open_case(user, case):
        conn.close()
        abort(403)

    action = request.form.get("action")
    new_status = case["status"]
    new_class = case["classification"]
    designation = case["designation"]
    detail = action

    if action == "CONTINUE":
        pass
    elif action == "ESCALATE":
        target = request.form.get("escalate_to")
        if target not in ("MANAGER_CASE", "PERSON_OF_INTEREST", "MONITOR"):
            conn.close()
            abort(400)
        if target == "MANAGER_CASE":
            if user["rank"] == "ANALYST":
                conn.close()
                abort(403)  # only Manager+ can move a case to Manager-only handling
            new_class = "LEVELX"
        else:
            designation = target
            if new_class == "LEVEL1":
                new_class = "LEVEL2"
        detail = f"ESCALATE:{target}"
    elif action == "REPORTED":
        new_status = "REPORTED"
    elif action == "CASE_DROPPED":
        new_status = "DROPPED"
    else:
        conn.close()
        abort(400)

    conn.execute(
        "UPDATE cases SET status=%s, classification=%s, designation=%s, updated_at=%s WHERE id=%s",
        (new_status, new_class, designation, now(), case_id),
    )
    conn.commit()
    log_audit(conn, user, "CASE_STATUS_CHANGED", case_ref=case["case_number"], target=detail)
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<int:case_id>/notes", methods=["POST"])
@login_required
def case_add_note(case_id):
    require_csrf()
    user = current_user()
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_open_case(user, case):
        conn.close()
        abort(403)
    content = request.form.get("content", "").strip()
    if content:
        conn.execute(
            "INSERT INTO case_notes (case_id, author_id, content, created_at) VALUES (%s,%s,%s,%s)",
            (case_id, user["id"], content, now()),
        )
        conn.commit()
        log_audit(conn, user, "CASE_NOTE_ADDED", case_ref=case["case_number"])
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/cases/<int:case_id>/contribute", methods=["POST"])
@login_required
def case_contribute(case_id):
    """Unassigned analysts adding info to L2/L3 cases without gaining read access."""
    require_csrf()
    user = current_user()
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_see_case_exists(user, case) or not can_contribute(user, case):
        conn.close()
        abort(403)
    content = request.form.get("content", "").strip()
    if content:
        conn.execute(
            "INSERT INTO case_contributions (case_id, author_id, content, created_at) VALUES (%s,%s,%s,%s)",
            (case_id, user["id"], content, now()),
        )
        conn.commit()
        log_audit(conn, user, "CASE_CONTRIBUTION_ADDED", case_ref=case["case_number"])
    conn.close()
    return redirect(url_for("case_list"))


@app.route("/cases/<int:case_id>/attach-request", methods=["POST"])
@login_required
def attach_request(case_id):
    require_csrf()
    user = current_user()
    if user["rank"] != "ANALYST":
        abort(403)
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_see_case_exists(user, case):
        conn.close()
        abort(404)
    existing = conn.execute(
        "SELECT id FROM attach_requests WHERE case_id=%s AND analyst_id=%s AND status='PENDING'", (case_id, user["id"])
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO attach_requests (case_id, analyst_id, status, requested_at) VALUES (%s,%s, 'PENDING', %s)",
            (case_id, user["id"], now()),
        )
        conn.commit()
        log_audit(conn, user, "ATTACH_REQUESTED", case_ref=case["case_number"])
    conn.close()
    return redirect(url_for("case_list"))


@app.route("/attach-requests/<int:req_id>/decide", methods=["POST"])
@manager_or_above
def attach_decide(req_id):
    require_csrf()
    user = current_user()
    decision = request.form.get("decision")
    conn = get_db()
    ar = conn.execute("SELECT * FROM attach_requests WHERE id=%s AND status='PENDING'", (req_id,)).fetchone()
    if not ar:
        conn.close()
        abort(404)
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (ar["case_id"],)).fetchone()
    if decision == "APPROVE":
        conn.execute("UPDATE cases SET assigned_analyst_id=%s, updated_at=%s WHERE id=%s", (ar["analyst_id"], now(), case["id"]))
        conn.execute("UPDATE attach_requests SET status='APPROVED', decided_by=%s, decided_at=%s WHERE id=%s", (user["id"], now(), req_id))
    elif decision == "DENY":
        conn.execute("UPDATE attach_requests SET status='DENIED', decided_by=%s, decided_at=%s WHERE id=%s", (user["id"], now(), req_id))
    else:
        conn.close()
        abort(400)
    conn.commit()
    log_audit(conn, user, "ATTACH_REQUEST_DECIDED", case_ref=case["case_number"], target=decision)
    conn.close()
    return redirect(url_for("dashboard_manager"))


# ---------------------------------------------------------------------------
# Person of Interest workflow
# ---------------------------------------------------------------------------
@app.route("/cases/<int:case_id>/poi", methods=["POST"])
@login_required
def poi_recommend(case_id):
    require_csrf()
    user = current_user()
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_open_case(user, case):
        conn.close()
        abort(403)
    reason = request.form.get("reason", "").strip()
    designation = request.form.get("designation")
    if designation not in ("PERSON_OF_INTEREST", "MONITOR", "EXTREME_POI") or not reason:
        conn.close()
        abort(400)
    conn.execute(
        "INSERT INTO poi_records (case_id, recommended_by, reason, requested_designation, status, created_at) "
        "VALUES (%s,%s,%s,%s, 'PENDING', %s)",
        (case_id, user["id"], reason, designation, now()),
    )
    conn.commit()
    log_audit(conn, user, "POI_PROPOSED", case_ref=case["case_number"], target=designation)
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/poi/<int:poi_id>/decide", methods=["POST"])
@manager_or_above
def poi_decide(poi_id):
    require_csrf()
    user = current_user()
    decision = request.form.get("decision")
    note = request.form.get("note", "")
    conn = get_db()
    poi = conn.execute("SELECT * FROM poi_records WHERE id=%s AND status='PENDING'", (poi_id,)).fetchone()
    if not poi:
        conn.close()
        abort(404)
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (poi["case_id"],)).fetchone()

    # An Analyst cannot approve their own recommendation — enforced structurally:
    # only Manager+ may hit this route at all (see decorator), and Managers
    # additionally may not decide a PoI they personally recommended.
    if poi["recommended_by"] == user["id"]:
        conn.close()
        abort(403)

    if decision == "APPROVE":
        conn.execute(
            "UPDATE poi_records SET status='APPROVED', decided_by=%s, decided_at=%s, decision_note=%s WHERE id=%s",
            (user["id"], now(), note, poi_id),
        )
        new_class = case["classification"]
        if poi["requested_designation"] == "EXTREME_POI":
            new_class = "LEVEL3"
        elif case["classification"] == "LEVEL1":
            new_class = "LEVEL2"
        conn.execute(
            "UPDATE cases SET designation=%s, classification=%s, updated_at=%s WHERE id=%s",
            (poi["requested_designation"], new_class, now(), case["id"]),
        )
        log_audit(conn, user, "POI_APPROVED", case_ref=case["case_number"], target=poi["requested_designation"])
    elif decision == "REJECT":
        conn.execute(
            "UPDATE poi_records SET status='REJECTED', decided_by=%s, decided_at=%s, decision_note=%s WHERE id=%s",
            (user["id"], now(), note, poi_id),
        )
        log_audit(conn, user, "POI_REJECTED", case_ref=case["case_number"])
    else:
        conn.close()
        abort(400)
    conn.commit()
    conn.close()
    return redirect(url_for("case_detail", case_id=case["id"]))


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
@app.route("/cases/<int:case_id>/evidence", methods=["POST"])
@login_required
def evidence_upload(case_id):
    require_csrf()
    user = current_user()
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_contribute(user, case):
        conn.close()
        abort(403)

    f = request.files.get("file")
    if not f or not f.filename or not allowed_file(f.filename):
        conn.close()
        flash("Unsupported or missing file.", "error")
        return redirect(url_for("case_detail", case_id=case_id))

    ext = f.filename.rsplit(".", 1)[1].lower()
    stored_name = f"{uuid.uuid4().hex}.{ext}"
    original_path = os.path.join(UPLOAD_ORIGINAL, stored_name)
    f.save(original_path)  # always written locally first — needed for watermarking either way

    watermarked_path = None
    wm_full_path = None
    if ext in ("png", "jpg", "jpeg"):
        wm_name = f"{uuid.uuid4().hex}.jpg"
        wm_full_path = os.path.join(UPLOAD_WATERMARK, wm_name)
        try:
            make_watermarked_copy(original_path, wm_full_path, case["case_number"], user["codename"])
            watermarked_path = wm_name
        except Exception:
            watermarked_path = None
            wm_full_path = None

    if STORAGE_REMOTE:
        with open(original_path, "rb") as fh:
            storage_upload("kalosafe-originals", stored_name, fh.read(), f.mimetype or "application/octet-stream")
        if wm_full_path:
            with open(wm_full_path, "rb") as fh:
                storage_upload("kalosafe-watermarked", watermarked_path, fh.read(), "image/jpeg")
        # Local copies were only needed to reach Supabase Storage — clear them
        # so they don't linger on Render's ephemeral disk between requests.
        for p in (original_path, wm_full_path):
            if p:
                try:
                    os.remove(p)
                except OSError:
                    pass

    conn.execute(
        "INSERT INTO evidence (case_id, uploaded_by, original_path, watermarked_path, original_filename, content_type, uploaded_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (case_id, user["id"], stored_name, watermarked_path, secure_filename(f.filename), f.mimetype, now()),
    )
    conn.commit()
    log_audit(conn, user, "EVIDENCE_UPLOADED", case_ref=case["case_number"])
    conn.close()
    return redirect(url_for("case_detail", case_id=case_id) if can_open_case(user, case) else url_for("case_list"))


@app.route("/evidence/<int:evidence_id>/original")
@login_required
def evidence_original(evidence_id):
    user = current_user()
    conn = get_db()
    ev = conn.execute("SELECT * FROM evidence WHERE id=%s", (evidence_id,)).fetchone()
    if not ev:
        conn.close()
        abort(404)
    if not can_access_original_evidence(user):
        log_audit(conn, user, "EVIDENCE_ACCESS_DENIED", target=f"evidence#{evidence_id}", result="DENIED")
        conn.close()
        abort(403)
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (ev["case_id"],)).fetchone()
    log_audit(conn, user, "EVIDENCE_ORIGINAL_DOWNLOADED", case_ref=case["case_number"], target=str(evidence_id))
    conn.close()

    data = storage_download("kalosafe-originals", ev["original_path"]) if STORAGE_REMOTE else None
    if data is not None:
        return send_file(io.BytesIO(data), as_attachment=True, download_name=ev["original_filename"])
    local_path = os.path.join(UPLOAD_ORIGINAL, ev["original_path"])
    if not os.path.exists(local_path):
        abort(404)
    return send_file(local_path, as_attachment=True, download_name=ev["original_filename"])


@app.route("/evidence/<int:evidence_id>/watermarked")
@login_required
def evidence_watermarked(evidence_id):
    user = current_user()
    conn = get_db()
    ev = conn.execute("SELECT * FROM evidence WHERE id=%s", (evidence_id,)).fetchone()
    if not ev:
        conn.close()
        abort(404)
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (ev["case_id"],)).fetchone()
    if not can_open_case(user, case) and ev["uploaded_by"] != user["id"]:
        log_audit(conn, user, "EVIDENCE_ACCESS_DENIED", target=f"evidence#{evidence_id}", result="DENIED")
        conn.close()
        abort(403)
    if not ev["watermarked_path"]:
        conn.close()
        abort(404)
    log_audit(conn, user, "EVIDENCE_VIEWED", case_ref=case["case_number"], target=str(evidence_id))
    conn.close()

    data = storage_download("kalosafe-watermarked", ev["watermarked_path"]) if STORAGE_REMOTE else None
    if data is not None:
        return send_file(io.BytesIO(data), mimetype="image/jpeg")
    local_path = os.path.join(UPLOAD_WATERMARK, ev["watermarked_path"])
    if not os.path.exists(local_path):
        abort(404)
    return send_file(local_path)


# ===========================================================================
# SEARCH — always filtered through the same permission functions as /cases
# ===========================================================================
@app.route("/search")
@login_required
def search():
    user = current_user()
    q = request.args.get("q", "").strip()
    results = []
    if q:
        conn = get_db()
        like = f"%{q}%"
        rows = conn.execute(
            "SELECT * FROM cases WHERE case_number LIKE %s OR subject_name LIKE %s OR discord_username LIKE %s "
            "OR discord_id LIKE %s OR classification LIKE %s OR status LIKE %s ORDER BY updated_at DESC",
            (like, like, like, like, like, like),
        ).fetchall()
        conn.close()
        results = [v for v in (_visible_case_row(user, r) for r in rows) if v is not None]
    return render_template("cases/search.html", q=q, results=results)


# ===========================================================================
# PERSONNEL / ACCOUNT CREATION
# ===========================================================================
CODENAME_PREFIX = {"ANALYST": "A", "MANAGER": "M"}


@app.route("/personnel/analysts", methods=["GET", "POST"])
@manager_or_above
def create_analyst():
    user = current_user()
    conn = get_db()
    if request.method == "GET":
        analysts = conn.execute("SELECT id, codename, active FROM users WHERE rank='ANALYST' ORDER BY codename").fetchall()
        conn.close()
        return render_template("personnel/create_analyst.html", analysts=analysts)

    require_csrf()
    codename = request.form.get("codename", "").strip()
    password = request.form.get("password", "")
    if not codename.startswith("A") or len(codename) < 3:
        flash("Analyst codenames must begin with 'A'.", "error")
        conn.close()
        return redirect(url_for("create_analyst"))
    if len(password) < 10:
        flash("Password must be at least 10 characters.", "error")
        conn.close()
        return redirect(url_for("create_analyst"))
    existing = conn.execute("SELECT id FROM users WHERE codename=%s AND active=1", (codename,)).fetchone()
    if existing:
        flash("That codename is already active.", "error")
        conn.close()
        return redirect(url_for("create_analyst"))

    conn.execute(
        "INSERT INTO users (codename, rank, password_hash, active, created_by, created_at) VALUES (%s, 'ANALYST', %s, 1, %s, %s)",
        (codename, generate_password_hash(password), user["id"], now()),
    )
    conn.commit()
    log_audit(conn, user, "ACCOUNT_CREATED", target=f"ANALYST:{codename}")
    conn.close()
    flash(f"Analyst account '{codename}' created. Communicate credentials to them securely and out-of-band.", "success")
    return redirect(url_for("create_analyst"))


@app.route("/personnel/managers", methods=["GET", "POST"])
@coordinator_only
def create_manager():
    user = current_user()
    conn = get_db()
    if request.method == "GET":
        managers = conn.execute("SELECT id, codename, active FROM users WHERE rank='MANAGER' ORDER BY codename").fetchall()
        conn.close()
        return render_template("personnel/create_manager.html", managers=managers)

    require_csrf()
    codename = request.form.get("codename", "").strip()
    password = request.form.get("password", "")
    if not codename.startswith("M") or len(codename) < 3:
        flash("Manager codenames must begin with 'M'.", "error")
        conn.close()
        return redirect(url_for("create_manager"))
    if len(password) < 10:
        flash("Password must be at least 10 characters.", "error")
        conn.close()
        return redirect(url_for("create_manager"))
    existing = conn.execute("SELECT id FROM users WHERE codename=%s AND active=1", (codename,)).fetchone()
    if existing:
        flash("That codename is already active.", "error")
        conn.close()
        return redirect(url_for("create_manager"))

    conn.execute(
        "INSERT INTO users (codename, rank, password_hash, active, created_by, created_at) VALUES (%s, 'MANAGER', %s, 1, %s, %s)",
        (codename, generate_password_hash(password), user["id"], now()),
    )
    conn.commit()
    log_audit(conn, user, "ACCOUNT_CREATED", target=f"MANAGER:{codename}")
    conn.close()
    flash(f"Manager account '{codename}' created.", "success")
    return redirect(url_for("create_manager"))


@app.route("/personnel/<int:user_id>/disable", methods=["POST"])
@manager_or_above
def disable_account(user_id):
    require_csrf()
    user = current_user()
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=%s", (user_id,)).fetchone()
    if not target:
        conn.close()
        abort(404)
    # Managers may only disable Analysts; Coordinator may disable Managers too.
    if user["rank"] == "MANAGER" and target["rank"] != "ANALYST":
        conn.close()
        abort(403)
    if target["rank"] == "COORDINATOR":
        conn.close()
        abort(403)
    conn.execute("UPDATE users SET active=0 WHERE id=%s", (user_id,))
    conn.commit()
    log_audit(conn, user, "ACCOUNT_DISABLED", target=target["codename"])
    conn.close()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/personnel")
@coordinator_only
def personnel_directory():
    conn = get_db()
    rows = conn.execute("SELECT id, codename, rank, active, real_identity, created_at FROM users ORDER BY rank, codename").fetchall()
    conn.close()
    return render_template("personnel/directory.html", users=rows)


@app.route("/personnel/<int:user_id>/identity", methods=["POST"])
@coordinator_only
def set_identity(user_id):
    require_csrf()
    user = current_user()
    real_identity = request.form.get("real_identity", "").strip()
    conn = get_db()
    conn.execute("UPDATE users SET real_identity=%s WHERE id=%s", (real_identity or None, user_id))
    conn.commit()
    log_audit(conn, user, "PERSONNEL_IDENTITY_UPDATED", target=f"user#{user_id}")
    conn.close()
    return redirect(url_for("personnel_directory"))


# ===========================================================================
# WATCHLIST MANAGEMENT (Manager+)
# ===========================================================================
@app.route("/watchlist/manage", methods=["GET", "POST"])
@manager_or_above
def watchlist_manage():
    user = current_user()
    conn = get_db()
    if request.method == "POST":
        require_csrf()
        action = request.form.get("form_action")
        if action == "add":
            name = request.form.get("display_name", "").strip()
            if name:
                conn.execute(
                    "INSERT INTO watchlist (display_name, case_id, added_by, added_at, active) VALUES (%s,%s,%s,%s,1)",
                    (name, request.form.get("case_id") or None, user["id"], now()),
                )
                conn.commit()
                log_audit(conn, user, "WATCHLIST_CHANGED", target=f"ADD:{name}")
        elif action == "remove":
            wid = request.form.get("watchlist_id")
            entry = conn.execute("SELECT * FROM watchlist WHERE id=%s", (wid,)).fetchone()
            conn.execute("UPDATE watchlist SET active=0 WHERE id=%s", (wid,))
            conn.commit()
            if entry:
                log_audit(conn, user, "WATCHLIST_CHANGED", target=f"REMOVE:{entry['display_name']}")
    entries = conn.execute("SELECT * FROM watchlist WHERE active=1 ORDER BY added_at DESC").fetchall()
    approved_poi = conn.execute(
        "SELECT c.id, c.case_number, c.subject_name FROM cases c "
        "WHERE c.designation IS NOT NULL ORDER BY c.updated_at DESC"
    ).fetchall()
    conn.close()
    return render_template("personnel/watchlist_manage.html", entries=entries, approved_poi=approved_poi)


# ===========================================================================
# MESSAGING
# ===========================================================================
@app.route("/messages")
@login_required
def messages_hub():
    user = current_user()
    conn = get_db()
    others = conn.execute("SELECT id, codename, rank FROM users WHERE id != %s AND active=1 ORDER BY rank, codename", (user["id"],)).fetchall()
    my_cases = conn.execute(
        "SELECT id, case_number, subject_name FROM cases WHERE assigned_analyst_id=%s OR manager_id=%s OR %s IN ('MANAGER','COORDINATOR') ORDER BY updated_at DESC LIMIT 25",
        (user["id"], user["id"], user["rank"]),
    ).fetchall() if user["rank"] != "ANALYST" else conn.execute(
        "SELECT id, case_number, subject_name FROM cases WHERE assigned_analyst_id=%s ORDER BY updated_at DESC", (user["id"],)
    ).fetchall()
    conn.close()
    return render_template("messages/hub.html", others=others, my_cases=my_cases)


@app.route("/messages/global", methods=["GET", "POST"])
@login_required
def messages_global():
    user = current_user()
    conn = get_db()
    if request.method == "POST":
        require_csrf()
        content = request.form.get("content", "").strip()
        if content:
            conn.execute(
                "INSERT INTO messages (channel_type, sender_id, content, created_at) VALUES ('GLOBAL', %s, %s, %s)",
                (user["id"], content, now()),
            )
            conn.commit()
            log_audit(conn, user, "MESSAGE_SENT", target="GLOBAL")
    rows = conn.execute(
        "SELECT m.*, u.codename, u.rank FROM messages m JOIN users u ON u.id=m.sender_id "
        "WHERE m.channel_type='GLOBAL' ORDER BY m.created_at DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return render_template("messages/global.html", messages=rows)


@app.route("/messages/private/<int:other_id>", methods=["GET", "POST"])
@login_required
def messages_private(other_id):
    user = current_user()
    conn = get_db()
    other = conn.execute("SELECT * FROM users WHERE id=%s AND active=1", (other_id,)).fetchone()
    if not other:
        conn.close()
        abort(404)
    if request.method == "POST":
        require_csrf()
        content = request.form.get("content", "").strip()
        if content:
            conn.execute(
                "INSERT INTO messages (channel_type, sender_id, recipient_id, content, created_at) VALUES ('PRIVATE', %s, %s, %s, %s)",
                (user["id"], other_id, content, now()),
            )
            conn.commit()
            log_audit(conn, user, "MESSAGE_SENT", target=f"PRIVATE:{other['codename']}")
    rows = conn.execute(
        "SELECT m.*, u.codename FROM messages m JOIN users u ON u.id=m.sender_id "
        "WHERE m.channel_type='PRIVATE' AND ((m.sender_id=%s AND m.recipient_id=%s) OR (m.sender_id=%s AND m.recipient_id=%s)) "
        "ORDER BY m.created_at ASC",
        (user["id"], other_id, other_id, user["id"]),
    ).fetchall()
    conn.close()
    return render_template("messages/private.html", messages=rows, other=other)


@app.route("/cases/<int:case_id>/chat", methods=["GET", "POST"])
@login_required
def case_chat(case_id):
    user = current_user()
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id=%s", (case_id,)).fetchone()
    if not case or not can_open_case(user, case):
        conn.close()
        abort(403)
    if request.method == "POST":
        require_csrf()
        content = request.form.get("content", "").strip()
        if content:
            conn.execute(
                "INSERT INTO messages (channel_type, case_id, sender_id, content, created_at) VALUES ('CASE', %s, %s, %s, %s)",
                (case_id, user["id"], content, now()),
            )
            conn.commit()
            log_audit(conn, user, "MESSAGE_SENT", case_ref=case["case_number"], target="CASE_CHAT")
    rows = conn.execute(
        "SELECT m.*, u.codename FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.channel_type='CASE' AND m.case_id=%s ORDER BY m.created_at ASC",
        (case_id,),
    ).fetchall()
    conn.close()
    return render_template("messages/case_chat.html", messages=rows, case=case)


# ===========================================================================
# AUDIT LOG (Coordinator)
# ===========================================================================
@app.route("/audit")
@coordinator_only
def audit_log_view():
    conn = get_db()
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    codename = request.args.get("codename", "").strip()
    action = request.args.get("action", "").strip()
    case_ref = request.args.get("case_ref", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    if codename:
        query += " AND user_codename LIKE %s"
        params.append(f"%{codename}%")
    if action:
        query += " AND action LIKE %s"
        params.append(f"%{action}%")
    if case_ref:
        query += " AND case_ref LIKE %s"
        params.append(f"%{case_ref}%")
    if date_from:
        query += " AND ts >= %s"
        params.append(date_from)
    if date_to:
        query += " AND ts <= %s"
        params.append(date_to + "T23:59:59Z")
    query += " ORDER BY id DESC LIMIT 500"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return render_template(
        "dashboard/audit.html", rows=rows, filters=dict(
            codename=codename, action=action, case_ref=case_ref, date_from=date_from, date_to=date_to
        )
    )


# NOTE: there is intentionally no route anywhere in this application that
# updates or deletes rows in audit_log. This is what "immutable" means in
# practice here (see README's documented limitations for what a production
# deployment should add on top, e.g. write-once storage / hash chaining).


if __name__ == "__main__":
    init_db()
    # host="0.0.0.0" + the PORT env var (set automatically by hosts like
    # Replit/Render) lets this run unchanged locally OR in the cloud.
    port = int(os.environ.get("PORT", 5055))
    app.run(host="0.0.0.0", port=port, debug=False)
