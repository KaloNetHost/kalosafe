"""
KALOSAFE — file storage layer (Supabase Storage edition).

Evidence files (original uploads + watermarked analyst copies) and
anonymous-report attachments were originally saved to local disk under
uploads/. That's wiped on every restart on free hosting tiers — the
same problem the SQLite database had. This module instead stores those
file bytes in Supabase Storage buckets, over Supabase's HTTP API, using
the SAME free Supabase project already holding the database.

Required environment variables (set alongside DATABASE_URL) to enable
remote storage:
  SUPABASE_URL          e.g. https://xxxxxxxx.supabase.co
  SUPABASE_SERVICE_KEY  Project Settings -> API -> service_role secret key

If those aren't set, REMOTE_ENABLED is False and app.py falls back to
local disk (handy for quick local testing) — but on a real deployment
you want them set, or evidence files will still be lost on restart even
though case records now survive via Postgres.

The service_role key bypasses Supabase's row-level-security policies,
which is what we want: KaloSafe's own permission checks (auth.py) are
the real gatekeeper, and the app is the ONLY thing that ever talks to
these buckets directly — evidence is always served back to the browser
through KaloSafe's own authenticated routes, never as a direct Supabase
Storage link. This key is a secret: it must only ever live in Render's
environment variables, never in code, never sent to the browser.

Create these THREE private buckets once in the Supabase dashboard
(Storage -> New bucket -> leave "Public bucket" OFF for each):
  kalosafe-originals
  kalosafe-watermarked
  kalosafe-reports
"""
import os
import requests

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
REMOTE_ENABLED = bool(SUPABASE_URL and SUPABASE_SERVICE_KEY)


def _headers(content_type=None):
    h = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "apikey": SUPABASE_SERVICE_KEY,
    }
    if content_type:
        h["Content-Type"] = content_type
    return h


def upload(bucket, path, data: bytes, content_type="application/octet-stream"):
    """Upload bytes to a Supabase Storage bucket. Returns True on success."""
    if not REMOTE_ENABLED:
        return False
    url = f"{SUPABASE_URL}/storage/v1/object/{bucket}/{path}"
    try:
        resp = requests.post(
            url, headers={**_headers(content_type), "x-upsert": "true"}, data=data, timeout=30
        )
        return resp.status_code in (200, 201)
    except requests.RequestException:
        return False


def download(bucket, path):
    """Return the file's bytes from Supabase Storage, or None if unavailable/not found."""
    if not REMOTE_ENABLED:
        return None
    url = f"{SUPABASE_URL}/storage/v1/object/{bucket}/{path}"
    try:
        resp = requests.get(url, headers=_headers(), timeout=30)
        if resp.status_code == 200:
            return resp.content
    except requests.RequestException:
        pass
    return None
