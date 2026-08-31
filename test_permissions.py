"""
KALOSAFE — permission boundary test suite.
Run against the local dev server: python3 test_permissions.py
Requires the seeded demo data (python3 seed.py) and a running server
(python3 app.py) on http://127.0.0.1:5055.
"""
import re
import sys
import requests

BASE = "http://127.0.0.1:5055"
results = []


def check(label, condition):
    results.append((label, condition))
    print(("PASS  " if condition else "FAIL  ") + label)


def get_csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else None


def login(codename, password):
    s = requests.Session()
    r = s.get(f"{BASE}/login")
    token = get_csrf(r.text)
    s.post(f"{BASE}/login", data={"csrf_token": token, "codename": codename, "password": password})
    return s


# Known IDs from seed.py: CASE-0001 (L1, Amber), CASE-0003 (L3, Atlas),
# CASE-0004 (LEVELX). We resolve numeric IDs via the Coordinator session.
coord = login("Crown", "CoordinatorDemo123!")
manager = login("Moonlight", "ManagerDemo123!")
manager2 = login("Meridian", "ManagerDemo123!")
amber = login("Amber", "AnalystDemo123!")   # assigned to CASE-0001
aster = login("Aster", "AnalystDemo123!")   # assigned to CASE-0002
anon = requests.Session()

# Discover case IDs (as coordinator, who can see everything)
case_html = coord.get(f"{BASE}/cases").text
# Map case_number -> id by hitting /cases/<n> sequentially 1..6
case_ids = {}
for i in range(1, 8):
    r = coord.get(f"{BASE}/cases/{i}")
    m = re.search(r"CASE-(\d{4})", r.text)
    if m:
        case_ids[f"CASE-{m.group(1)}"] = i

id_l1_assigned_amber = case_ids.get("CASE-0001")
id_l3 = case_ids.get("CASE-0003")
id_levelx = case_ids.get("CASE-0004")
id_l1_unassigned = case_ids.get("CASE-0005")

# 1. Unauthenticated visitor cannot access internal information
r = anon.get(f"{BASE}/cases", allow_redirects=False)
check("1. Anon /cases redirects to login (no data)", r.status_code in (302, 401, 403))
r2 = anon.get(f"{BASE}/audit", allow_redirects=False)
check("1b. Anon /audit blocked", r2.status_code in (302, 401, 403))

# 2. Analyst cannot access an unassigned case (limited view only, no notes/evidence)
r = amber.get(f"{BASE}/cases/{id_l1_unassigned}")
check("2. Analyst on unassigned L1 case gets limited view (no 'Internal Notes' panel)",
      r.status_code == 200 and "Internal Notes" not in r.text)

# 3. Analyst cannot access Level X
r = amber.get(f"{BASE}/cases/{id_levelx}")
check("3. Analyst -> Level X case returns 404 (existence hidden)", r.status_code == 404)

# 4. Analyst cannot access original evidence
# Upload evidence as Amber to her assigned case first.
detail = amber.get(f"{BASE}/cases/{id_l1_assigned_amber}").text
token = get_csrf(detail)
files = {"file": ("demo.png", b"\x89PNG\r\n\x1a\n" + b"0" * 100, "image/png")}
amber.post(f"{BASE}/cases/{id_l1_assigned_amber}/evidence", data={"csrf_token": token}, files=files)
ev_match = re.search(r"/evidence/(\d+)/original", amber.get(f"{BASE}/cases/{id_l1_assigned_amber}").text)
evidence_id = ev_match.group(1) if ev_match else "1"
r = amber.get(f"{BASE}/evidence/{evidence_id}/original")
check("4. Analyst denied original evidence (403)", r.status_code == 403)
r2 = manager.get(f"{BASE}/evidence/{evidence_id}/original")
check("4b. Manager CAN access original evidence", r2.status_code == 200)

# 5. Analyst cannot access Coordinator-only identity information
r = amber.get(f"{BASE}/personnel", allow_redirects=False)
check("5. Analyst -> /personnel blocked (403/redirect)", r.status_code in (302, 403))

# 6. Manager cannot access Coordinator-only identity information
r = manager.get(f"{BASE}/personnel", allow_redirects=False)
check("6. Manager -> /personnel blocked (403/redirect)", r.status_code in (302, 403))

# 7. Manager cannot create another Manager
csrf_html = manager.get(f"{BASE}/dashboard/manager").text
token = get_csrf(csrf_html)
r = manager.post(f"{BASE}/personnel/managers", data={"csrf_token": token, "codename": "Mallory", "password": "TryHarder123!"})
check("7. Manager -> POST /personnel/managers blocked (403/redirect, not 200-with-success)", r.status_code in (302, 403))

# 8. Analyst cannot approve their own PoI designation
detail = amber.get(f"{BASE}/cases/{id_l1_assigned_amber}").text
token = get_csrf(detail)
amber.post(f"{BASE}/cases/{id_l1_assigned_amber}/poi", data={
    "csrf_token": token, "designation": "PERSON_OF_INTEREST", "reason": "Self-test recommendation"
})
# find poi id (via coordinator view, since the decide buttons — and hence
# the id — are only rendered for Manager+; the id itself is not secret,
# only the ability to act on it matters)
poi_match = re.findall(r"/poi/(\d+)/decide", coord.get(f"{BASE}/cases/{id_l1_assigned_amber}").text)
poi_id = poi_match[-1] if poi_match else None
analyst_decide_attempt = None
if poi_id:
    analyst_decide_attempt = amber.post(f"{BASE}/poi/{poi_id}/decide", data={"csrf_token": token, "decision": "APPROVE"})
check("8. Analyst has no route to decide PoI at all (403/redirect)",
      analyst_decide_attempt is not None and analyst_decide_attempt.status_code in (302, 403))

# 9. Restricted cases cannot be accessed by manipulating URLs/API requests
r = amber.get(f"{BASE}/evidence/{evidence_id}/original")
check("9. Direct evidence URL manipulation still blocked for Analyst", r.status_code == 403)
r2 = amber.get(f"{BASE}/cases/{id_levelx}/action", allow_redirects=False)
# GET not even defined for /action (POST only) -> should 405, not leak data
r3 = amber.post(f"{BASE}/cases/{id_levelx}/action", data={"csrf_token": token, "action": "CONTINUE"})
check("9b. Analyst POST action on Level X case blocked (403/404)", r3.status_code in (403, 404))

# 10. Audit logs cannot be edited/deleted by ordinary users -- structural:
# confirm there is no route registered for mutating audit_log.
import app as kalosafe_app
audit_mutation_routes = [
    rule for rule in kalosafe_app.app.url_map.iter_rules()
    if "audit" in rule.rule and any(m in rule.methods for m in ("POST", "PUT", "DELETE", "PATCH"))
]
check("10. No POST/PUT/DELETE/PATCH route exists for /audit (immutable)", len(audit_mutation_routes) == 0)

print("\n----------------------------------------")
passed = sum(1 for _, ok in results if ok)
print(f"{passed}/{len(results)} checks passed")
if passed != len(results):
    sys.exit(1)
