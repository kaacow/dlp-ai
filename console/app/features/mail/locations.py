"""Wraps `action=getlocs`, confirmed live to return a `users` array with
`user_name`, `fio` (full name), `department`, `ids` — used to populate the
custom-range page's employee selector."""
from . import emp_sql as k


def list_users(session):
    resp = session.get(f"{k.BASE}/cgi-report.exe", params={"action": "getlocs"})
    resp.raise_for_status()
    data = resp.json()
    users = data.get("response", {}).get("users", [])
    return [
        {
            "location_id": (u.get("ids") or [""])[0],
            "username": u.get("user_name", ""),
            "fullname": u.get("fio", ""),
            "department": u.get("department", ""),
        }
        for u in users
    ]
