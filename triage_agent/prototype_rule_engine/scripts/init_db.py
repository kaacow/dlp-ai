#!/usr/bin/env python3
"""Create the dlp_ai SQLite DB (if missing) and seed/refresh employees from EMP."""
import sqlite3
from pathlib import Path

import emp_sql as k

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"
SCHEMA_PATH = Path(__file__).parent.parent / "db" / "schema.sql"


def init_schema(conn):
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()


def seed_employees(conn):
    sess = k.get_session()
    cols, rows, _ = k.run_sql(
        sess,
        "SELECT id, user_domain, user_name, fio, department FROM tuserinfo;",
    )
    cur = conn.cursor()
    n = 0
    for row in rows:
        rec = dict(zip(cols, row))
        cur.execute(
            """INSERT INTO employees (user_locator, user_domain, user_name, full_name, department, synced_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(user_locator) DO UPDATE SET
                 user_domain=excluded.user_domain,
                 user_name=excluded.user_name,
                 full_name=excluded.full_name,
                 department=excluded.department,
                 synced_at=excluded.synced_at;""",
            (rec["id"], rec["user_domain"], rec["user_name"], rec["fio"], rec["department"]),
        )
        n += 1
    conn.commit()
    return n


if __name__ == "__main__":
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    init_schema(conn)
    n = seed_employees(conn)
    print(f"DB ready at {DB_PATH}")
    print(f"Seeded/refreshed {n} employees from tuserinfo")
    conn.close()
