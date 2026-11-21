"""Session for the content-fetch pipeline (ReportId=215 fetch + `getfile` download).

Originally used a deliberately narrow svc_readonly account (scoped to exactly one test
employee, user_locator=1001) for this pipeline's build/test phase. Switched to
svc_reports on 2026-08-24 — the same broad-scope account `emp_sql.py` already uses
for everything else in this app, confirmed to already have report-215 access
org-wide (this is literally the account that answered a live "how much content is
available org-wide" query across all employees before this switch was made — no
EMP-side permission change was needed).

svc_readonly's credentials (`.env.svc_readonly`) are no longer read by this module — nothing
else in this app currently depends on them (`screenshots.py`'s docstring claims an
svc_readonly dependency but its actual code imports `emp_sql`/svc_reports too; that
docstring is stale, not something this change touches).

Kept as its own module (rather than having callers import emp_sql.py directly) so
report_filesend.py/file_fetch.py/content_evidence.py/content_scan.py didn't need
any changes — they all call `content_emp.get_session()` / `content_emp.BASE`
exactly as before.
"""
from emp_sql import BASE, get_session  # noqa: F401 — re-exported for content_* modules
