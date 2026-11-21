"""Global Search: nightly + on-demand check that the username typed into bi01 belongs to the person typing it.
Routes under /api/gsearch/* sit behind the console auth; only /runs/auto (cron) is public (see main.py)."""
import re
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import analyze, fetch, runner, store

router = APIRouter(prefix="/api/gsearch", tags=["gsearch"])


def init_db():
    store.init_db()


def _admin(request: Request):
    if request.state.user["role"] != "admin":
        raise HTTPException(403, "admin access required")


@router.get("/config")
def config():
    c = store.conn()
    try:
        last = c.execute("SELECT id,status,started,finished,t_from,new_events,alerts,error FROM gs_runs WHERE kind='auto' ORDER BY id DESC LIMIT 1").fetchone()
        new = c.execute("SELECT COUNT(*) FROM gs_events WHERE status='new' AND verdict='alert'").fetchone()[0]
        n = c.execute("SELECT COUNT(DISTINCT bi01_user) FROM gs_watch").fetchone()[0]
    finally:
        c.close()
    return {"watch_count": n, "target": fetch.TARGET, "night_time": runner.NIGHT_HOUR, "last_auto": dict(last) if last else None,
            "open_alerts": new, "busy": runner.LOCK.locked()}


# ---- bi01 username list
@router.get("/watch")
def get_watch():
    return {"entries": [{"bi01": a, "win": b} for a, b in store.load_watch()]}


class WatchBody(BaseModel):
    text: str
    mode: str = "replace"          # replace | append


@router.put("/watch")
def put_watch(body: WatchBody, request: Request):
    _admin(request)
    entries, bad = analyze.parse_list(body.text)
    if not entries:
        raise HTTPException(400, "No usernames found. One per line, optionally 'bi01name=windowsname'." + (" Rejected: " + "; ".join(bad[:5]) if bad else ""))
    total = store.save_watch(entries, body.mode != "append")
    return {"saved": len(entries), "total": total, "rejected": bad[:10]}


# ---- runs
class RunBody(BaseModel):
    t_from: str
    t_to: str
    users: str = ""


def _dt(s):
    for f in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s.strip(), f)
        except ValueError:
            pass
    raise HTTPException(400, f"Bad date/time '{s}'")


@router.post("/runs")
def manual_run(body: RunBody, request: Request):
    t0, t1 = _dt(body.t_from).replace(second=0), _dt(body.t_to).replace(second=0)
    if t1 <= t0:
        raise HTTPException(400, "'To' must be after 'From'.")
    if (t1 - t0).days > 31:
        raise HTTPException(400, "Range is limited to 31 days (about 2 minutes of DLP time per day).")
    users = list(dict.fromkeys(analyze.sam(u) for u in re.split(r"[,;\s]+", body.users) if u.strip()))
    if len(users) > 100:
        raise HTTPException(400, "At most 100 users per check.")
    if not store.load_watch():
        raise HTTPException(400, "The bi01 username list is empty - add it first.")
    rid = runner.start("manual", t0, t1, users, request.state.user.get("username", ""))
    if rid is None:
        return JSONResponse({"detail": "Another check is already running - wait for it to finish."}, status_code=409)
    return {"id": rid}


@router.post("/runs/auto")
def auto_run():
    rid = runner.start_auto()
    if rid is None:
        return JSONResponse({"started": False, "message": "a run is already in progress"}, status_code=409)
    return {"started": True, "run_id": rid}


@router.get("/runs")
def runs(limit: int = 15):
    c = store.conn()
    try:
        return [dict(r) for r in c.execute("SELECT * FROM gs_runs ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 100),))]
    finally:
        c.close()


@router.get("/runs/{rid}")
def run(rid: int):
    c = store.conn()
    try:
        r = c.execute("SELECT * FROM gs_runs WHERE id=?", (rid,)).fetchone()
    finally:
        c.close()
    if not r:
        raise HTTPException(404, "run not found")
    return dict(r)


# ---- findings
SORT_COLS = {"time": "event_time", "user": "user_name", "machine": "machine", "title": "title", "typed": "foreign_users",
             "type": "verdict", "status": "status"}


def _filters(date_from, date_to, verdict, status, q, user, sort, dir):
    where, args = [], []
    if date_from:
        where.append("event_time >= ?"); args.append(date_from[:10] + " 00:00:00")
    if date_to:
        where.append("event_time <= ?"); args.append(date_to[:10] + " 23:59:59")
    if verdict in ("alert", "review"):
        where.append("verdict = ?"); args.append(verdict)
    if status in ("new", "reviewed"):
        where.append("status = ?"); args.append(status)
    if q.strip():
        like = f"%{q.strip().lower()}%"
        where.append("(lower(user_name) LIKE ? OR lower(fio) LIKE ? OR lower(machine) LIKE ? OR lower(foreign_users) LIKE ? OR lower(title) LIKE ?)")
        args += [like] * 5
    if user.strip():
        where.append("lower(user_name) = ?"); args.append(user.strip().lower())
    w = (" WHERE " + " AND ".join(where)) if where else ""
    col = SORT_COLS.get(sort, SORT_COLS["time"])
    d = "ASC" if dir.lower() == "asc" else "DESC"
    order = f" ORDER BY {col} COLLATE NOCASE {d}, event_time DESC, id DESC"      # col comes from the whitelist only
    return w, args, order


def _grouped_sql(w):
    # one row per user = their most recent matching alert; "cnt" = how many matching alerts that user has
    return ("WITH f AS (SELECT * FROM gs_events" + w + "), r AS (SELECT *, ROW_NUMBER() OVER (PARTITION BY lower(user_name) "
            "ORDER BY event_time DESC, id DESC) rn, COUNT(*) OVER (PARTITION BY lower(user_name)) cnt FROM f) ")


@router.get("/events")
def events(date_from: str = "", date_to: str = "", verdict: str = "", status: str = "", q: str = "", limit: int = 50, offset: int = 0,
           sort: str = "time", dir: str = "desc", group: int = 0, user: str = ""):
    w, args, order = _filters(date_from, date_to, verdict, status, q, user, sort, dir)
    lim, off = min(max(limit, 1), 200), max(offset, 0)
    c = store.conn()
    try:
        if group:
            base = _grouped_sql(w)
            total = c.execute(base + "SELECT COUNT(*) FROM r WHERE rn=1", args).fetchone()[0]
            rows = [dict(r) for r in c.execute(base + "SELECT * FROM r WHERE rn=1" + order + " LIMIT ? OFFSET ?", (*args, lim, off))]
        else:
            total = c.execute("SELECT COUNT(*) FROM gs_events" + w, args).fetchone()[0]
            rows = [dict(r) for r in c.execute("SELECT * FROM gs_events" + w + order + " LIMIT ? OFFSET ?", (*args, lim, off))]
    finally:
        c.close()
    return {"total": total, "rows": rows}


def _cell(v):
    """Typed text / window titles come from end users: never let Excel treat them as a formula."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


@router.get("/export")
def export(date_from: str = "", date_to: str = "", verdict: str = "", status: str = "", q: str = "", sort: str = "time", dir: str = "desc",
           group: int = 0, open: str = ""):
    """The Findings table exactly as filtered / sorted / grouped on screen - every page. In the unique-users view the other alerts of
    a user are included only for users the analyst has expanded (`open` = their user names)."""
    import io
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    from fastapi.responses import Response
    w, args, order = _filters(date_from, date_to, verdict, status, q, "", sort, dir)
    opened = {u.strip().lower() for u in open.split(",") if u.strip()}
    c = store.conn()
    try:
        if group:
            main = [dict(r) for r in c.execute(_grouped_sql(w) + "SELECT * FROM r WHERE rn=1" + order + " LIMIT 50000", args)]
        else:
            main = [dict(r) for r in c.execute("SELECT * FROM gs_events" + w + order + " LIMIT 50000", args)]
        out = []
        for r in main:
            out.append((r, False))
            if group and r["cnt"] > 1 and r["user_name"].lower() in opened:
                w2, a2, _ = _filters(date_from, date_to, verdict, status, q, r["user_name"], "time", "desc")
                for k in c.execute("SELECT * FROM gs_events" + w2 + " ORDER BY event_time DESC, id DESC", a2):
                    if k["id"] != r["id"]:
                        out.append((dict(k), True))
    finally:
        c.close()
    wb = Workbook(); ws = wb.active; ws.title = "Global Search"
    head = ["Time", "User", "Full name", "Machine", "IP", "App / site / title", "Typed username", "Typed text (masked)", "Type", "Status",
            "Reviewed by", "Reviewed at", "Note"] + (["Entry"] if group else [])
    ws.append(head)
    for r, child in out:
        try:
            t = datetime.strptime(r["event_time"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            t = r["event_time"]
        row = [t, f"{r['user_domain']}\\{r['user_name']}" if r["user_domain"] else r["user_name"], r["fio"], r["machine"], r["ip"], r["title"],
               r["foreign_users"], r["snippet"], r["verdict"], "Reviewed" if r["status"] == "reviewed" else "Open",
               r["reviewed_by"] or "", r["reviewed_at"] or "", r["note"] or ""]
        if group:
            row.append("\u21b3 same user" if child else (f"latest of {r['cnt']}" if r["cnt"] > 1 else "only alert"))
        ws.append([_cell(v) for v in row])
        if child:
            for cell in ws[ws.max_row]:
                cell.fill = PatternFill("solid", fgColor="F3EFEA")
        ws.cell(ws.max_row, 1).number_format = "yyyy-mm-dd hh:mm:ss"
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF"); cell.fill = PatternFill("solid", fgColor="8A1F2D"); cell.alignment = Alignment(vertical="center")
    for i, wd in enumerate([20, 24, 22, 20, 14, 46, 18, 26, 8, 10, 14, 19, 30, 14][:len(head)], 1):
        ws.column_dimensions[get_column_letter(i)].width = wd
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    buf = io.BytesIO(); wb.save(buf)
    fn = f"global-search-{datetime.now():%Y%m%d-%H%M}.xlsx"
    return Response(buf.getvalue(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{fn}"'})


class ReviewBody(BaseModel):
    status: str = "reviewed"
    note: str = ""


@router.post("/events/{eid}/review")
def review(eid: int, body: ReviewBody, request: Request):
    if body.status not in ("new", "reviewed"):
        raise HTTPException(400, "bad status")
    u = request.state.user
    who = u.get("username", "")
    c = store.conn()
    try:
        cur = c.execute("UPDATE gs_events SET status=?, reviewed_by=?, reviewed_at=datetime('now','localtime'), note=? WHERE id=?",
                        (body.status, who, body.note[:500], eid))
        c.commit()
        if not cur.rowcount:
            raise HTTPException(404, "event not found")
    finally:
        c.close()
    return {"ok": True}


# ---- "Search in DLP": the DLP's own report page, filtered to this one event
BAR = """
<div id="gsbar" style="position:fixed;bottom:0;left:0;right:0;z-index:99999;background:#222;color:#fff;font:13px Verdana;padding:7px 14px">
 Global search: <b>%(kw)s</b> &nbsp;&middot;&nbsp; %(who)s &nbsp;&middot;&nbsp; %(t)s &nbsp;&rarr;&nbsp; <span id="gsmsg">locating the row...</span></div>
<script>
// the DLP's Report link calls top.GenReportInNewWindow, which only exists inside the DLP itself: open our own viewer instead
window.Go=function(rid,locs,b,e){
  if (String(rid)!=="212"){ alert("Only the screenshots report is supported from here."); return; }
  window.open(window.location.origin+"/api/gsearch/shots?locs="+encodeURIComponent(locs)+"&b="+encodeURIComponent(b)+"&e="+encodeURIComponent(e),"_blank");
};
(function(){
  var user=%(user)s, t=%(tj)s;
  function go(n){
    var best=null, all=document.querySelectorAll("tr,[role=row]");
    for (var i=0;i<all.length;i++){ var x=all[i].textContent||""; if (x.indexOf(t)>=0 && x.toLowerCase().indexOf(user)>=0){ best=all[i]; break; } }
    if(!best){ if(n<40) return setTimeout(function(){go(n+1)},250); document.getElementById("gsmsg").textContent="row not highlighted - see the table above"; return; }
    best.style.outline="3px solid #e0a83f"; best.style.background="#fff3c4"; best.scrollIntoView({block:"center"});
    var m=document.getElementById("gsmsg"); m.textContent="highlighted"; document.getElementById("gsbar").style.background="#1f5f3b";
  }
  window.addEventListener("load",function(){setTimeout(function(){go(0)},600)});
})();</script>"""


def _msg(title, text, code=200):
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>{title}</title><body style='font:15px sans-serif;margin:60px auto;max-width:560px'>"
                        f"<h2>{title}</h2><p>{text}</p>", status_code=code)


@router.get("/view/{eid}")
def view_in_dlp(eid: int):
    import json
    from datetime import timedelta
    from html import escape
    c = store.conn()
    try:
        e = c.execute("SELECT * FROM gs_events WHERE id=?", (eid,)).fetchone()
    finally:
        c.close()
    if not e:
        return _msg("Not found", "This finding no longer exists.", 404)
    t = datetime.strptime(e["event_time"], "%Y-%m-%d %H:%M:%S")
    t0 = t.replace(second=0)                                        # the exact minute of the event
    kw = e["foreign_users"].split(",")[0]
    try:
        page, base = fetch.fetch_slice(fetch.sd.load_cfg(), [], t0, t0 + timedelta(minutes=1), kw, raw=True)
    except Exception as ex:
        return _msg("DLP did not answer", escape(str(ex))[:300], 502)
    if not page:
        return _msg("Nothing found in the DLP", f"The DLP has no result for <b>{escape(kw)}</b> at {escape(e['event_time'])} any more.")
    who = f"{e['user_domain']}\\{e['user_name']}"
    bar = BAR % {"kw": escape(kw), "who": escape(who), "t": escape(e["event_time"]), "user": json.dumps(e["user_name"].lower()), "tj": json.dumps(e["event_time"])}
    page = page.replace("<head>", f'<head><base href="{escape(base)}/">', 1).replace("</body>", bar + "</body>", 1)
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


# ---- the DLP table's "Report" link: that user's screenshots, jumping to the one nearest the event
@router.get("/shots")
def shots(request: Request, locs: str, b: float, e: float = 0):
    from html import escape
    from ..shots import dlp as sd
    if not re.fullmatch(r"\d{1,7}(,\d{1,7}){0,300}", locs):
        return _msg("Bad request", "Invalid location ids.", 400)
    t = (datetime(1899, 12, 30) + timedelta(days=b)).replace(microsecond=0)      # the DLP passes Excel day serials
    cfg = sd.load_cfg()
    try:
        ids = set(locs.split(","))
        for lst in sd.locations(cfg).values():          # send ALL of the person's devices, as the Screenshots tab does
            if ids & set(lst):
                ids |= set(lst)
        with sd.GEN_LOCK:
            page = sd.fetch_group(cfg, "", t.date(), sorted(ids, key=int))
    except Exception as ex:
        return _msg("DLP did not answer", escape(str(ex))[:300], 502)
    if 'class="sshot"' not in page:
        return _msg("No screenshots", f"The DLP has no screenshots for this user on {t:%Y-%m-%d} (checked all of their machines).")
    sub = {"base": cfg["dlp_base"].rstrip("/") + "/emp/sessions/x/content/0/", "target": t.strftime("%Y-%m-%d %H:%M:%S"),
           "iso": t.strftime("%Y-%m-%dT%H:%M:%S")}
    page = page.replace('href="../../../../cgi-report.exe?action=getfile&filepath=', f'target="_blank" href="{request.base_url}api/shots/getfile?filepath=')
    page = page.replace("<head>", "<head>" + sd.HEAD_INJ % sub, 1)
    bar = sd.BAR_INJ % sub
    j = page.rfind("</body>")
    page = page[:j] + bar + page[j:] if j >= 0 else page + bar
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})
