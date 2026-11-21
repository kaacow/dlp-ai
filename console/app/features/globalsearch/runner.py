"""Runs a Global Search check: fetch report 247 rows (bi01 only), judge every row's typed text against the bi01 username
list, store alerts, and (scheduled runs only) push a Telegram digest of NEW alerts. One run at a time."""
import threading
import traceback
from datetime import datetime, timedelta

from . import analyze, fetch, store

LOCK = threading.Lock()
TG_MAX_LINES = 15
NIGHT_HOUR = "03:10"          # crontab time, shown in the UI


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def start(kind, t0, t1, users, owner=""):
    """-> run id, or None when a run is already in progress."""
    if not LOCK.acquire(blocking=False):
        return None
    try:
        c = store.conn()
        try:
            cur = c.execute("INSERT INTO gs_runs (kind,status,started,t_from,t_to,scope,owner) VALUES (?,?,?,?,?,?,?)",
                            (kind, "running", _now(), f"{t0:%Y-%m-%d %H:%M}", f"{t1:%Y-%m-%d %H:%M}",
                             ", ".join(users) if users else "all users", owner))
            rid = cur.lastrowid
            c.commit()
        finally:
            c.close()
    except Exception:
        LOCK.release()
        raise
    threading.Thread(target=_run, args=(rid, kind, t0, t1, users), daemon=True).start()
    return rid


def start_auto():
    """Nightly: the whole previous day."""
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    return start("auto", today - timedelta(days=1), today, [], "cron")


def _update(rid, **kv):
    c = store.conn()
    try:
        c.execute("UPDATE gs_runs SET " + ",".join(f"{k}=?" for k in kv) + " WHERE id=?", (*kv.values(), rid))
        c.commit()
    finally:
        c.close()


def _telegram(text):
    try:
        from ..mail import notify
        return notify.send_telegram(text)
    except Exception as e:
        print(f"[globalsearch] telegram failed: {e}")
        return False


def _run(rid, kind, t0, t1, users):
    try:
        entries = store.load_watch()
        watch = analyze.Watch(entries)
        if not len(watch):
            raise RuntimeError("The bi01 username list is empty - add it on the Global Search page first.")
        cfg = fetch.sd.load_cfg()
        # every listed name is a search keyword: the DLP returns who TYPED it; bi01 rows are then judged
        names = list(dict.fromkeys(users)) if users else sorted(watch.owners)
        for u in names:
            watch.owners.setdefault(u, {u})          # a name searched by hand that is not on the list yet
        cnt = {"ok": 0, "alert": 0, "skipped": 0}
        warns, new, seen, done = [], [], set(), 0

        def tick():
            _update(rid, slices=n_req[0] + 1)
            n_req[0] += 1
        n_req = [0]
        c = store.conn()
        try:
            for name in names:
                rows, w = fetch.collect(cfg, name, t0, t1, tick)
                warns += [f"{name}: {x}" for x in w]
                for r in rows:
                    verdict = analyze.judge(r["user"], name, r["title"], r["text"], watch, fetch.TARGET)
                    if verdict is None:
                        cnt["skipped"] += 1
                        continue
                    k = (name, r["domain"].lower(), r["user"].lower(), r["machine"], r["time"], r["text"])
                    if k in seen:
                        continue
                    seen.add(k)
                    cnt[verdict] += 1
                    if verdict == "alert":
                        cur = c.execute(
                            "INSERT OR IGNORE INTO gs_events (run_id,verdict,user_domain,user_name,fio,machine,ip,event_time,title,"
                            "foreign_users,own_users,snippet,text_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (rid, "alert", r["domain"], r["user"], r["fio"], r["machine"], r["ip"], r["time"], r["title"][:300],
                             name, "", analyze.snippet(r["text"], watch), store.text_hash(r["text"] + "|" + name)))
                        if cur.rowcount:
                            new.append((r, "alert", [name]))
                        c.commit()
                done += 1
                _update(rid, rows_text=done)
        finally:
            c.close()
        _update(rid, status="done", finished=_now(), rows_seen=cnt["ok"] + cnt["alert"], rows_text=done, ok=cnt["ok"],
                unknown=cnt["skipped"], review=0, alerts=cnt["alert"], new_events=len(new), warnings="\n".join(warns[:20]))
        if kind == "auto":
            _digest(rid, t0, t1, cnt["ok"] + cnt["alert"], cnt, new, warns)
    except Exception as e:
        traceback.print_exc()
        _update(rid, status="error", finished=_now(), error=str(e)[:500])
        if kind == "auto":      # a silently failing security control is worse than a noisy one
            _telegram(f"Global Search nightly run FAILED ({t0:%Y-%m-%d}): {str(e)[:300]}")
    finally:
        LOCK.release()


def _digest(rid, t0, t1, seen, cnt, new, warns):
    a = [x for x in new if x[1] == "alert"]
    rv = [x for x in new if x[1] == "review"]
    if not new and not warns:
        return                                   # quiet night: no message
    lines = [f"bi01 login check {t0:%Y-%m-%d}: {len(a)} new ALERT ({seen} bi01 logins with a listed username checked)"]
    for r, v, foreign in (a + rv)[:TG_MAX_LINES]:
        who = f"{r['domain']}\\{r['user']}" + (f" ({r['fio']})" if r["fio"] else "")
        lines.append(f"{'ALERT' if v == 'alert' else 'review'} {r['time']} {who} {r['machine']} typed the bi01 username of: {', '.join(foreign)}")
    if len(new) > TG_MAX_LINES:
        lines.append(f"... +{len(new) - TG_MAX_LINES} more, see the Global Search page")
    for w in warns[:3]:
        lines.append("WARNING " + w)
    _telegram("\n".join(lines))
