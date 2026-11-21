"""Report 247 ("Global database search") fetcher. Shares the Screenshots feature's logged-in DLP session,
location map and report lock (the DLP allows ONE report session at a time)."""
import json
import re
import time
from datetime import datetime, timedelta
from urllib.parse import quote

from ..shots import dlp as sd

REPORT_ID = "247"
TARGET = "bi.example-corp.com"
CAP = 500                          # the DLP returns only the LAST 500 records of a query
BODY = ("MyHttpURL={myurl}&ReportId={rid}&LocationIds={loc}&ScreenWidth=1920&ScreenHeight=1080"
        "&DateTimePickerBegin={d0}&HourSelectBegin={h0}&MinuteSelectBegin={m0}"
        "&DateTimePickerEnd={d1}&HourSelectEnd={h1}&MinuteSelectEnd={m1}"
        "&EditWorkHours=8&HourWorkDayBegin=9.0&EditDayBreak=60&ComboBoxFilterAppSite=&ComboBoxFilterText={text}"
        "&TemplatesSearch0=&CheckBoxFileLinkURL=1&SQLQueryText=&GlobalSearchWhere=2")


def window_fields(t0, t1):
    """t1 is exclusive; midnight is expressed the way the DLP form does it: previous day, hour 24."""
    if t1.hour == 0 and t1.minute == 0:
        d1, h1, m1 = (t1 - timedelta(days=1)).date(), 24, 0
    else:
        d1, h1, m1 = t1.date(), t1.hour, t1.minute
    return dict(d0=t0.strftime("%d.%m.%Y"), h0=t0.hour, m0=t0.minute, d1=d1.strftime("%d.%m.%Y"), h1=h1, m1=m1)


def parse_user_cell(v):
    """'CORP\\jdoe\\r\\n(John Doe)' -> (domain, name, fio)"""
    first, _, rest = (v or "").replace("\r", "").partition("\n")
    dom, _, name = first.strip().rpartition("\\")
    return dom.strip(), name.strip(), rest.strip().strip("()")


def parse_report(js):
    """report_data.js text -> (rows, capped)"""
    j = json.loads(js[js.index("=") + 1:].strip().rstrip(";"))
    cols = [c.get("title") for c in j.get("columns", [])]
    need = ["User", "Machine", "IPv4", "Time", "App/Site/Title", "Text"]
    if any(n not in cols for n in need):
        raise RuntimeError(f"report 247 columns changed: {cols}")
    ix = {n: cols.index(n) for n in need}
    rows = []
    for r in j.get("rows", []):
        dom, name, fio = parse_user_cell(r[ix["User"]])
        rows.append({"domain": dom, "user": name, "fio": fio, "machine": r[ix["Machine"]], "ip": r[ix["IPv4"]],
                     "time": r[ix["Time"]], "title": r[ix["App/Site/Title"]], "text": r[ix["Text"]] or ""})
    capped = "last" in str(j.get("tableTitle", "")).lower() and len(rows) >= CAP
    return rows, capped


def fetch_slice(cfg, locids, t0, t1, keyword, raw=False):
    """One report request for [t0, t1): the DLP text-searches `keyword` (what users TYPED; LocationIds is ignored by
    this report). Returns (rows, capped)."""
    base = cfg["dlp_base"].rstrip("/") + "/emp"
    body = BODY.format(myurl=quote(base + "/boffline/", safe=""), rid=REPORT_ID, loc=",".join(locids), text=quote(keyword),
                       **window_fields(t0, t1))
    hdr = {"Content-Type": "application/x-www-form-urlencoded", "Origin": cfg["dlp_base"], "Referer": base + "/boffline/"}
    busy, last = 0, ""
    with sd.GEN_LOCK:
        for _ in range(30):
            s = sd.DLP.get(cfg)
            r = s.post(base + "/cgi-report.exe?action=report", data=body, headers=hdr, timeout=300)
            txt = r.content.decode("utf-8-sig", errors="replace")      # DLP declares no charset
            last = txt
            if "nothing was found in base" in txt or "there is no data" in txt:
                return (None, None) if raw else ([], False)
            if "report_data.js" in txt:
                if raw:                                  # the page itself + the DLP folder holding its assets
                    return txt, r.url.rsplit("/", 1)[0]
                d = s.get(r.url.rsplit("/", 1)[0] + "/report_data.js", timeout=300)
                return parse_report(d.content.decode("utf-8-sig", errors="replace"))
            if "Session busy" in txt:
                busy += 1
                if busy == 8:
                    try:
                        s.get(base + "/cgi-report.exe?action=killall", timeout=30)
                    except Exception:
                        pass
                time.sleep(3)
                continue
            sd.DLP.reset()                                              # login page / expired -> log in again
    raise RuntimeError("DLP gave no report data: " + re.sub(r"<[^>]+>", " ", last)[:160].strip())


def collect(cfg, keyword, t0, t1, progress=None):
    """All rows in [t0, t1). If the DLP says it cut the answer at 500 rows, the window is halved until
    every piece fits (down to 1 minute). Returns (rows deduped, warnings)."""
    out, seen, warns = [], set(), []

    def go(a, b):
        rows, capped = fetch_slice(cfg, [], a, b, keyword)
        if progress:
            progress()
        if capped and (b - a) > timedelta(minutes=1):
            mid = a + (b - a) / 2
            mid = mid.replace(second=0, microsecond=0)
            if mid <= a:
                mid = a + timedelta(minutes=1)
            go(a, mid)
            go(mid, b)
            return
        if capped:
            warns.append(f"{a:%Y-%m-%d %H:%M}: more than {CAP} rows inside a single minute, the oldest were cut off by the DLP")
        for r in rows:
            k = (r["domain"].lower(), r["user"].lower(), r["machine"], r["time"], r["title"], r["text"])
            if k not in seen:
                seen.add(k)
                out.append(r)

    go(t0, t1)
    return out, warns


def user_locids(cfg, names):
    """names (Windows user names, any case) -> (location ids, unknown names)"""
    m = sd.locations(cfg)
    ids, unknown = [], []
    for n in names:
        got = m.get(n.lower())
        if not got:
            unknown.append(n)
        else:
            ids += [i for i in got if i not in ids]
    return ids, unknown
