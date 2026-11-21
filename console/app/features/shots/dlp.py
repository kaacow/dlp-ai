"""Screenshot Opener core: Excel parsing, DLP (EMP report portal) session + report generation,
grouping logic, favicon cache. Router in router.py."""
import io, json, os, re, threading, time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urljoin

import openpyxl
import requests
import urllib3

urllib3.disable_warnings()

BASE_DIR = Path(os.environ.get("SHOTS_BASE", "./data"))
DB_DIR = BASE_DIR / "db"
CFG_PATH = DB_DIR / "shots_config.json"
FAV_DIR = DB_DIR / "shots_favicons"

DEFAULT_CFG = {"dlp_base": "https://emp.example.internal", "username": "", "password": "", "report_id": "212", "date_order": "MDY"}


def load_cfg():
    cfg = dict(DEFAULT_CFG)
    try:
        cfg.update(json.loads(CFG_PATH.read_text()))
    except Exception:
        pass
    return cfg


# ---------------------------------------------------------------- Excel
def parse_time(v, order):
    if isinstance(v, datetime):
        return v
    s = str(v).strip()
    mdy = ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y"]
    dmy = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y"]
    other = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d.%m.%Y %H:%M:%S", "%d.%m.%Y %H:%M"]
    for f in (mdy + dmy if order == "MDY" else dmy + mdy) + other:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            pass
    raise ValueError(f"cannot read time '{s}'")


def parse_excel(data, order):
    """header, rows, errors, meta. Rows hidden by an Excel filter (or manually hidden) get _hidden=True."""
    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=True)
    ws = wb.active
    meta = {"filter_ref": ws.auto_filter.ref or "", "hidden": 0}
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        raise ValueError("The file is empty.")
    header = [str(c).strip() if c is not None else "" for c in rows[0]]
    low = [h.lower() for h in header]
    missing = [c for c in ("User", "Time") if c.lower() not in low]
    if missing:
        raise ValueError("Missing required column(s): " + ", ".join(missing) +
                         ". Columns found: " + ", ".join(h for h in header if h))
    iu, it = low.index("user"), low.index("time")
    out, errors = [], []
    for n, r in enumerate(rows[1:], start=2):
        if not r or all(c is None or str(c).strip() == "" for c in r):
            continue
        hidden = bool(ws.row_dimensions[n].hidden) if n in ws.row_dimensions else False
        d = {header[i]: ("" if c is None else str(c)) for i, c in enumerate(r) if i < len(header) and header[i]}
        user = str(r[iu] or "").strip()
        try:
            t = parse_time(r[it], order)
            if not user:
                raise ValueError("empty User")
        except Exception as e:
            if not hidden:
                errors.append(f"Row {n}: {e}")
            continue
        d["_user"], d["_time"], d["_row"], d["_hidden"] = user, t, n, hidden
        meta["hidden"] += hidden
        out.append(d)
    return header, out, errors, meta


def show_cols(header):
    """Keep only Employee, File, Application/Site (in that order)."""
    def rank(h):
        l = h.lower()
        return 0 if l == "employee" else 1 if l == "file" else 2 if l.startswith("application") else None
    return sorted((h for h in header if h and rank(h) is not None), key=rank)


# ---------------------------------------------------------------- locations (live from the DLP)
_LOC = {"t": 0, "map": {}}
_LOC_LOCK = threading.Lock()


def locations(cfg):
    """user_name(lower) -> [every LocationId] — one id per (user, device); cached 10 min."""
    with _LOC_LOCK:
        if time.time() - _LOC["t"] > 600 or not _LOC["map"]:
            s = DLP.get(cfg)
            r = s.get(cfg["dlp_base"].rstrip("/") + "/emp/cgi-report.exe", params={"action": "getlocs"}, timeout=90)
            users = r.json().get("response", {}).get("users", [])
            m = {}
            for u in users:
                name = str(u.get("user_name", "")).strip().lower()
                for i in (u.get("ids") or []):
                    if name and str(i).isdigit() and str(i) not in m.setdefault(name, []):
                        m[name].append(str(i))
            if m:
                _LOC.update(t=time.time(), map=m)
        return _LOC["map"]


# ---------------------------------------------------------------- DLP session + report
BODY = ("MyHttpURL={myurl}&ReportId={rid}&LocationIds={loc}&ScreenWidth=1920&ScreenHeight=1080"
        "&DateTimePickerBegin={d}&HourSelectBegin=0&MinuteSelectBegin=0"
        "&DateTimePickerEnd={d}&HourSelectEnd=24&MinuteSelectEnd=0"
        "&EditWorkHours=8&HourWorkDayBegin=9.0&EditDayBreak=60&ComboBoxFilterAppSite=&ComboBoxFilterText="
        "&TemplatesSearch0=&CheckBoxFileLinkURL=1&CheckBoxMasterRepMulti243=1&CheckBoxMasterRepMulti227=1"
        "&CheckBoxMasterRepMulti223=1&CheckBoxMasterRepSingle231=1&CheckBoxMasterRepSingle206=1"
        "&CheckBoxMasterRepSingle241=1&CheckBoxMasterRepSingle204=1&CheckBoxMasterRepMulti204=1"
        "&CheckBoxMasterRepSingle201=1&CheckBoxMasterRepSingle202=1&CheckBoxMasterRepSingle205=1"
        "&CheckBoxMasterRepMulti205=1&CheckBoxMasterRepMulti224=1&CheckBoxMasterRepSingle208=1"
        "&CheckBoxMasterRepMulti208=1&CheckBoxMasterRepSingle212=1&CheckBoxMasterRepSingle211=1"
        "&CheckBoxMasterRepMulti211=1&CheckBoxMasterRepSingle207=1&CheckBoxMasterRepSingle215=1"
        "&CheckBoxMasterRepMulti215=1&CheckBoxMasterRepSingle253=1&CheckBoxMasterRepSingle217=1"
        "&CheckBoxMasterRepMulti217=1&CheckBoxMasterRepSingle218=1&CheckBoxMasterRepMulti218=1"
        "&CheckBoxMasterRepMulti222=1&CheckBoxMasterRepSingle226=1&CheckBoxMasterRepSingle252=1"
        "&CheckBoxMasterRepMulti252=1&CheckBoxMasterRepSingle214=1&CheckBoxMasterRepMulti214=1"
        "&CheckBoxMasterRepSingle219=1&CheckBoxMasterRepMulti219=1&SQLQueryText=&GlobalSearchWhere=0")


class Dlp:
    """One logged-in DLP session, re-created automatically when it expires."""
    def __init__(self):
        self.s = None
        self.lock = threading.Lock()

    def reset(self):
        self.s = None

    def get(self, cfg):
        with self.lock:
            if self.s is None:
                if not cfg.get("username") or not cfg.get("password"):
                    raise RuntimeError("No DLP username/password configured (db/shots_config.json).")
                base = cfg["dlp_base"].rstrip("/") + "/emp"
                s = requests.Session()
                s.verify = False
                s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/146.0.0.0 Safari/537.36"
                s.get(base + "/cgi-report.exe", timeout=30)
                s.post(base + "/cgi-report.exe?action=login", timeout=30, allow_redirects=False,
                       data={"username": cfg["username"], "userpwd": cfg["password"]})
                if not s.cookies.get("stkh_login"):
                    raise RuntimeError("DLP login failed - check the credentials in db/shots_config.json.")
                self.s = s
            return self.s


DLP = Dlp()
GEN_LOCK = threading.Lock()   # the DLP allows only one report session at a time
CACHE = []                    # (batch, key) holding html, oldest first
MAX_CACHE = 10


def fetch_group(cfg, user, day, locids):
    base = cfg["dlp_base"].rstrip("/") + "/emp"
    body = BODY.format(myurl=quote(base + "/boffline/", safe=""), rid=cfg["report_id"],
                       loc=",".join(locids), d=day.strftime("%d.%m.%Y"))
    hdr = {"Content-Type": "application/x-www-form-urlencoded", "Origin": cfg["dlp_base"], "Referer": base + "/boffline/"}
    busy, last, r = 0, "", None
    for _ in range(30):
        s = DLP.get(cfg)
        r = s.post(base + "/cgi-report.exe?action=report", data=body, headers=hdr, timeout=300)
        txt = r.content.decode("utf-8-sig", errors="replace")   # the DLP declares no charset -> force UTF-8
        last = txt
        if "View screenshots" in txt and "tagspane" in txt:
            return txt
        if "nothing was found in base" in txt:
            return txt
        if "Session busy" in txt:
            busy += 1
            if busy == 8:   # stuck session: terminate it, as the DLP's own link offers
                try:
                    s.get(base + "/cgi-report.exe?action=killall", timeout=30)
                except Exception:
                    pass
            time.sleep(3)
            continue
        DLP.reset()          # login page / expired session -> log in again
    raise RuntimeError(f"DLP returned no screenshots page (HTTP {r.status_code if r is not None else '?'}): {re.sub('<[^>]+>', ' ', last)[:160].strip()}")


def run_group(batch, key):
    g = batch["groups"][key]
    g["status"], g["error"] = "running", ""
    with GEN_LOCK:
        try:
            user, day = key
            locs = locations(batch["cfg"]).get(user.lower())
            if not locs:
                raise RuntimeError(f"User '{user}' not found in the DLP user list (no LocationId)")
            html = fetch_group(batch["cfg"], user, day, locs)   # every device of the user
            g["html"], g["count"] = html, html.count('class="sshot"')
            g["status"] = "ready" if g["count"] else "empty"
            if not g["count"]:
                g["error"] = "No screenshots recorded for this user on that day (checked all of their machines)."
        except Exception as e:
            g["status"], g["error"] = "error", str(e)
        if g["status"] == "ready":
            CACHE.append((batch, key))
            while len(CACHE) > MAX_CACHE:
                ob, ok = CACHE.pop(0)
                og = ob["groups"][ok]
                og["html"], og["status"] = "", "queued"


# ---------------------------------------------------------------- grouping / batches
BATCH = 50


def recompute(b):
    """Consecutive rows with the same user form a block; same user+minute form a time group."""
    rows = b["rows"]
    b["vis"] = [i for i, r in enumerate(rows) if b["show_hidden"] or not r["_hidden"]]
    blk = tg = -1
    pu = pk = None
    bsize, tsize = {}, {}
    for i in b["vis"]:
        r = rows[i]
        u = r["_user"].lower()
        k = (u, f"{r['_time']:%Y-%m-%d %H:%M:%S}")      # exact second: one button = one exact moment
        if u != pu:
            blk += 1
        if k != pk:
            tg += 1
        pu, pk = u, k
        r["_blk"], r["_tg"], r["_tgk"] = blk, tg, k
        bsize[blk] = bsize.get(blk, 0) + 1
        tsize[tg] = tsize.get(tg, 0) + 1
    b["bsize"], b["tsize"] = bsize, tsize


def range_bounds(b, rs, re_):
    rows, vis = b["rows"], b["vis"]

    def find(name, last):
        hits = [k for k, i in enumerate(vis) if rows[i]["_user"].lower() == name.lower()]
        if hits:
            return (hits[-1] if last else hits[0]), None
        hidden = any(r["_user"].lower() == name.lower() for r in rows)
        return None, (f"User '{name}' is only in rows hidden by your Excel filter - tick the 'include hidden rows' box." if hidden
                      else f"User '{name}' does not exist in this file.")
    lo, hi, errs = 0, len(vis) - 1, []
    if rs:
        lo, e = find(rs, False)
        errs += [e] if e else []
    if re_:
        hi, e = find(re_, True)
        errs += [e] if e else []
    if errs:
        return None, None, " ".join(errs)
    if lo > hi:
        return None, None, f"'{rs}' comes after '{re_}' in the file - swap start and end."
    return lo, hi, None


def filtered(b, q, rs="", re_=""):
    rows, vis = b["rows"], b["vis"]
    if rs or re_:
        lo, hi, err = range_bounds(b, rs, re_)
        if not err:
            vis = vis[lo:hi + 1]
    return [i for i in vis if not q or q in rows[i]["_search"]]


def batch_ranges(b, idx):
    """~50 rows per batch, a batch only ends where the user changes (a user is never split)."""
    rows, rng, start = b["rows"], [], 0
    for k in range(1, len(idx) + 1):
        if k == len(idx):
            rng.append((start, k))
        elif k - start >= BATCH and rows[idx[k]]["_blk"] != rows[idx[k - 1]]["_blk"]:
            rng.append((start, k))
            start = k
    return rng


def stats(b):
    rows = b["rows"]
    ev = {rows[i]["_tgk"] for i in b["vis"]}
    return {"events": len(ev), "checked": len(ev & b["checked"]), "rows": len(b["vis"]),
            "rows_checked": sum(1 for i in b["vis"] if rows[i]["_tgk"] in b["checked"])}


# ---------------------------------------------------------------- viewer injection (jump to the event's screenshot)
HEAD_INJ = '<base href="%(base)s">'
BAR_INJ = """
<div id="dlpbar" style="position:fixed;bottom:0;left:0;right:0;z-index:99999;background:#222;color:#fff;font:13px Verdana;padding:6px 12px">
 Event: <b>%(target)s</b> &nbsp;&rarr;&nbsp; <span id="dlpmsg">locating...</span></div>
<script>
(function(){
  var target = new Date("%(iso)s".replace(/-/g,"/").replace("T"," "));
  function go(tries){
    if (typeof g_ar === "undefined" || !g_ar || typeof Click !== "function" || !g_ar.length){
      if (tries < 40) return setTimeout(function(){go(tries+1)}, 250);
      document.getElementById("dlpmsg").textContent = "no screenshots found on page"; return;
    }
    var best=-1, bd=1e18, bt=null;
    for (var i=0;i<g_ar.length;i++){
      var m = /(\\d{4})-(\\d\\d)-(\\d\\d) (\\d\\d):(\\d\\d):(\\d\\d)/.exec(g_ar[i].text||"");
      if(!m) continue;
      var t = new Date(+m[1],+m[2]-1,+m[3],+m[4],+m[5],+m[6]);
      var d = Math.abs(t-target);
      if (d<bd){bd=d;best=i;bt=m[0];}
    }
    if (best<0){document.getElementById("dlpmsg").textContent="could not read timestamps";return;}
    var secs=Math.round(bd/1000), mt=/(\\d{4})-(\\d\\d)-(\\d\\d) (\\d\\d):(\\d\\d):(\\d\\d)/.exec(bt), st=new Date(+mt[1],+mt[2]-1,+mt[3],+mt[4],+mt[5],+mt[6]), sd=Math.round((st-target)/1000);
    var how = secs==0 ? "exact match" : (secs<=90 ? (sd>0?"+":"-")+secs+" s from the event" : "nearest available, "+(secs>=3600?(secs/3600).toFixed(1)+" h":Math.round(secs/60)+" min")+(sd>0?" after":" before")+" the event");
    document.getElementById("dlpmsg").innerHTML = "screenshot <b>" + bt + "</b> &middot; " + how;
    document.getElementById("dlpbar").style.background = secs<=90 ? "#1f5f3b" : "#8a5a00";
    var s=document.getElementById("search"); if(s){s.value=bt; try{SearchContent();}catch(e){}}
    Click(best);
  }
  window.addEventListener("load", function(){ setTimeout(function(){go(0)}, 700); });
})();
</script>
"""


# ---------------------------------------------------------------- favicons (fetched once, cached on disk)
FAV_SEM = threading.Semaphore(6)
FAV_LOCKS = {}
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
NOT_TLD = {"exe", "dll", "msi", "bat", "cmd", "scr", "lnk", "sys", "tmp", "ini", "txt", "log", "dat", "bin", "pdf", "doc", "docx", "xls", "xlsx"}
FAV_TYPES = {"png": "image/png", "svg": "image/svg+xml", "ico": "image/x-icon", "gif": "image/gif", "jpg": "image/jpeg"}


def sniff(b):
    if b[:8] == b"\x89PNG\r\n\x1a\n": return "png"
    if b[:4] == b"\x00\x00\x01\x00": return "ico"
    if b[:3] == b"GIF": return "gif"
    if b[:3] == b"\xff\xd8\xff": return "jpg"
    head = b[:300].lstrip().lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in b[:1000].lower()): return "svg"
    return None


def fetch_icon(host):
    labels = host.split(".")
    for h in [host] + ([".".join(labels[1:])] if len(labels) >= 3 else []):
        urls = [f"https://{h}/favicon.ico"]
        try:
            home = requests.get(f"https://{h}/", timeout=4, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            for m in re.finditer(r"<link[^>]+>", home.text[:200000], re.I):
                tag = m.group(0)
                if re.search(r'rel=["\'][^"\']*icon', tag, re.I):
                    hm = re.search(r'href=["\']([^"\']+)', tag, re.I)
                    if hm:
                        urls.insert(0, urljoin(home.url, hm.group(1)))
        except Exception:
            pass
        for u in urls[:4]:
            try:
                r = requests.get(u, timeout=4, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200 and 0 < len(r.content) < 300000 and sniff(r.content):
                    return sniff(r.content), r.content
            except Exception:
                continue
    return None, None


def favicon_for(host):
    """(mime, bytes) or None."""
    host = host.lower().strip()
    if not DOMAIN_RE.match(host) or host.rsplit(".", 1)[-1] in NOT_TLD:
        return None
    FAV_DIR.mkdir(parents=True, exist_ok=True)
    for ext in FAV_TYPES:
        p = FAV_DIR / f"{host}.{ext}"
        if p.exists():
            return FAV_TYPES[ext], p.read_bytes()
    neg = FAV_DIR / f"{host}.none"
    if neg.exists() and time.time() - neg.stat().st_mtime < 7 * 86400:
        return None
    lock = FAV_LOCKS.setdefault(host, threading.Lock())
    with lock, FAV_SEM:
        kind, data = fetch_icon(host)
    if not kind:
        neg.touch()
        return None
    (FAV_DIR / f"{host}.{kind}").write_bytes(data)
    return FAV_TYPES[kind], data
