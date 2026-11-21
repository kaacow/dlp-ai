"""Screenshot Opener — upload the daily Excel of DLP events; per row, open that user's day in the
DLP screenshot viewer, jumping to the screenshot nearest to the event time.

Routes live under /api/shots/* behind the console's shared auth (middleware in main.py).
Batches (uploaded files) are kept in memory per logged-in user; reports are generated on click only.
"""
import re
import threading
import time
import uuid
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import dlp

router = APIRouter(prefix="/api/shots", tags=["shots"])

BATCHES = {}          # id -> batch dict
MAX_BATCHES = 12      # keep the most recent uploads only


def init_db():
    dlp.DB_DIR.mkdir(parents=True, exist_ok=True)
    dlp.FAV_DIR.mkdir(parents=True, exist_ok=True)


def get_batch(bid, request: Request):
    b = BATCHES.get(bid)
    if not b:
        raise HTTPException(404, "This upload is no longer in memory - upload the file again.")
    u = request.state.user
    if b["owner"] != u["id"] and u["role"] != "admin":
        raise HTTPException(403, "not your upload")
    return b


@router.post("/upload")
def upload(request: Request, file: UploadFile = File(...), date_order: str = Form("MDY")):
    cfg = dlp.load_cfg()
    cfg["date_order"] = date_order if date_order in ("MDY", "DMY") else "MDY"
    try:
        header, rows, errors, meta = dlp.parse_excel(file.file.read(), cfg["date_order"])
    except Exception as e:
        raise HTTPException(400, f"Could not read file: {e}")
    if not rows:
        raise HTTPException(400, "No usable rows. " + "; ".join(errors[:5]))
    groups = {}
    for r in rows:
        key = (r["_user"], r["_time"].date())
        groups.setdefault(key, {"status": "queued", "error": "", "count": 0, "html": ""})
        r["_key"] = key
        r["_search"] = " ".join(str(v) for v in r.values() if isinstance(v, str)).lower() + " " + f"{r['_time']:%Y-%m-%d %H:%M:%S}"
    bid = uuid.uuid4().hex[:8]
    b = {"cfg": cfg, "header": header, "rows": rows, "groups": groups, "errors": errors, "name": file.filename or "upload.xlsx",
         "meta": meta, "show_hidden": False, "checked": set(), "viewed": set(), "owner": request.state.user["id"], "created": time.time()}
    dlp.recompute(b)
    BATCHES[bid] = b
    while len(BATCHES) > MAX_BATCHES:
        BATCHES.pop(min(BATCHES, key=lambda k: BATCHES[k]["created"]))
    return {"id": bid}


@router.get("/batches")
def my_batches(request: Request):
    u = request.state.user
    out = [{"id": k, "name": b["name"], "rows": len(b["rows"]), "created": b["created"]}
           for k, b in BATCHES.items() if b["owner"] == u["id"] or u["role"] == "admin"]
    return sorted(out, key=lambda x: -x["created"])


@router.get("/b/{bid}")
def batch_meta(bid: str, request: Request):
    b = get_batch(bid, request)
    users = list(dict.fromkeys(r["_user"] for r in b["rows"]))
    return {"name": b["name"], "cols": ["User", "Time"] + dlp.show_cols(b["header"]), "users": users,
            "user_w": min(320, max(160, max(len(u) for u in users) * 10 + 44)),
            "hidden": b["meta"]["hidden"], "filter_ref": b["meta"]["filter_ref"], "errors": b["errors"][:5],
            "more_errors": max(0, len(b["errors"]) - 5), "show_hidden": b["show_hidden"]}


@router.get("/rows/{bid}")
def rows_batch(bid: str, request: Request, n: int = 0, q: str = "", rs: str = "", re: str = ""):
    b = get_batch(bid, request)
    q = q.strip().lower()
    n = max(0, n)
    idx = dlp.filtered(b, q, rs.strip(), re.strip())
    rng = dlp.batch_ranges(b, idx)
    cols = dlp.show_cols(b["header"])
    out, start, end = [], 0, 0
    if rng:
        n = min(n, len(rng) - 1)
        s0, e0 = rng[n]
        start, end = s0 + 1, e0
        sl = idx[s0:e0]
        rows = b["rows"]
        for k, i in enumerate(sl):
            r = rows[i]
            g = b["groups"][r["_key"]]
            pv = rows[sl[k - 1]] if k else None
            nx = rows[sl[k + 1]] if k + 1 < len(sl) else None
            out.append({"i": i, "cells": [r["_user"], f"{r['_time']:%Y-%m-%d %H:%M:%S}"] + [r.get(c, "") for c in cols],
                        "status": g["status"], "error": g["error"], "count": g["count"],
                        "tg": r["_tg"], "ubs": b["bsize"][r["_blk"]], "uh": (r["_blk"] * 47) % 360,
                        "th": (r["_tg"] * 83 + 200) % 360, "tsize": b["tsize"][r["_tg"]],
                        "ufirst": pv is None or pv["_blk"] != r["_blk"], "ulast": nx is None or nx["_blk"] != r["_blk"],
                        "tfirst": pv is None or pv["_tg"] != r["_tg"], "tlast": nx is None or nx["_tg"] != r["_tg"],
                        "checked": r["_tgk"] in b["checked"], "viewed": r["_tgk"] in b["viewed"]})
    return {"rows": out, "n": n, "nb": len(rng), "start": start, "end": end, "total": len(idx), "stats": dlp.stats(b)}


@router.get("/range/{bid}")
def range_check(bid: str, request: Request, s: str = "", e: str = ""):
    b = get_batch(bid, request)
    lo, hi, err = dlp.range_bounds(b, s.strip(), e.strip())
    if err:
        return {"ok": False, "msg": err}
    sl = b["vis"][lo:hi + 1]
    return {"ok": True, "rows": len(sl), "users": len({b["rows"][i]["_blk"] for i in sl})}


@router.post("/check/{bid}/{i}")
def toggle_check(bid: str, i: int, request: Request):
    b = get_batch(bid, request)
    k = b["rows"][i]["_tgk"]
    b["checked"].symmetric_difference_update({k})
    return {"checked": k in b["checked"], "stats": dlp.stats(b)}


@router.post("/hidden/{bid}")
def toggle_hidden(bid: str, request: Request, on: int = 0):
    b = get_batch(bid, request)
    b["show_hidden"] = bool(on)
    dlp.recompute(b)
    return {"ok": True}


@router.get("/status/{bid}/{i}")
def status(bid: str, i: int, request: Request):
    b = get_batch(bid, request)
    g = b["groups"][b["rows"][i]["_key"]]
    return {"status": g["status"], "error": g["error"], "count": g["count"]}


WAIT_PAGE = """<!doctype html><meta charset=utf-8><title>Generating screenshots...</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#f6f5f2;--card:#fff;--ink:#1c1b19;--mut:#6b6862;--bd:#e3e0d9;--ac:#8a1f2d;--ok:#2f7d4f;--bad:#b3261e}
@media(prefers-color-scheme:dark){:root{--bg:#171614;--card:#211f1c;--ink:#eeece7;--mut:#9b968c;--bd:#37342e;--ac:#d3707d;--ok:#5fbf85;--bad:#e2665d}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,Segoe UI,sans-serif;overflow:hidden}
.c{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:34px 38px 28px;width:min(520px,92vw);text-align:center;position:relative;box-shadow:0 10px 40px rgba(0,0,0,.08)}
.spin{height:120px;margin:0 auto 6px;display:block;animation:spin 1.1s linear infinite;filter:drop-shadow(0 6px 10px rgba(0,0,0,.25))}
.spin.pop{animation:pop .6s ease-out forwards}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pop{0%{transform:scale(1) rotate(0)}40%{transform:scale(1.35) rotate(-12deg)}100%{transform:scale(1) rotate(0)}}
h1{font-size:18px;margin:14px 0 4px}.sub{color:var(--mut);font-size:13px}
.msg{height:24px;margin:16px 0 8px;font-weight:600;color:var(--ac);transition:opacity .35s,transform .35s}.msg.out{opacity:0;transform:translateY(8px)}
.dots{display:flex;gap:7px;justify-content:center;margin:6px 0 14px}.dots i{width:9px;height:9px;border-radius:50%;background:var(--ac);animation:bounce 1s ease-in-out infinite}
.dots i:nth-child(2){animation-delay:.15s}.dots i:nth-child(3){animation-delay:.3s}.dots i:nth-child(4){animation-delay:.45s}.dots i:nth-child(5){animation-delay:.6s}
@keyframes bounce{0%,80%,100%{transform:translateY(0);opacity:.45}40%{transform:translateY(-11px);opacity:1}}
.bar{height:6px;border-radius:3px;background:var(--bd);overflow:hidden}.bar i{display:block;height:100%;width:40%;border-radius:3px;background:linear-gradient(90deg,transparent,var(--ac),transparent);animation:slide 1.3s ease-in-out infinite}
@keyframes slide{0%{transform:translateX(-120%)}100%{transform:translateX(280%)}}
.t{margin-top:12px;color:var(--mut);font-size:12.5px}
.fl{position:absolute;font-size:22px;opacity:.9;animation:float 4s ease-in-out infinite}
.f1{left:-14px;top:30px}.f2{right:-12px;top:70px;animation-delay:.8s}.f3{left:8%;bottom:-16px;animation-delay:1.6s}.f4{right:10%;bottom:-18px;animation-delay:2.4s}
@keyframes float{0%,100%{transform:translateY(0) rotate(-8deg)}50%{transform:translateY(-14px) rotate(8deg)}}
.err{background:color-mix(in srgb,var(--bad) 12%,transparent);border:1px solid var(--bad);padding:10px;border-radius:8px;margin:14px 0 6px;text-align:left;font-size:13px}
a.retry{display:inline-block;margin-top:8px;color:#fff;background:var(--ac);padding:7px 16px;border-radius:8px;text-decoration:none;font-weight:600}
</style>
<div class=c>
 <span class="fl f1">&#128247;</span><span class="fl f2">&#128269;</span><span class="fl f3">&#128190;</span><span class="fl f4">&#9749;</span>
 <img class=spin id=sp src="/shots-loading.png" alt="">
 <h1>Fetching __USER__'s screenshots</h1><div class=sub>__DAY__ &middot; all of their devices</div>
 <div class=msg id=msg>Asking the DLP very nicely...</div>
 <div class=dots><i></i><i></i><i></i><i></i><i></i></div>
 <div class=bar><i></i></div>
 <div class=t id=t>0s</div><div id=e></div>
</div>
<script>
const M=["Asking EMP very nicely...","Counting screenshots (no peeking)...","Convincing the server to open its photo album...","Teaching hamsters to fetch JPEGs...","Dusting off yesterday's desktops...","Waking up the DLP server...","Still faster than doing it by hand &#9749;","Almost there... probably.","Politely knocking on emp.example.internal...","Sorting pixels by importance..."];
let k=0,t0=Date.now(),m=document.getElementById('msg');m.innerHTML=M[0];
const rot=setInterval(()=>{m.classList.add('out');setTimeout(()=>{k=(k+1)%M.length;m.innerHTML=M[k];m.classList.remove('out')},350)},2400);
const tick=setInterval(()=>{document.getElementById('t').textContent=Math.round((Date.now()-t0)/1000)+'s'},500);
const poll=setInterval(async()=>{
  const r=await fetch('/api/shots/status/__BID__/__I__');if(r.status==401){location='/login.html';return}
  const x=await r.json();
  if(x.status=='ready'){clearInterval(poll);clearInterval(rot);clearInterval(tick);const sp=document.getElementById('sp');sp.classList.add('pop');
    m.innerHTML='Got it! Opening '+x.count.toLocaleString()+' screenshots...';setTimeout(()=>location.reload(),650);}
  if(x.status=='error'||x.status=='empty'){clearInterval(poll);clearInterval(rot);clearInterval(tick);
    document.getElementById('sp').style.animation='none';m.innerHTML=x.status=='empty'?'Nothing to show here':'Something went wrong';
    document.getElementById('e').innerHTML='<div class=err></div><a class=retry href="">Try again</a>';document.querySelector('.err').textContent=x.error;}
},1500);
</script>"""


@router.get("/view/{bid}/{i}")
def view(bid: str, i: int, request: Request):
    b = get_batch(bid, request)
    r = b["rows"][i]
    g = b["groups"][r["_key"]]
    b["viewed"].add(r["_tgk"])           # opening an event dims it; only "Mark checked" counts + collapses it
    if g["status"] in ("queued", "error", "empty"):
        threading.Thread(target=dlp.run_group, args=(b, r["_key"]), daemon=True).start()
        g["status"] = "running"
    if g["status"] != "ready":
        import html as _h
        return HTMLResponse(WAIT_PAGE.replace("__USER__", _h.escape(r["_user"])).replace("__DAY__", f"{r['_time']:%Y-%m-%d}")
                            .replace("__BID__", bid).replace("__I__", str(i)))
    t = r["_time"]
    sub = {"base": b["cfg"]["dlp_base"].rstrip("/") + "/emp/sessions/x/content/0/",
           "target": t.strftime("%Y-%m-%d %H:%M:%S"), "iso": t.strftime("%Y-%m-%dT%H:%M:%S")}
    html = g["html"].replace('href="../../../../cgi-report.exe?action=getfile&filepath=',
                             f'target="_blank" href="{str(request.base_url)}api/shots/getfile?filepath=')
    html = html.replace("<head>", "<head>" + dlp.HEAD_INJ % sub, 1)
    bar = dlp.BAR_INJ % sub
    j = html.rfind("</body>")
    html = html[:j] + bar + html[j:] if j >= 0 else html + bar
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@router.get("/getfile")
def getfile(filepath: str = ""):
    """Full-size screenshot, fetched with the console's own DLP session."""
    cfg = dlp.load_cfg()
    base = cfg["dlp_base"].rstrip("/") + "/emp"
    r = None
    for _ in range(2):
        s = dlp.DLP.get(cfg)
        r = s.get(base + "/cgi-report.exe", params={"action": "getfile", "filepath": filepath}, timeout=60)
        if r.headers.get("Content-Type", "").startswith("image") or r.status_code != 200:
            break
        dlp.DLP.reset()
    return Response(r.content, status_code=r.status_code, media_type=r.headers.get("Content-Type", "image/jpeg"))


@router.get("/favicon/{host}")
def favicon(host: str):
    res = dlp.favicon_for(host)
    if not res:
        return Response(status_code=404, headers={"Cache-Control": "max-age=3600"})
    return Response(res[1], media_type=res[0], headers={"Cache-Control": "max-age=604800"})
