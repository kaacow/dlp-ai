"""Screenshot fetch + vision-model description, via the EMP report portal web CGI —
NOT the database. See dlp_ai_project_handoff.md for the full story; short version:

Reconstructing the getfile path manually from raw `treportscreenshots` SQL columns
(as originally documented) turned out to be unreliable — a screenshot's SQL-reported
`shot_time`/`file_name`/`file_name_p` did NOT match the real file location for the
same-looking timestamp (confirmed with a direct side-by-side comparison). The
reliable approach is to generate the actual "Screenshots" report (ReportId=212) for
the target user/day and parse the links EMP's own server puts in the HTML —
those are authoritative, ours were guesses.

The generated report page embeds a small base64 JPEG thumbnail per shot directly in
the HTML (`src="data:image/jpeg;base64,..."`, ~4-5KB) AND a full-size download link
(`href=".../cgi-report.exe?action=getfile&filepath=..."`, ~80KB) right next to it.

Tested both on a real screenshot with a contact name visible in a chat header: the
~5KB thumbnail was compressed enough that the vision model misread "Maral" as
"Morgan" — a real, confirmed accuracy problem, not a one-off. The full-size image,
same model, read the name correctly. We fetch full-size for every screenshot that
actually gets analyzed (i.e. only the handful within a given event's time window,
not the whole day) — one extra HTTP round-trip per image is worth it for accuracy
on something a human might act on.

NOTE on account scope: svc_readonly only has report/screenshot access for ONE employee
(user_locator=1001, jdoe — a deliberately scoped test account, confirmed by
the user). Report generation for any other user_locator returns an empty gallery
(no screenshots section rendered), not an error — get_screenshot_evidence() treats
"generated but empty" the same as "no access" and returns [] either way, so it's
always safe to call.
"""
import base64
import html as html_module
import re
from datetime import datetime, timedelta

import requests

import emp_sql as k
import ollama_client

OLLAMA_URL = "http://localhost:11434/api/chat"
# qwen2.5vl:32b — upgraded from the 7b variant after confirming (side-by-side, same
# image) the 32b picks up more scene detail; both read text fine once given a
# full-size image (see module docstring), the 32b's extra value is richer/more
# complete descriptions (concurrent chats, secondary windows) rather than raw OCR
# accuracy. ~20GB, fits comfortably in the GPU workstation's 128GB unified memory alongside
# qwen3:32b.
VISION_MODEL = "qwen2.5vl:32b"

# Each shot in the report HTML looks like:
#   <a href="...action=getfile&filepath=...">
#   <img src="data:image/jpeg;base64,...">
#   <div>2026-07-14 10:00:01<br>[@NB0001]: Program Manager</div>
# The href's filepath query param is itself fully percent-encoded (dashes are %2D,
# underscore is %5F, etc.), so we pull the href as an opaque string and let the
# server resolve it later rather than trying to decode/rebuild it ourselves.
_SHOT_RE = re.compile(
    r'href="([^"]*action=getfile[^"]*)"><img src="data:image/jpeg;base64,([^"]+)">'
    r'<div>(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:<br>([^<]*))?</div>',
)


def generate_screenshots_report(session, user_locator, day: datetime.date):
    date_str = day.strftime("%d.%m.%Y")
    resp = session.post(
        f"{k.BASE}/cgi-report.exe?action=report",
        data={
            "ReportId": "212", "LocationIds": str(user_locator),
            "DateTimePickerBegin": date_str, "DateTimePickerEnd": date_str,
            "HourSelectBegin": "0", "HourSelectEnd": "24",
            "MinuteSelectBegin": "0", "MinuteSelectEnd": "0",
            "EditWorkHours": "", "HourWorkDayBegin": "", "EditDayBreak": "",
            "ComboBoxFilterAppSite": "", "CheckBoxExpandText": "1",
            "MyHttpURL": f"{k.BASE}/boffline/", "NoCleanDir": "1",
        },
        allow_redirects=False,
    )
    if resp.status_code != 302:
        raise RuntimeError(f"Screenshots report generation failed: {resp.status_code}")
    index_url = f"{k.BASE}/" + resp.headers["Location"]
    html = session.get(index_url).text
    return html


def parse_screenshots(html: str):
    """Returns list of {time, window_title, thumbnail_bytes, fullsize_href}."""
    out = []
    for href, b64, ts_str, title in _SHOT_RE.findall(html):
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        out.append({
            "time": dt, "window_title": title.strip(),
            "thumbnail_bytes": base64.b64decode(b64),
            "fullsize_href": html_module.unescape(href),
        })
    return out


def fetch_fullsize(session, fullsize_href: str) -> bytes:
    # href is relative (e.g. "../../../../cgi-report.exe?action=getfile&...")
    url = f"{k.BASE}/cgi-report.exe?" + fullsize_href.split("?", 1)[1]
    resp = session.get(url)
    resp.raise_for_status()
    return resp.content


def describe_screenshot(session, image_bytes: bytes, model: str = None, cancel_event=None) -> str:
    b64 = base64.b64encode(image_bytes).decode("ascii")
    message = ollama_client.stream_chat(
        OLLAMA_URL,
        {
            "model": model or VISION_MODEL,
            "messages": [{
                "role": "user",
                "content": (
                    "This is a screenshot from an employee's work computer, being reviewed "
                    "for a data-loss-prevention investigation. Describe factually what "
                    "application/window is visible, any visible chat recipient name or "
                    "contact info, and any visible document content relevant to judging "
                    "whether sensitive company data is being shared. Be concise (3-5 "
                    "sentences). Do not speculate beyond what's visibly on screen."
                ),
                "images": [b64],
            }],
            "think": False,
        },
        cancel_event=cancel_event, timeout=120,
    )
    return message["content"]


_report_cache = {}  # (user_locator, date) -> parsed shots, per-process cache


def find_screenshots_in_window(session, user_locator, event_time: datetime, window_minutes=5, max_images=3):
    """Returns matching shots (time, window_title, fullsize_href), nearest-first, or []."""
    cache_key = (user_locator, event_time.date())
    if cache_key not in _report_cache:
        try:
            html = generate_screenshots_report(session, user_locator, event_time.date())
            _report_cache[cache_key] = parse_screenshots(html)
        except Exception:
            _report_cache[cache_key] = []

    all_shots = _report_cache[cache_key]
    if not all_shots:
        return []

    window_start = event_time - timedelta(minutes=window_minutes)
    window_end = event_time + timedelta(minutes=window_minutes)
    matching = [s for s in all_shots if window_start <= s["time"] <= window_end]
    matching.sort(key=lambda s: abs((s["time"] - event_time).total_seconds()))
    return matching[:max_images]


def get_screenshot_evidence(session, user_locator, event_time: datetime, window_minutes=5,
                             max_images=3, on_progress=None, vision_model: str = None, cancel_event=None):
    """Returns a list of {time, window_title, description, image_bytes} dicts (full-size
    images, fetched fresh — see module docstring for why not the thumbnail), or []
    if no access/no screenshots in the window. Never raises — best-effort given the
    account's scope limits. `image_bytes` is included so callers (e.g. a report
    builder) can show the analyst the actual image next to the AI's description —
    strip it before persisting to a DB/JSON blob if you don't want raw image bytes
    stored (see investigate.py's store_investigation).

    on_progress(str), if given, is called with a human-readable status line at each
    step — screenshot lookup, fetch, and per-image vision analysis — so a caller can
    surface live progress (e.g. investigation_jobs.steps_json) instead of a bare spinner.

    cancel_event, if given and set, aborts before starting the next screenshot and
    propagates ollama_client.Cancelled from mid-vision-call — see that module for why
    this actually stops GPU work, not just our interest in the result.
    """
    def emit(msg):
        if on_progress:
            on_progress(msg)

    emit(f"Looking for screenshots within {window_minutes} min of the event…")
    matching = find_screenshots_in_window(session, user_locator, event_time, window_minutes, max_images)
    if not matching:
        emit("No screenshots found in window (or no access for this employee).")
        return []
    emit(f"Found {len(matching)} screenshot(s) to analyze.")

    evidence = []
    for i, shot in enumerate(matching, 1):
        if cancel_event is not None and cancel_event.is_set():
            raise ollama_client.Cancelled()
        time_str = shot["time"].strftime("%Y-%m-%d %H:%M:%S")
        try:
            emit(f"Fetching full-size screenshot {i}/{len(matching)} ({time_str})…")
            image_bytes = fetch_fullsize(session, shot["fullsize_href"])
            emit(f"Vision model reading screenshot {i}/{len(matching)}…")
            description = describe_screenshot(session, image_bytes, model=vision_model, cancel_event=cancel_event)
            evidence.append({
                "time": time_str, "window_title": shot["window_title"],
                "description": description, "image_bytes": image_bytes,
            })
        except ollama_client.Cancelled:
            raise
        except Exception as e:
            emit(f"Screenshot {i}/{len(matching)} failed: {e}")
            evidence.append({
                "time": time_str, "window_title": shot["window_title"],
                "description": f"(failed to analyze: {e})", "image_bytes": None,
            })
    return evidence
