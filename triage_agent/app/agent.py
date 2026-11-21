"""Track C — agentic investigation.

Baseline evidence (chat messages, window activity, screenshots) is always gathered
automatically for the relevant destination type, same as before. On top of that, the
reasoning model gets a `query_dlp_database` tool and can run its own read-only SQL
against the live EMP DB for anything the baseline evidence didn't cover —
per the user's direction, the investigation isn't limited to a fixed evidence set;
if something else in the DLP tool would help judge an event, the model can go look.

Guardrails: SELECT/WITH only (regex + keyword blocklist, defense in depth even though
the svc_readonly account is itself read-scoped), max 5 tool-call rounds per event, each
query capped to 200 returned rows before being handed back to the model (context
budget, not a query LIMIT — the model can add its own LIMIT).
"""
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import emp_sql as k
import ollama_client
from content_evidence import get_file_content_evidence
from screenshots import get_screenshot_evidence

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"

OLLAMA_URL = "http://localhost:11434/api/chat"
REASONING_MODEL = "qwen3:32b"
MAX_TOOL_ROUNDS = 5
MAX_ROWS_RETURNED = 200

SCREENSHOT_CACHE_DIR = Path(__file__).parent.parent / "db" / "screenshot_cache"

MESSAGING_DESTINATION_TO_MESSENGER = {
    "web.whatsapp.com": "WhatsApp", "web.whatsapp.comcan": "WhatsApp",
    "whatsapp.com": "WhatsApp", "WhatsApp.Root": "WhatsApp",
    "web.telegram.org": "WebTelegram", "Telegram Desktop": "WebTelegram",
    "YandexMessenger": "YandexMessenger",
}

_WRITE_KEYWORDS = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|grant|revoke|create|replace|merge|call|exec|execute)\b",
    re.IGNORECASE,
)

OLE_EPOCH = datetime(1899, 12, 30)


def to_ole(dt: datetime) -> float:
    return (dt - OLE_EPOCH).total_seconds() / 86400.0


def is_safe_select(sql: str) -> bool:
    stripped = sql.strip().rstrip(";").strip()
    if not re.match(r"^(select|with)\b", stripped, re.IGNORECASE):
        return False
    if _WRITE_KEYWORDS.search(stripped):
        return False
    if ";" in stripped:  # no stacked statements
        return False
    return True


def get_chat_context(sess, user_locator, event_time, messenger, window_minutes=5):
    begin, end = to_ole(event_time - timedelta(minutes=window_minutes)), to_ole(event_time + timedelta(minutes=window_minutes))
    query = f"""
        SELECT op_time, msg_type, user_uin, ws_text FROM treportchats
        WHERE user_locator={user_locator} AND messenger='{messenger}'
          AND op_time >= {begin} AND op_time <= {end}
        ORDER BY op_time;
    """
    cols, rows, _ = k.run_sql(sess, query)
    out = []
    for r in rows:
        rec = dict(zip(cols, r))
        text = rec["ws_text"] or ""
        try:
            text = text.encode("latin1").decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
        out.append({
            "time": rec["op_time"], "direction": "sent" if rec["msg_type"] == 1 else "received",
            "contact": rec["user_uin"], "text": text,
        })
    return out


def get_window_context(sess, user_locator, event_time, window_minutes=5):
    from urllib.parse import unquote
    begin, end = to_ole(event_time - timedelta(minutes=window_minutes)), to_ole(event_time + timedelta(minutes=window_minutes))
    query = f"""
        SELECT start_time, ws_app_title, ws_user_text FROM treportappusage
        WHERE user_locator={user_locator} AND start_time >= {begin} AND start_time <= {end}
        ORDER BY start_time;
    """
    cols, rows, _ = k.run_sql(sess, query)
    out = []
    for r in rows:
        rec = dict(zip(cols, r))
        out.append({
            "time": rec["start_time"],
            "window_title": unquote(rec["ws_app_title"] or ""),
            "visible_text": unquote(rec["ws_user_text"] or "")[:500],
        })
    return out


def gather_baseline_evidence(sess, event, on_progress=None, vision_model: str = None, cancel_event=None):
    def emit(msg):
        if on_progress:
            on_progress(msg)

    event_time = datetime.strptime(event["event_time"], "%Y-%m-%d %H:%M:%S")
    user_locator = event["user_locator"]
    messenger = MESSAGING_DESTINATION_TO_MESSENGER.get(event["app_desc"])
    evidence = {}

    if messenger:
        emit(f"Looking up {messenger} chat messages around the event…")
        chat = get_chat_context(sess, user_locator, event_time, messenger)
        if not chat:
            emit("No chat messages nearby, widening to +/-30min…")
            chat = get_chat_context(sess, user_locator, event_time, messenger, window_minutes=30)
        if chat:
            emit(f"Found {len(chat)} chat message(s).")
            evidence["chat_messages"] = chat
        else:
            emit("No chat messages found.")
    else:
        emit("Looking up window/screen activity around the event…")
        window = get_window_context(sess, user_locator, event_time)
        if not window:
            emit("No window activity nearby, widening to +/-30min…")
            window = get_window_context(sess, user_locator, event_time, window_minutes=30)
        if window:
            emit(f"Found {len(window)} window-activity record(s).")
            evidence["window_activity"] = window
        else:
            emit("No window activity found.")

    if cancel_event is not None and cancel_event.is_set():
        raise ollama_client.Cancelled()

    screenshots = get_screenshot_evidence(sess, user_locator, event_time, on_progress=on_progress,
                                           vision_model=vision_model, cancel_event=cancel_event)
    if screenshots:
        evidence["screenshot_descriptions"] = screenshots

    if cancel_event is not None and cancel_event.is_set():
        raise ollama_client.Cancelled()

    content_assessment = get_file_content_evidence(event, on_progress=on_progress)
    if content_assessment:
        evidence["file_content_analysis"] = [content_assessment]

    return evidence


def strip_image_bytes(evidence_by_kind):
    out = {}
    for kind, items in evidence_by_kind.items():
        out[kind] = [{k2: v2 for k2, v2 in item.items() if k2 != "image_bytes"} for item in items]
    return out


def persist_and_strip_images(evidence_by_kind, user_locator):
    """Writes screenshot_descriptions' image_bytes to disk (once, dedup'd by content
    hash so re-investigating the same event doesn't duplicate files) and replaces
    them with an "image_file" key the API can serve statically. Keeps the SQLite DB
    to text/JSON only — screenshots stay as plain files on disk.
    """
    SCREENSHOT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out = {}
    for kind, items in evidence_by_kind.items():
        new_items = []
        for item in items:
            item = dict(item)
            image_bytes = item.pop("image_bytes", None)
            if image_bytes:
                digest = hashlib.sha256(image_bytes).hexdigest()[:16]
                fname = f"{user_locator}_{digest}.jpg"
                fpath = SCREENSHOT_CACHE_DIR / fname
                if not fpath.exists():
                    fpath.write_bytes(image_bytes)
                item["image_file"] = fname
            new_items.append(item)
        out[kind] = new_items
    return out


TOOL_SCHEMA = [{
    "type": "function",
    "function": {
        "name": "query_dlp_database",
        "description": (
            "Run a read-only SQL SELECT query against the live EMP DLP database "
            "(PostgreSQL) to look up anything not already covered by the evidence "
            "you were given — e.g. this user's other recent file sends, their "
            "employee/department record, printed documents, internet searches, "
            "other messenger activity, file classification scores, etc.\n\n"
            "Key tables and their actual columns (all text/path fields are "
            "percent-encoded — e.g. use `file_path LIKE '%25PROJECTSRV%25'` style matches "
            "cautiously, prefer filtering by user_locator/time and reading results "
            "rather than pattern-matching encoded text):\n"
            "  treportfilesnd(user_locator, op_time, file_path, url, size_kb, app_desc, "
            "id_vocab, row_auto_increment) — file-send events. NOTE: the path/filename "
            "column is `file_path`, there is no `file_name` column.\n"
            "  treportappusage(user_locator, start_time, ws_app_title, ws_user_text, "
            "app_desc, url) — window titles + OCR'd visible text.\n"
            "  treportchats(user_locator, op_time, msg_type, messenger, user_uin, "
            "ws_text) — chat messages (msg_type 1=sent, 0=received).\n"
            "  tuserinfo(id, user_domain, user_name, fio, department) — employee "
            "directory; join on id = user_locator. Many users have no row here.\n"
            "  tvocabs(id, name) — EMP's built-in category list (id_vocab FK).\n"
            "  treportfileclassification(user_locator, op_time, ws_path, ws_desc, "
            "scores_json) — LLM classification scores, if the feature is enabled.\n"
            "  treportprinteddocs, treportinetsearches, treportfileops — similar "
            "shape to treportfilesnd/treportappusage (user_locator + a time column).\n"
            "SELECT/WITH only, single statement, no writes."
        ),
        "parameters": {
            "type": "object",
            "properties": {"sql": {"type": "string", "description": "A single read-only SQL SELECT statement"}},
            "required": ["sql"],
        },
    },
}]

SYSTEM_PROMPT = (
    "You are a DLP (data-loss-prevention) analyst assistant investigating one "
    "file-send event that an automated rule engine flagged for review. The event's "
    "user_locator field is the exact integer to filter any follow-up query by — use "
    "it directly (e.g. `WHERE user_locator = 1001`). Do not try to derive the user "
    "from a window-title computer name or app tag (e.g. '@NB0001') — that is not a "
    "valid user_locator value and queries built from it will always return nothing.\n\n"
    "You've been given contextual evidence gathered automatically (chat messages "
    "and/or on-screen window/screenshot activity from the same time window). If "
    "evidence_file_content_analysis is present, it is a direct AI reading of the "
    "ACTUAL file that was sent (its real extracted text/image content, not an "
    "inference from screenshots or window titles) — this is the strongest evidence "
    "available for this event and should be DECISIVE, not just heavily weighted. "
    "Specifically: if it says is_confidential=false AND related_to_company=false, "
    "that means a direct read of the real file found nothing sensitive and nothing "
    "connecting it to this company — your default verdict should be \"cleared\" "
    "unless you have a SPECIFIC, concrete reason from the evidence to override that "
    "(e.g. the content analysis itself flagged something borderline, or other "
    "evidence directly contradicts what the content analysis read). \"sent via a "
    "personal messaging app\" or \"the filename sounds work-related\" are NOT "
    "specific reasons on their own — the whole point of reading the actual content "
    "is that it supersedes exactly those kinds of surface-level, destination-based "
    "guesses. Do not flag an event as risky based on how it looks (destination, "
    "filename) once the actual content has been read and shown to be genuinely "
    "unrelated/non-sensitive — that would be ignoring your best evidence in favor "
    "of your weakest. If that's "
    "not enough to judge the event, use the query_dlp_database tool to look "
    "up anything else in the "
    "live DLP database that would help — e.g. is this destination/contact part of a "
    "recurring pattern for this user, what does their employee record say, did they "
    "search for anything related, is there file-classification data for this file. "
    "Don't guess when you can look it up, but don't over-query either — stop once you "
    "have enough to make a grounded call.\n\n"
    "If an \"analyst_precedent\" field is present, it contains real past events a "
    "human analyst has already reviewed and written a verdict + reasoning for, "
    "picked because they're similar to this one (same destination or category). "
    "Treat this as the closest thing you have to house rules — but read WHY each "
    "precedent was judged that way, not just its surface similarity (same "
    "destination/app) to this event. This team's actual precedent is content-driven: "
    "past confirmed_risk examples were confirmed_risk because a human confirmed the "
    "actual file content was sensitive or company-related (e.g. an internal SOP "
    "document, an employee list with real PII) — NOT merely because the destination "
    "was a personal messaging app. Past cleared examples were cleared specifically "
    "because content review showed the file was personal/unrelated to the company, "
    "even though the destination looked identical to a confirmed_risk case. A "
    "precedent example only transfers to THIS event if its underlying reason (content "
    "sensitivity) actually matches THIS event's content analysis result — a "
    "confirmed_risk precedent about a different, genuinely sensitive file does not "
    "make this file risky just because both went to the same app. Say explicitly in "
    "your reasoning which precedent you used and why its underlying reason does or "
    "doesn't apply here.\n\n"
    "Decide whether this looks like routine/benign activity or a genuine data-leak "
    "concern that a human analyst should look at closely. Reference the evidence you "
    "actually gathered — do not invent details. If evidence sources disagree or don't "
    "pin down specifics, say so honestly rather than guessing.\n\n"
    "When you are done investigating (with or without extra tool calls), respond with "
    "ONLY a JSON object (no tool call) with these exact keys:\n"
    '  "verdict": one of "cleared", "needs_human_review", "confirmed_risk"\n'
    '  "severity": one of "low", "medium", "high"\n'
    '  "reasoning": a short plain-language paragraph an analyst can read directly, '
    "referencing the specific evidence used (including anything you looked up yourself)"
)


def _ollama_chat(messages, model, tools=None, force_json=False, cancel_event=None):
    payload = {"model": model, "messages": messages, "think": False}
    if tools:
        payload["tools"] = tools
    if force_json:
        payload["format"] = "json"
    return ollama_client.stream_chat(OLLAMA_URL, payload, cancel_event=cancel_event, timeout=180)


def find_similar_precedent(event, limit=5):
    """Few-shot retrieval, NOT fine-tuning — see labeled_examples table comment in
    schema.sql for why. Looks up past analyst-written labels ("Feed to AI") most
    relevant to this event and returns them for inclusion in the prompt as
    precedent. Matching is deliberately simple and explainable (no embeddings/
    vector search infra here): exact app_desc match ranks above same
    destination_category, both rank above generic recent labels; results are
    capped small so precedent doesn't drown out the actual evidence.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """SELECT l.label_verdict, l.label_notes, l.app_desc, l.destination_category,
                      v.file_name, u.username AS labeled_by,
                      (CASE WHEN l.app_desc = ? THEN 2 WHEN l.destination_category = ? THEN 1 ELSE 0 END) AS relevance
               FROM labeled_examples l
               JOIN app_users u ON u.id = l.labeled_by
               LEFT JOIN event_verdicts v ON v.id = l.event_verdict_id
               ORDER BY relevance DESC, l.labeled_at DESC
               LIMIT ?;""",
            (event.get("app_desc"), event.get("destination_category"), limit),
        ).fetchall()
        # Prefer topical matches; only fall back to generic recent labels (capped at
        # 2) if the analyst hasn't labeled anything relevant yet at all — early on,
        # with few examples total, *something* is more useful than nothing, but
        # once there's real data, don't dilute it with unrelated precedent.
        relevant = [r for r in rows if r["relevance"] > 0]
        chosen = relevant if relevant else rows[:2]
        return [
            {
                "similar_file": r["file_name"], "similar_destination": r["app_desc"],
                "analyst_verdict": r["label_verdict"], "analyst_reasoning": r["label_notes"],
                "labeled_by": r["labeled_by"],
            }
            for r in chosen
        ]
    finally:
        conn.close()


def investigate_event(sess, event, on_progress=None, reasoning_model: str = None,
                       vision_model: str = None, cancel_event=None):
    """Returns dict: verdict, severity, reasoning, evidence_by_kind, extra_queries.
    Raises ollama_client.Cancelled if cancel_event fires mid-investigation — callers
    (runner.run_analyze_job) are expected to catch it and mark the job cancelled
    rather than treating it as a failure.

    reasoning_model/vision_model let a caller pick a lighter/heavier model per
    investigation (e.g. a quick pass vs a deep one) — defaults to the standard
    32B pair if not given. on_progress(str), if given, receives a live step-by-step
    log entry at each stage (evidence gathering, each tool-call round, done).
    """
    def emit(msg):
        if on_progress:
            on_progress(msg)

    reasoning_model = reasoning_model or REASONING_MODEL
    baseline_evidence = gather_baseline_evidence(sess, event, on_progress=on_progress,
                                                  vision_model=vision_model, cancel_event=cancel_event)
    extra_queries = []

    user_content = {
        "event": {
            "user_locator": event["user_locator"],  # the exact integer to filter follow-up queries by —
                                                      # without this the model guesses at identifying the
                                                      # user from window-title text (e.g. a computer name)
                                                      # and burns tool-call rounds on queries that never match
            "event_time": event["event_time"],
            "file_name": event["file_name"],
            "destination_app": event["app_desc"],
            "destination_category": event["destination_category"],
            "rule_engine_flag_reason": event["reasoning"],
        },
    }
    for kind, items in strip_image_bytes(baseline_evidence).items():
        if kind == "file_content_analysis":
            # extracted_text_preview (up to 150k chars) is kept in the persisted
            # evidence for a human to inspect later, but content_analyze.py already
            # distilled it into summary/reasoning/risk_score — the top-level
            # reasoning model gets that distillation, not the raw text again, to
            # keep this prompt a reasonable size.
            items = [{k2: v2 for k2, v2 in item.items() if k2 != "extracted_text_preview"} for item in items]
        user_content[f"evidence_{kind}"] = items

    precedent = find_similar_precedent(event)
    if precedent:
        emit(f"Found {len(precedent)} similar analyst-labeled example(s) to use as precedent.")
        user_content["analyst_precedent"] = precedent

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(user_content, ensure_ascii=False, indent=2)},
    ]

    emit("Asking the reasoning model to weigh the evidence…")
    final = None
    for round_num in range(1, MAX_TOOL_ROUNDS + 1):
        if cancel_event is not None and cancel_event.is_set():
            raise ollama_client.Cancelled()
        msg = _ollama_chat(messages, reasoning_model, tools=TOOL_SCHEMA, cancel_event=cancel_event)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            # model is done — parse its final answer as JSON, forcing a retry with
            # format=json if it replied in prose instead
            content = msg.get("content", "").strip()
            try:
                final = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": "Respond with ONLY the JSON object described above, no other text."})
                msg2 = _ollama_chat(messages, reasoning_model, force_json=True, cancel_event=cancel_event)
                final = json.loads(msg2["content"])
            break

        messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": tool_calls})
        for call in tool_calls:
            if cancel_event is not None and cancel_event.is_set():
                raise ollama_client.Cancelled()
            sql = call["function"]["arguments"].get("sql", "")
            emit(f"AI is looking up extra data (round {round_num}): {sql[:140]}")
            if not is_safe_select(sql):
                result_text = "ERROR: only single read-only SELECT/WITH statements are allowed."
                row_count = 0
            else:
                try:
                    cols, rows, _ = k.run_sql(sess, sql)
                    rows = rows[:MAX_ROWS_RETURNED]
                    result_text = json.dumps({"columns": cols, "rows": rows}, ensure_ascii=False, default=str)
                    row_count = len(rows)
                except Exception as e:
                    result_text = f"ERROR: {e}"
                    row_count = 0
            emit(f"  → {row_count} row(s) returned.")
            extra_queries.append({"sql": sql, "row_count": row_count})
            messages.append({"role": "tool", "content": result_text})
    else:
        final = {
            "verdict": "needs_human_review", "severity": event.get("severity", "medium"),
            "reasoning": f"Investigation hit the {MAX_TOOL_ROUNDS}-query limit without reaching a "
                         "conclusion — needs a human to finish the analysis.",
        }

    emit(f"Done: {final['verdict']} ({final['severity']}).")
    return {
        "verdict": final["verdict"], "severity": final["severity"], "reasoning": final["reasoning"],
        "evidence_by_kind": baseline_evidence, "extra_queries": extra_queries,
    }
