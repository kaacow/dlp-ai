#!/usr/bin/env python3
"""Track C — investigation pipeline for events the Track B rule engine escalated.

Gathers context around an escalated file-send event, then asks a local reasoning
model (qwen3:32b via Ollama) for a plain-language verdict an analyst can act on.

Evidence sources, combined whenever available:
  - treportchats (SQL)      — for messaging_personal destinations (WhatsApp/
                               WebTelegram/YandexMessenger): actual message text +
                               contact identity around the event time.
  - treportappusage (SQL)    — window titles + ws_user_text (OCR'd/visible on-screen
                               text) around the event time — the same "search window
                               titles for the filename" step an analyst does by hand.
  - screenshots.py (web,     — actual screenshot images around the event time, read
    NOT SQL)                   by a vision model (qwen2.5vl:7b). See screenshots.py
                               for why this needs the *web report* flow, not a
                               database column, and why it currently only works for
                               one employee (svc_readonly is a deliberately scoped test
                               account, confirmed by the user — user_locator=1001,
                               jdoe). get_screenshot_evidence() returns []
                               for anyone else, so this degrades gracefully to
                               text-only evidence rather than failing.
"""
import argparse
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

import requests

import emp_sql as k
from screenshots import get_screenshot_evidence

DB_PATH = Path(__file__).parent.parent / "db" / "dlp_ai.sqlite3"
OLE_EPOCH = datetime(1899, 12, 30)
OLLAMA_URL = "http://localhost:11434/api/chat"
REASONING_MODEL = "qwen3:32b"

MESSAGING_DESTINATION_TO_MESSENGER = {
    "web.whatsapp.com": "WhatsApp", "web.whatsapp.comcan": "WhatsApp",
    "whatsapp.com": "WhatsApp", "WhatsApp.Root": "WhatsApp",
    "web.telegram.org": "WebTelegram", "Telegram Desktop": "WebTelegram",
    "YandexMessenger": "YandexMessenger",
}


def to_ole(dt: datetime) -> float:
    return (dt - OLE_EPOCH).total_seconds() / 86400.0


def get_chat_context(sess, user_locator, event_time: datetime, messenger, window_minutes=5):
    begin, end = to_ole(event_time - timedelta(minutes=window_minutes)), to_ole(event_time + timedelta(minutes=window_minutes))
    query = f"""
        SELECT op_time, msg_type, user_uin, ws_text
        FROM treportchats
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
            pass  # already clean or not the expected mojibake pattern
        out.append({
            "time": rec["op_time"], "direction": "sent" if rec["msg_type"] == 1 else "received",
            "contact": rec["user_uin"], "text": text,
        })
    return out


def get_window_context(sess, user_locator, event_time: datetime, window_minutes=5):
    begin, end = to_ole(event_time - timedelta(minutes=window_minutes)), to_ole(event_time + timedelta(minutes=window_minutes))
    query = f"""
        SELECT start_time, ws_app_title, ws_user_text
        FROM treportappusage
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


def strip_image_bytes(evidence_by_kind):
    """screenshot_descriptions items carry raw image_bytes for report-building —
    strip them before JSON-serializing (LLM prompt or DB storage), both because
    bytes aren't JSON-serializable and because the reasoning model only needs the
    text description, not the pixels."""
    out = {}
    for kind, items in evidence_by_kind.items():
        out[kind] = [{k: v for k, v in item.items() if k != "image_bytes"} for item in items]
    return out


def call_reasoning_model(event, evidence_by_kind):
    system_prompt = (
        "You are a DLP (data-loss-prevention) analyst assistant. You are given one "
        "file-send event that an automated rule engine flagged for review, plus "
        "contextual evidence gathered from the same time window — possibly from "
        "multiple sources (chat messages, on-screen window activity, and/or "
        "vision-model descriptions of actual screenshots). Decide whether this looks "
        "like routine/benign activity or a genuine data-leak concern that a human "
        "analyst should look at closely. Be concrete and reference the evidence you "
        "were given — do not invent details not present in the evidence. If sources "
        "disagree or the evidence doesn't pin down specifics (e.g. multiple "
        "simultaneous chats, so you can't be sure which one received the file), say "
        "so honestly rather than guessing. If the evidence is too thin to judge, say "
        "so honestly rather than guessing.\n\n"
        "Respond with ONLY a JSON object with these exact keys:\n"
        '  "verdict": one of "cleared", "needs_human_review", "confirmed_risk"\n'
        '  "severity": one of "low", "medium", "high"\n'
        '  "reasoning": a short plain-language paragraph an analyst can read directly, '
        "referencing the specific evidence used"
    )
    user_prompt = {
        "event": {
            "file_name": event["file_name"],
            "destination_app": event["app_desc"],
            "destination_category": event["destination_category"],
            "rule_engine_flag_reason": event["reasoning"],
        },
    }
    for kind, evidence in strip_image_bytes(evidence_by_kind).items():
        user_prompt[f"evidence_{kind}"] = evidence
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": REASONING_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_prompt, ensure_ascii=False, indent=2)},
            ],
            "stream": False,
            "format": "json",
            "think": False,
        },
        timeout=120,
    )
    resp.raise_for_status()
    content = resp.json()["message"]["content"]
    return json.loads(content)


def investigate_event(sess, event):
    event_time = datetime.strptime(event["event_time"], "%Y-%m-%d %H:%M:%S")
    messenger = MESSAGING_DESTINATION_TO_MESSENGER.get(event["app_desc"])
    user_locator = event["user_locator"]

    evidence_by_kind = {}

    if messenger:
        chat_evidence = get_chat_context(sess, user_locator, event_time, messenger)
        if not chat_evidence:
            # widen the window once if nothing found nearby, per the manual triage procedure
            chat_evidence = get_chat_context(sess, user_locator, event_time, messenger, window_minutes=30)
        if chat_evidence:
            evidence_by_kind["chat_messages"] = chat_evidence
    else:
        window_evidence = get_window_context(sess, user_locator, event_time)
        if not window_evidence:
            window_evidence = get_window_context(sess, user_locator, event_time, window_minutes=30)
        if window_evidence:
            evidence_by_kind["window_activity"] = window_evidence

    # Best-effort — returns [] and never raises if this user is outside the
    # account's screenshot-access scope (see screenshots.py).
    screenshot_evidence = get_screenshot_evidence(sess, user_locator, event_time)
    if screenshot_evidence:
        evidence_by_kind["screenshot_descriptions"] = screenshot_evidence

    if not evidence_by_kind:
        return {
            "verdict": "needs_human_review", "severity": event.get("severity", "medium"),
            "reasoning": "No chat/window-activity/screenshot evidence found within "
                         "+/-30min of the event — not enough context for an automated "
                         "call, needs a human look.",
            "evidence_by_kind": {},
        }

    result = call_reasoning_model(event, evidence_by_kind)
    result["evidence_by_kind"] = evidence_by_kind
    return result


def load_pending_escalations(conn, limit):
    cur = conn.execute(
        """SELECT id, user_locator, event_time, file_name, app_desc, destination_category, reasoning, severity
           FROM event_verdicts
           WHERE verdict='escalate' AND model_version IS NULL
           ORDER BY event_time DESC LIMIT ?;""",
        (limit,),
    )
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def store_investigation(conn, verdict_id, result):
    conn.execute(
        """UPDATE event_verdicts SET
             verdict=?, severity=?, reasoning=?, screenshots_used=?, model_version=?,
             reviewed_at=datetime('now')
           WHERE id=?;""",
        (
            result["verdict"], result["severity"], result["reasoning"],
            json.dumps(strip_image_bytes(result["evidence_by_kind"]), ensure_ascii=False),
            REASONING_MODEL, verdict_id,
        ),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50, help="max escalated events to investigate this run")
    args = ap.parse_args()

    conn = sqlite3.connect(DB_PATH)
    pending = load_pending_escalations(conn, args.limit)
    print(f"{len(pending)} escalated events pending investigation")

    sess = k.get_session()
    for event in pending:
        print(f"\n--- verdict_id={event['id']} user={event['user_locator']} file={event['file_name']} ---")
        result = investigate_event(sess, event)
        print(f"  -> {result['verdict']} ({result['severity']}): {result['reasoning'][:200]}")
        store_investigation(conn, event["id"], result)
        conn.commit()

    conn.close()


if __name__ == "__main__":
    main()
