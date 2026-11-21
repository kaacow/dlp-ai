"""Small-model verdict for one already-flagged mail. Unlike Track D's scanner.py,
there's no regex prefilter or judgment call to make about *whether* something is
worth flagging — `detector.py`'s rule match already decided that. This step's only
job is a one-line read of the actual content (body + attachment names) so the
human reviewer has a hint before opening the .msg file themselves.
"""
import json

from . import ollama_client

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3.1:8b"

SYSTEM_PROMPT = (
    "You are a DLP (data-loss-prevention) analyst assistant. You are given metadata "
    "and content for ONE outgoing mail that a rule-based check already flagged as a "
    "likely self-send (an employee mailing something to what looks like their own "
    "personal address, or to their own corporate address). Each attachment includes "
    "its actual extracted content in its \"text\" field where available (spreadsheets "
    "are given as CSV per sheet, documents/PDFs as plain text) — READ IT, don't just "
    "mention the filename. If \"text\" is null, either the format isn't supported for "
    "extraction (say so briefly if relevant) or it's a short note explaining why it "
    "couldn't be read (e.g. password-protected). Your job is to write ONE short "
    "sentence (max ~40 words) giving the human reviewer a quick read on this specific "
    "mail — what the body AND attachment content actually contain, and call out "
    "anything that looks notably sensitive (financial data, contracts, credentials, "
    "customer data, PII). Do NOT write a report or repeat the metadata back — the "
    "reviewer already sees it and will open the file themselves; just give your read "
    "on the actual content.\n\n"
    'Respond with ONLY a JSON object: {"summary": <string, one short sentence>}.'
)


def build_user_content(mail: dict, match: dict, content: dict) -> str:
    payload = {
        "sender_fullname": mail["sender_fullname"],
        "recipient_email": mail["recipient_email"],
        "match_type": match["match_type"],
        "similarity_score": match["similarity_score"],
        "subject": mail["subject"],
        "attachments": content["attachments"],
        "body_truncated": content["truncated"],
        "body": content["body"],
    }
    return json.dumps(payload, ensure_ascii=False)


def analyze(mail: dict, match: dict, content: dict, model: str = None, cancel_event=None) -> tuple[str, str]:
    """Returns (summary, model_used)."""
    model = model or DEFAULT_MODEL
    message = ollama_client.stream_chat(
        OLLAMA_URL,
        {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_content(mail, match, content)},
            ],
            "format": "json",
            "think": False,
        },
        cancel_event=cancel_event, timeout=120,
    )
    try:
        summary = json.loads(message["content"]).get("summary", "").strip()
    except (json.JSONDecodeError, ValueError, KeyError, AttributeError):
        summary = message.get("content", "").strip()[:300]
    return summary or "(no summary produced)", model
