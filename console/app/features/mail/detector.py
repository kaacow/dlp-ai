"""Detection rules for outgoing mail, ported from the old Exchange-based
`self-email/server.py` tool's `compute_score`/`similarity` logic — no Azure AD
lookup needed here (unlike that tool), since the Mails report's `User` cell
already gives the sender's full name for free.

Two mutually-exclusive rules (split by recipient domain), matching what the user
described wanting to check: mail to an external address whose local-part looks
like the sender's own name (a personal account), or mail sent straight to the
sender's own corporate address (no reason to email yourself internally).

self_corporate additionally requires (per the user 2026-07-24): the recipient
IS the sender (username-in-domain equality, same proxy used since there's no
raw sender email in the report) AND the mail had exactly one recipient total —
a self-send that was also cc'd/bcc'd to someone else doesn't count, since that's
no longer "sending it to no one but myself"."""
import re
from difflib import SequenceMatcher

from .domains import SELF_CORPORATE_DOMAINS, is_internal_domain

DEFAULT_THRESHOLD = 0.5


def normalize_text(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"[^a-z]", "", str(s).lower())


def extract_email_username(email: str) -> str:
    if not email or "@" not in email:
        return ""
    return email.lower().strip().split("@")[0]


def get_domain(email: str) -> str:
    email = (email or "").strip().lower()
    return email.split("@")[1] if "@" in email else ""


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def name_parts(name: str) -> list[str]:
    return re.findall(r"[a-z]+", (name or "").lower())


def compute_score(sender_name: str, email_user: str) -> float:
    """Exact port of the original detection logic."""
    sender_norm = normalize_text(sender_name)
    email_norm = normalize_text(email_user)
    if not sender_norm or not email_norm:
        return 0.0
    score = similarity(sender_norm, email_norm)
    for p in name_parts(sender_name):
        if len(p) > 2 and p in email_norm:
            score += 0.15
    return min(score, 1.0)


def classify(mail: dict, threshold: float = DEFAULT_THRESHOLD) -> dict | None:
    """mail: one dict from mail_report.parse_mail_rows (must include
    recipient_count — how many total recipients this mail had). Returns
    {"match_type": ..., "similarity_score": ...} or None if it doesn't match
    either rule."""
    recipient_email = mail["recipient_email"]
    recipient_domain = get_domain(recipient_email)
    if not recipient_domain:
        return None

    if is_internal_domain(recipient_domain):
        if (
            recipient_domain in SELF_CORPORATE_DOMAINS
            and mail.get("recipient_count", 1) == 1
            and extract_email_username(recipient_email) == (mail["sender_username"] or "").lower()
        ):
            return {"match_type": "self_corporate", "similarity_score": 1.0}
        return None

    score = compute_score(mail["sender_fullname"], extract_email_username(recipient_email))
    if score >= threshold:
        return {"match_type": "personal_domain_match", "similarity_score": round(score, 3)}
    return None
