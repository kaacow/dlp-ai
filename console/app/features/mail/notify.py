"""Telegram bot notifications — the channel the user picked (2026-08-04) for
"Exchange session expired, please log in manually" alerts, since there's no
email/Slack integration on the GPU workstation. Reads TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID
from .env using the same tiny `_load_env()` pattern emp_sql.py already uses
(copied rather than imported, matching this codebase's convention of small
self-contained modules)."""
import os
from pathlib import Path

import requests


def _load_env():
    env_path = Path(__file__).parent / ".env"
    env = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


_env = _load_env()
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", _env.get("TELEGRAM_BOT_TOKEN"))
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", _env.get("TELEGRAM_CHAT_ID"))


def send_telegram(text: str) -> bool:
    """Best-effort — a notification failure must never take down the run that
    triggered it, so this always catches and returns False rather than
    raising. Returns True only on a confirmed 200 from Telegram."""
    if not BOT_TOKEN or not CHAT_ID:
        print(f"[notify] Telegram not configured, message dropped: {text}")
        return False
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"[notify] Telegram send failed: {e}")
        return False


if __name__ == "__main__":
    import sys
    msg = sys.argv[1] if len(sys.argv) > 1 else "Mail detector: test notification."
    ok = send_telegram(msg)
    print("sent" if ok else "failed (see above)")
