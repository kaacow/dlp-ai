"""Destination classification table for file-send `app_desc` values.

This is intentionally a plain editable dict, not a database table, so the security
team can tune it without touching the SQLite schema. Any app_desc not listed here
falls through to UNCATEGORIZED (see rule_engine.py) — logged, never silently
auto-cleared.

The entries below are illustrative. Replace INTERNAL_DOMAIN_SUFFIXES and the
"internal" / "no_check" sets with your own organisation's reviewed values (or load
them from a file via DLP_INTERNAL_DOMAINS, comma-separated).
"""
import os
import re

INTERNAL_DOMAIN_SUFFIXES = [
    d.strip().lower()
    for d in os.environ.get("DLP_INTERNAL_DOMAINS", "example-corp.com,examplecorp.sharepoint.com,examplecorp-my.sharepoint.com").split(",")
    if d.strip()
]

# category -> set of exact app_desc values (case-sensitive as seen in the source data)
DESTINATION_CATEGORIES = {
    "internal": {
        "Microsoft Outlook", "Microsoft Teams", "Windows Explorer",
        "outlook.office.com", "outlook.office365.com", "teams.cloud.microsoft",
        "intranet.example-corp.com", "wiki.example-corp.com",
        "examplecorp.sharepoint.com", "examplecorp-my.sharepoint.com",
    },
    "social_media": {"instagram.com", "x.com"},
    # Looks like "OneDrive" but is Microsoft's *personal/consumer* cloud, not the
    # company's OneDrive-for-Business tenant. Do NOT treat as approved storage.
    "personal_cloud_storage": {
        "onedrive.live.com", "drive.google.com", "drive.usercontent.google.com",
        "mail.google.com", "photos.google.com", "Microsoft OneDrive", "dropbox.com",
    },
    "messaging_personal": {
        "web.whatsapp.com", "whatsapp.com", "web.telegram.org", "Telegram Desktop",
    },
    # Third-party generative-AI tools: a genuine leak vector, not a novelty.
    "ai_tools": {
        "chatgpt.com", "claude.ai", "gemini.google.com", "aistudio.google.com",
        "notebooklm.google.com", "colab.research.google.com",
    },
    "file_transfer_sites": {"wetransfer.com", "sendspace.com"},
    # External partner/vendor tenants: legitimate exchange is plausible, but it is
    # still external, so it is not blanket auto-cleared like "internal".
    "third_party_vendor_cloud": {"partner-a.sharepoint.com", "consultancy-b.sharepoint.com"},
    "social_marketing": set(),
    # Not a network destination at all — local folder copy / USB copy. Its own
    # category because the risk model differs (uncontrolled physical media).
    "removable_or_local": {"CopyToFlash"},
    # Explicitly reviewed and excluded from ANY scrutiny (never escalates, content
    # analysis never runs). Distinct from "internal" (an approved company channel).
    # Never silently expand this list: unreviewed destinations default to scrutiny.
    "no_check": {
        # browsers / auth chrome — app_desc noise, not a real destination
        "Microsoft Edge", "Microsoft Edge WebView2", "Google Chrome",
        "about", "login.microsoftonline.com", "Microsoft Excel", "Adobe Acrobat",
        # local/known network hosts
        "localhost",
        # file-conversion / utility sites
        "ilovepdf.com", "smallpdf.com", "tinypng.com", "canva.com", "imgur.com",
        # job search / recruiting
        "linkedin.com", "indeed.com",
        # social / marketing / video
        "facebook.com", "youtube.com", "ads.google.com",
        # local folder copy (not a network exfil path) — USB (CopyToFlash) still checked
        "CopyToSelectedFolder",
    },
}

# app_desc -> category, built once at import time
_APP_DESC_TO_CATEGORY = {
    app: cat for cat, apps in DESTINATION_CATEGORIES.items() for app in apps
}


def classify_destination(app_desc: str, url: str = "") -> str:
    """Return a destination_category string for an app_desc value."""
    if app_desc in _APP_DESC_TO_CATEGORY:
        return _APP_DESC_TO_CATEGORY[app_desc]

    lowered = (app_desc or "").lower()
    for suffix in INTERNAL_DOMAIN_SUFFIXES:
        if suffix in lowered:
            return "internal"

    # internal IP address (RFC1918) as app_desc
    if re.fullmatch(r"(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)[\d.]+", app_desc or ""):
        return "internal"

    return "uncategorized"
