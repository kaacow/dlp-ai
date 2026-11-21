"""Track B — rule-engine triage layer for treportfilesnd events.

Buckets each file-send event into one of:
  auto_clear     — cleared automatically, not worth an analyst's time
  baseline_match — matches a pre-approved recurring pattern (dlp_ai.baseline_exceptions)
  spot_check     — needs a quick human glance (1-2 screenshots), not a full investigation
  escalate       — needs full investigation (Track C: chat text / screenshots / vision model)

Encodes the manual triage heuristics from the infosec team (see
dlp_ai_project_handoff.md "Analyst workflow" section) plus destination categories
pulled from real live data (destinations.py).
"""
import re
import ntpath
from destinations import classify_destination

DOC_EXTS = {"doc", "docx", "pdf", "xls", "xlsx", "csv", "ppt", "pptx", "rtf",
            "odt", "ods", "odp", "txt"}
IMAGE_EXTS = {"jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff"}

# Multilingual risk keywords (English plus a few other languages — filenames are
# often not in English, e.g. "müqavilə" = contract, "məxfi" = confidential).
# Deliberately filename-only / cheap — content-level checks belong to Track C.
#
# Matched with \b word-boundary regex, not plain substring containment — a plain
# `"nda" in filename.lower()` was found (via live-data testing) to false-positive on
# "panda.jpg", "komanda.jfif" (AZ/RU for "team"), and "...Standard...". Keep new
# keywords short-and-ambiguous ones (3-4 letters) especially suspect; test against
# real filenames before adding.
RISK_KEYWORDS = [
    "contract", "agreement", "invoice", "confidential", "salary", "passport",
    "statement", "bank", "ssn", "NDA",
    "müqavilə", "razılaşma", "məxfi", "maaş", "əmək haqqı", "pasport", "faktura",
    "договор", "конфиденциально", "зарплата", "паспорт", "счет",
]
_RISK_KEYWORD_RES = [re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE | re.UNICODE)
                      for kw in RISK_KEYWORDS]

WHATSAPP_MEDIA_RE = re.compile(r"^WhatsApp (Image|Video)", re.IGNORECASE)


def _basename_and_ext(file_path: str):
    name = ntpath.basename(file_path or "")
    # EMP appends a hash suffix on some rows, e.g. "foo.pdf*3DE9AC86" — strip it
    name = re.split(r"\*[0-9A-Fa-f]{6,}$", name)[0]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return name, ext


def _has_risk_keyword(filename: str) -> bool:
    return any(rx.search(filename) for rx in _RISK_KEYWORD_RES)


def check_baseline(user_locator, app_desc, destination_category, baseline_index):
    """baseline_index: dict[(user_locator, destination_or_category)] -> exception row."""
    key1 = (user_locator, app_desc)
    key2 = (user_locator, destination_category)
    return baseline_index.get(key1) or baseline_index.get(key2)


def classify_event(event: dict, baseline_index: dict) -> dict:
    """event: dict with user_locator, file_path, url, app_desc, size_kb, id_vocab.
    Returns dict with destination_category, verdict, severity, reasoning, matched_rule.
    """
    app_desc = event.get("app_desc") or ""
    file_path = event.get("file_path") or ""
    user_locator = event.get("user_locator")
    id_vocab = event.get("id_vocab")

    destination_category = classify_destination(app_desc, event.get("url") or "")
    filename, ext = _basename_and_ext(file_path)
    is_doc = ext in DOC_EXTS
    is_image = ext in IMAGE_EXTS
    has_risk_kw = _has_risk_keyword(filename)

    result = dict(destination_category=destination_category)

    # 0. Pre-approved recurring pattern always wins first.
    baseline = check_baseline(user_locator, app_desc, destination_category, baseline_index)
    if baseline:
        result.update(
            verdict="baseline_match", severity="low",
            reasoning=f"Matches approved baseline exception (id={baseline.get('id')})",
            matched_rule="baseline_exception",
        )
        return result

    if destination_category == "internal":
        result.update(
            verdict="auto_clear", severity="low",
            reasoning=f"Internal/approved destination ({app_desc})",
            matched_rule="internal_destination",
        )
        return result

    if destination_category == "messaging_personal":
        if WHATSAPP_MEDIA_RE.match(filename):
            result.update(
                verdict="auto_clear", severity="low",
                reasoning="Filename matches 'WhatsApp Image/Video *' — inbound/downloaded content, not an outbound leak",
                matched_rule="whatsapp_media_inbound_pattern",
            )
        elif is_doc and has_risk_kw:
            result.update(
                verdict="escalate", severity="high",
                reasoning=f"Document sent to personal messenger ({app_desc}) with risk keyword in filename '{filename}'",
                matched_rule="messenger_doc_risk_keyword",
            )
        elif is_image:
            result.update(
                verdict="spot_check", severity="low",
                reasoning=f"Image sent to personal messenger ({app_desc}) — generally low risk, quick glance only",
                matched_rule="messenger_image",
            )
        else:
            result.update(
                verdict="spot_check", severity="medium",
                reasoning=f"File sent to personal messenger ({app_desc}), no strong signal either way",
                matched_rule="messenger_default",
            )
        return result

    if destination_category == "ai_tools":
        if is_doc and has_risk_kw:
            result.update(
                verdict="escalate", severity="high",
                reasoning=f"Document with risk keyword in filename '{filename}' uploaded to third-party AI tool ({app_desc})",
                matched_rule="ai_tool_doc_risk_keyword",
            )
        elif is_doc:
            result.update(
                verdict="spot_check", severity="medium",
                reasoning=f"Document uploaded to third-party AI tool ({app_desc}) — no data-retention guarantee from vendor",
                matched_rule="ai_tool_doc",
            )
        else:
            result.update(
                verdict="spot_check", severity="low",
                reasoning=f"Non-document file uploaded to third-party AI tool ({app_desc})",
                matched_rule="ai_tool_other",
            )
        return result

    if destination_category == "personal_cloud_storage":
        result.update(
            verdict="spot_check", severity="medium",
            reasoning=f"File sent to personal (non-corporate) cloud storage ({app_desc}) — only corporate OneDrive/SharePoint is approved",
            matched_rule="personal_cloud_storage",
        )
        return result

    if destination_category == "file_transfer_sites":
        if is_image:
            result.update(
                verdict="spot_check", severity="low",
                reasoning=f"Image sent via file-transfer site ({app_desc}) — marketing/design commonly does this legitimately",
                matched_rule="file_transfer_image",
            )
        elif is_doc and has_risk_kw:
            result.update(
                verdict="escalate", severity="high",
                reasoning=f"Document with risk keyword in filename '{filename}' sent via third-party transfer site ({app_desc})",
                matched_rule="file_transfer_doc_risk_keyword",
            )
        else:
            result.update(
                verdict="spot_check", severity="medium",
                reasoning=f"File sent via third-party transfer site ({app_desc})",
                matched_rule="file_transfer_default",
            )
        return result

    if destination_category == "third_party_vendor_cloud":
        result.update(
            verdict="spot_check", severity="medium",
            reasoning=f"File sent to external vendor/partner cloud tenant ({app_desc}) — plausibly legitimate but not pre-approved",
            matched_rule="third_party_vendor_cloud",
        )
        return result

    if destination_category == "social_media":
        result.update(
            verdict="spot_check", severity="low",
            reasoning=f"File sent to personal social media ({app_desc})",
            matched_rule="social_media",
        )
        return result

    if destination_category == "social_marketing":
        result.update(
            verdict="spot_check", severity="low",
            reasoning=f"File sent via social/marketing platform ({app_desc})",
            matched_rule="social_marketing",
        )
        return result

    if destination_category == "removable_or_local":
        if has_risk_kw:
            result.update(
                verdict="escalate", severity="high",
                reasoning=f"Risk keyword in filename '{filename}' copied to removable media/local folder — destination is uncontrolled",
                matched_rule="removable_media_risk_keyword",
            )
        else:
            result.update(
                verdict="spot_check", severity="low",
                reasoning="Local folder/USB copy, no risk keyword in filename",
                matched_rule="removable_media_default",
            )
        return result

    # Fallback for anything not in destinations.py — never silently auto-clear.
    result.update(
        verdict="spot_check", severity="medium",
        reasoning=f"Unrecognized destination app_desc='{app_desc}' — not yet classified, needs config update",
        matched_rule="uncategorized_destination",
    )
    return result
