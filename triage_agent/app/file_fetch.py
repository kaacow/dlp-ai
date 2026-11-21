"""Fetches the actual saved-copy bytes for a sent file via `action=getfile`, same
relative-href-resolution trick as screenshots.py's fetch_fullsize() — the href
EMP puts in report HTML is authoritative, don't try to reconstruct the
filepath query param yourself (report_filesend.py's docstring has the full story).

Unlike Track D's file_fetch.py (which decodes straight to text, since it only ever
dealt with code files), this hands back raw bytes only — content_extract.py handles
turning those bytes into analyzable text/images for whatever file type they are.
"""
MAX_CONTENT_BYTES = 100_000_000  # raised from 15MB 2026-08-26 — confirmed live real
                                  # employee sends up to ~52MB (order-transfer xlsx
                                  # exports); the old 15MB cap silently truncated
                                  # them via content[:MAX_CONTENT_BYTES], corrupting
                                  # the zip structure of every .xlsx/.pptx over that
                                  # size (9 real files hit this in one backfill run,
                                  # all failing with "not a zip file"/"Package not
                                  # found" — indistinguishable from real corruption
                                  # without checking size). extract.py applies its
                                  # own tighter per-format content caps on top of this.


class ContentTooLargeError(Exception):
    """Raised instead of silently truncating — a truncated binary file (zip-based
    .xlsx/.docx/.pptx, or any other binary format) is corrupted, not just
    incomplete, so silently slicing bytes produced a real, confirmed data-quality
    bug rather than a graceful degradation. Fail loud instead."""
    pass


def fetch_file_bytes(session, base: str, href: str) -> bytes:
    url = f"{base}/cgi-report.exe?" + href.split("?", 1)[1]
    resp = session.get(url)
    resp.raise_for_status()
    if len(resp.content) > MAX_CONTENT_BYTES:
        raise ContentTooLargeError(
            f"File is {len(resp.content)} bytes, over the {MAX_CONTENT_BYTES}-byte cap — "
            "not fetched to avoid corrupting it via truncation."
        )
    return resp.content
