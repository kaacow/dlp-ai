"""Fetches the actual `.msg` bytes for a captured mail via `action=getfile` (same
relative-href-resolution trick as `file_fetch.fetch_file_bytes` in the Track D
content-scan app — the href EMP puts in the report HTML is authoritative,
don't try to reconstruct the filepath query param yourself), and parses it with
`extract_msg` (OLE-format Outlook message file) for the AI analyzer's body +
attachment input.

Attachment CONTENT extraction (2026-08-05): previously this only ever passed
attachment *filenames* to the AI analyzer, never the actual file content — the
user tested with a real Excel attachment and confirmed the AI had no idea
what was in it. `_extract_attachment_text()` now reads common office/text
formats (xlsx/xls/csv/txt/docx/pdf) into plain text so the analyzer prompt
actually includes what's inside, not just the filename. Needs `openpyxl`,
`xlrd`, `python-docx`, `pypdf` in the venv (not in the original build).
"""
import io
import tempfile
from pathlib import Path

import extract_msg

from . import emp_sql as k

MAX_BODY_CHARS = 3000  # small model, short verdict — keep the prompt light
MAX_ATTACHMENT_CHARS = 3000  # per-attachment cap on extracted text
MAX_ATTACHMENT_TOTAL_CHARS = 6000  # combined cap across all attachments


def fetch_mail_bytes(session, href: str) -> bytes:
    url = f"{k.BASE}/cgi-report.exe?" + href.split("?", 1)[1]
    resp = session.get(url)
    resp.raise_for_status()
    return resp.content


def _read_excel(data: bytes, engine: str) -> str:
    import pandas as pd
    sheets = pd.read_excel(io.BytesIO(data), sheet_name=None, engine=engine)
    parts = []
    for name, df in sheets.items():
        parts.append(f"--- sheet: {name} ---\n{df.to_csv(index=False)}")
    return "\n".join(parts)


def _read_docx(data: bytes) -> str:
    import docx
    d = docx.Document(io.BytesIO(data))
    paragraphs = [p.text for p in d.paragraphs if p.text.strip()]
    for table in d.tables:
        for row in table.rows:
            paragraphs.append(" | ".join(cell.text for cell in row.cells))
    return "\n".join(paragraphs)


def _read_pdf(data: bytes) -> str:
    import pypdf
    reader = pypdf.PdfReader(io.BytesIO(data))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def _extract_attachment_text(filename: str, data: bytes) -> str | None:
    """Returns extracted plain text, or a short note explaining why content
    couldn't be read (e.g. password-protected), or None for formats this
    doesn't attempt to parse (images, archives, etc — filename/size alone
    still reaches the analyzer, just no content)."""
    ext = Path(filename or "").suffix.lower()
    try:
        if ext in (".xlsx", ".xlsm"):
            return _read_excel(data, "openpyxl")
        if ext == ".xls":
            return _read_excel(data, "xlrd")
        if ext in (".csv", ".txt", ".log"):
            return data.decode("utf-8", errors="replace")
        if ext == ".docx":
            return _read_docx(data)
        if ext == ".pdf":
            return _read_pdf(data)
    except Exception as e:
        return f"(could not read this {ext or 'file'} attachment — possibly password-protected or corrupt: {e})"
    return None


def parse_msg(raw_bytes: bytes) -> dict:
    """Returns {"body": str, "attachments": [{"filename", "size_bytes", "text"}],
    "truncated": bool}. extract_msg needs an actual file path (not a
    file-like object), so this writes to a temp file and always cleans it up."""
    tmp = tempfile.NamedTemporaryFile(suffix=".msg", delete=False)
    try:
        tmp.write(raw_bytes)
        tmp.close()
        msg = extract_msg.Message(tmp.name)
        try:
            body = (msg.body or "").strip()
            attachments = []
            total_chars = 0
            for a in msg.attachments:
                filename = a.longFilename or a.shortFilename or "(unnamed attachment)"
                data = a.data if isinstance(a.data, bytes) else None
                text = _extract_attachment_text(filename, data) if data else None
                if text and total_chars < MAX_ATTACHMENT_TOTAL_CHARS:
                    budget = min(MAX_ATTACHMENT_CHARS, MAX_ATTACHMENT_TOTAL_CHARS - total_chars)
                    text = text[:budget]
                    total_chars += len(text)
                elif text:
                    text = None  # combined budget already spent
                attachments.append({
                    "filename": filename,
                    "size_bytes": len(data) if data else None,
                    "text": text,
                })
        finally:
            msg.close()
        truncated = len(body) > MAX_BODY_CHARS
        return {"body": body[:MAX_BODY_CHARS], "attachments": attachments, "truncated": truncated}
    finally:
        Path(tmp.name).unlink(missing_ok=True)
