"""File content extraction: turns a downloaded file's bytes into a list of chunks,
each either plain text or an image that needs a vision model to read. Ported
unchanged from the File Analyzer app's extract.py (proven there across real
uploads) — same logic, just fed bytes pulled from EMP's saved-copy storage
instead of a user's browser upload."""
import csv
import io
import subprocess
import tempfile
from pathlib import Path

import fitz  # PyMuPDF
from docx import Document as DocxDocument
from openpyxl import load_workbook
from pptx import Presentation
from PIL import Image

TEXT_EXTS = {".txt", ".md", ".log", ".json", ".xml", ".yaml", ".yml"}
CSV_EXTS = {".csv", ".tsv"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp", ".tif", ".tiff"}
DOC_EXTS = {".pdf", ".docx", ".xlsx", ".pptx"}  # .xls is legacy-converted, see LEGACY_CONVERT_EXTS
# Legacy office formats that real-world sends still contain (e.g. old .doc, not
# .docx) that python-docx/openpyxl can't read directly — converted via a locally
# installed LibreOffice headless pass into a format the extractors above can read,
# rather than silently skipping content analysis for an entire format family.
LEGACY_CONVERT_EXTS = {".doc": ".docx", ".rtf": ".docx", ".odt": ".docx", ".ppt": ".pptx", ".xls": ".xlsx"}
LIBREOFFICE_TIMEOUT = 60

SUPPORTED_EXTS = TEXT_EXTS | CSV_EXTS | IMAGE_EXTS | DOC_EXTS | set(LEGACY_CONVERT_EXTS)

# EMP's own auth layer, not a real file — confirmed live (2026-08-25): a
# ~5.6-hour unattended download loop's EMP report portal session expired partway
# through, and `action=getfile` served a genuine, well-formed one-page PDF (HTTP
# 200, no error status at all) whose only content is this message. fitz.open()
# had no reason to reject it — it's a syntactically valid PDF — so it silently
# "extracted" successfully and got scored by the AI as if it were the real file.
# 99 of 199 rows in one run were entirely this placeholder. Checked here (post-
# extraction, on the resulting text) rather than at the raw-bytes/HTTP level,
# since the fake response is genuinely well-formed for at least the PDF case —
# there's no earlier signal to catch it on. Every caller of extract() (Track C's
# content_evidence.py, content_analyze.py, content_label_seed.py) gets this for
# free since they all route through here.
SESSION_EXPIRED_MARKER = "session has expired or finished"
SESSION_EXPIRED_MAX_LEN = 500  # a real document that happens to mention this
                                # phrase in passing would be far longer; only
                                # reject when it's essentially the WHOLE content


class SessionExpiredError(Exception):
    """Raised when downloaded bytes turn out to be EMP's session-expired
    placeholder, not the real file. Callers should refresh their EMP
    session and retry the download — this is not a real extraction failure."""
    pass


def _check_not_session_expired(chunks):
    combined = " ".join((c.text or "") for c in chunks if c.kind == "text").strip().lower()
    if SESSION_EXPIRED_MARKER in combined and len(combined) < SESSION_EXPIRED_MAX_LEN:
        raise SessionExpiredError(
            "Downloaded content is EMP's session-expired placeholder, not the real file — "
            "the EMP session needs to be refreshed and the download retried."
        )

# A PDF page with less real text than this is treated as a scan and rasterized
# for the vision model instead of trusting the (near-empty) extracted text layer.
MIN_TEXT_CHARS_PER_PAGE = 25

# Cap how many rows/slides/pages we walk per file so one gigantic spreadsheet
# doesn't stall the pipeline; the model gets a note that content was truncated.
MAX_XLSX_ROWS_PER_SHEET = 500
MAX_PPTX_SLIDES = 300
MAX_PDF_PAGES = 300


class Chunk:
    def __init__(self, kind, label, text=None, image_bytes=None):
        self.kind = kind  # "text" | "image"
        self.label = label
        self.text = text
        self.image_bytes = image_bytes


def _convert_legacy(file_path: str, target_ext: str, notes: list) -> str | None:
    """Runs `soffice --headless --convert-to` in an isolated user-profile dir (so
    concurrent conversions don't collide on LibreOffice's lock file) and returns the
    converted file's path, or None if conversion failed — callers fall back to a
    filename-only assessment rather than crashing the whole pipeline over one file."""
    out_dir = tempfile.mkdtemp(prefix="loconv_")
    profile_dir = tempfile.mkdtemp(prefix="loprofile_")
    try:
        subprocess.run(
            ["soffice", "--headless", "--norestore",
             f"-env:UserInstallation=file://{profile_dir}",
             "--convert-to", target_ext.lstrip("."), "--outdir", out_dir, file_path],
            check=True, capture_output=True, timeout=LIBREOFFICE_TIMEOUT,
        )
        converted = list(Path(out_dir).glob(f"*{target_ext}"))
        return str(converted[0]) if converted else None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError) as e:
        notes.append(f"Legacy-format conversion failed ({e}); analyzing filename/metadata only.")
        return None


def extract(file_path: str, filename: str):
    """Returns (chunks: list[Chunk], notes: list[str])."""
    ext = Path(filename).suffix.lower()
    notes = []

    if ext in TEXT_EXTS:
        chunks = _extract_text_file(file_path)
    elif ext in CSV_EXTS:
        chunks = _extract_csv(file_path)
    elif ext in IMAGE_EXTS:
        chunks = _extract_image(file_path, filename)
    elif ext == ".pdf":
        chunks = _extract_pdf(file_path, notes)
    elif ext == ".docx":
        chunks = _extract_docx(file_path)
    elif ext in (".xlsx", ".xlsm"):
        chunks = _extract_xlsx(file_path, notes)
    elif ext == ".pptx":
        chunks = _extract_pptx(file_path, notes)
    elif ext in LEGACY_CONVERT_EXTS:
        # .xls (old binary Excel, not .xlsx) added 2026-08-24 — openpyxl explicitly
        # does not support this format (confirmed live: InvalidFileException,
        # "please use xlrd... or convert to .xlsx"); it was previously grouped with
        # .xlsx/.xlsm and threw an uncaught exception for every real .xls file seen
        # during the content_labels backfill. Routed through the same LibreOffice
        # conversion path as .doc/.ppt/.rtf/.odt instead.
        target_ext = LEGACY_CONVERT_EXTS[ext]
        converted_path = _convert_legacy(file_path, target_ext, notes)
        if converted_path is None:
            chunks = []
        elif target_ext == ".docx":
            chunks = _extract_docx(converted_path)
        elif target_ext == ".pptx":
            chunks = _extract_pptx(converted_path, notes)
        else:  # .xlsx
            chunks = _extract_xlsx(converted_path, notes)
    else:
        raise ValueError(f"Unsupported file type: {ext or '(no extension)'}")

    _check_not_session_expired(chunks)
    return chunks, notes


def _extract_text_file(file_path):
    with open(file_path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="replace")
    return [Chunk("text", "file content", text=text)]


def _extract_csv(file_path):
    with open(file_path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="replace")
    try:
        rows = list(csv.reader(io.StringIO(text)))
        rendered = "\n".join(", ".join(row) for row in rows[:MAX_XLSX_ROWS_PER_SHEET])
    except Exception:
        rendered = text
    return [Chunk("text", "csv content", text=rendered)]


def _extract_image(file_path, filename):
    with open(file_path, "rb") as f:
        data = f.read()
    # Validate it's a real image early so a bad upload fails fast with a clear error.
    Image.open(io.BytesIO(data)).verify()
    return [Chunk("image", filename, image_bytes=data)]


def _extract_pdf(file_path, notes):
    chunks = []
    doc = fitz.open(file_path)
    try:
        page_count = doc.page_count
        if page_count > MAX_PDF_PAGES:
            notes.append(f"PDF has {page_count} pages; only the first {MAX_PDF_PAGES} were analyzed.")
        for i, page in enumerate(doc):
            if i >= MAX_PDF_PAGES:
                break
            text = page.get_text("text").strip()
            if len(text) >= MIN_TEXT_CHARS_PER_PAGE:
                chunks.append(Chunk("text", f"page {i + 1}", text=text))
            else:
                pix = page.get_pixmap(dpi=150)
                img_bytes = pix.tobytes("png")
                chunks.append(Chunk("image", f"page {i + 1} (scanned/image)", image_bytes=img_bytes))
    finally:
        doc.close()
    if not chunks:
        notes.append("No extractable content found in PDF.")
    return chunks


def _extract_docx(file_path):
    doc = DocxDocument(file_path)
    parts = []
    for p in doc.paragraphs:
        if p.text.strip():
            parts.append(p.text)
    for table in doc.tables:
        for row in table.rows:
            cells = [c.text.strip() for c in row.cells]
            if any(cells):
                parts.append(" | ".join(cells))
    text = "\n".join(parts)
    if not text.strip():
        return [Chunk("text", "document", text="(no extractable text found in document body)")]
    return [Chunk("text", "document text", text=text)]


def _extract_xlsx(file_path, notes):
    wb = load_workbook(file_path, data_only=True, read_only=True)
    chunks = []
    for sheet in wb.worksheets:
        lines = []
        for i, row in enumerate(sheet.iter_rows(values_only=True)):
            if i >= MAX_XLSX_ROWS_PER_SHEET:
                notes.append(f"Sheet '{sheet.title}' truncated to first {MAX_XLSX_ROWS_PER_SHEET} rows.")
                break
            cells = ["" if v is None else str(v) for v in row]
            if any(c.strip() for c in cells):
                lines.append(", ".join(cells))
        if lines:
            chunks.append(Chunk("text", f"sheet '{sheet.title}'", text="\n".join(lines)))
    if not chunks:
        notes.append("No non-empty cells found in workbook.")
    return chunks


def _extract_pptx(file_path, notes):
    prs = Presentation(file_path)
    chunks = []
    for i, slide in enumerate(prs.slides):
        if i >= MAX_PPTX_SLIDES:
            notes.append(f"Presentation truncated to first {MAX_PPTX_SLIDES} slides.")
            break
        parts = []
        for shape in slide.shapes:
            if shape.has_text_frame and shape.text_frame.text.strip():
                parts.append(shape.text_frame.text)
            if shape.has_table:
                for row in shape.table.rows:
                    cells = [c.text.strip() for c in row.cells]
                    if any(cells):
                        parts.append(" | ".join(cells))
        if slide.has_notes_slide and slide.notes_slide.notes_text_frame.text.strip():
            parts.append("[speaker notes] " + slide.notes_slide.notes_text_frame.text)
        if parts:
            chunks.append(Chunk("text", f"slide {i + 1}", text="\n".join(parts)))
    if not chunks:
        notes.append("No extractable text found in presentation.")
    return chunks
