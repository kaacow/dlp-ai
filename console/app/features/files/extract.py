"""File content extraction: turns an uploaded file into a list of chunks,
each either plain text or an image that needs a vision model to read."""
import csv
import io
from pathlib import Path

import fitz  # PyMuPDF
from docx import Document as DocxDocument
from openpyxl import load_workbook
from pptx import Presentation
from PIL import Image

TEXT_EXTS = {".txt", ".md", ".log", ".json", ".xml", ".yaml", ".yml"}
CSV_EXTS = {".csv", ".tsv"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp", ".tif", ".tiff"}
DOC_EXTS = {".pdf", ".docx", ".xlsx", ".xls", ".pptx"}

SUPPORTED_EXTS = TEXT_EXTS | CSV_EXTS | IMAGE_EXTS | DOC_EXTS

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
    elif ext in (".xlsx", ".xls"):
        chunks = _extract_xlsx(file_path, notes)
    elif ext == ".pptx":
        chunks = _extract_pptx(file_path, notes)
    else:
        raise ValueError(f"Unsupported file type: {ext or '(no extension)'}")

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
