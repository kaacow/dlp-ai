"""Fetches the actual saved-copy bytes for a sent file via `action=getfile`, same
relative-href-resolution trick as `screenshots.fetch_fullsize()` in the existing
Track C app (the href EMP puts in report HTML is authoritative — don't try to
reconstruct the filepath query param yourself, see report_filesend.py's docstring).
"""
import json

from . import emp_sql as k

MAX_CONTENT_BYTES = 200_000  # keeps individual files well within the model's context
                              # budget even at 256K tokens; flagged as truncated rather
                              # than silently scanning a partial file unremarked


def fetch_file_bytes(session, href: str) -> bytes:
    url = f"{k.BASE}/cgi-report.exe?" + href.split("?", 1)[1]
    resp = session.get(url)
    resp.raise_for_status()
    return resp.content


def _extract_notebook_code(raw_text: str) -> str:
    """Joins source from code cells only (skips markdown cells and raster outputs) —
    scanning the raw notebook JSON directly would work but buries actual code in a lot
    of structural noise the model doesn't need to see."""
    notebook = json.loads(raw_text)
    parts = []
    for cell in notebook.get("cells", []):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        parts.append("".join(source) if isinstance(source, list) else source)
    return "\n\n# --- next cell ---\n\n".join(parts)


def _decode(raw_bytes: bytes) -> str:
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes.decode("latin1")


def decode_and_unwrap(file_type: str, raw_bytes: bytes) -> tuple[str, bool]:
    """Returns (text, truncated). file_type is the lowercased extension (e.g. '.ipynb')
    as reported by the filesend report's Type column.

    For .ipynb, the code-cell extraction MUST run on the full, untruncated file before
    any size cap is applied — cutting raw bytes at MAX_CONTENT_BYTES first (the
    original approach) breaks the JSON structure entirely on real-world notebooks
    (confirmed live: a 757KB notebook has an early markdown cell with a large inline
    base64 image, so a flat byte-cap lands inside that image data and JSON parsing
    fails, silently falling back to scanning raw undecoded JSON/base64 noise instead
    of actual code). Extracting first means the size cap only ever trims actual code
    text, which is already far smaller than the raw notebook file.
    """
    if file_type == ".ipynb":
        try:
            code_text = _extract_notebook_code(_decode(raw_bytes))
        except (json.JSONDecodeError, ValueError):
            code_text = _decode(raw_bytes)  # genuinely malformed notebook — best effort
        truncated = len(code_text) > MAX_CONTENT_BYTES
        return code_text[:MAX_CONTENT_BYTES], truncated

    truncated = len(raw_bytes) > MAX_CONTENT_BYTES
    return _decode(raw_bytes[:MAX_CONTENT_BYTES]), truncated
