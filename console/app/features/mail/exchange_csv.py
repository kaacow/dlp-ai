"""Exchange message-trace CSV parsing — ported near-verbatim from
`old_server.py`'s `load_csv`/`clean_str` (the old Flask self-email tool).
Exchange's export uses tab-separated values despite the `.csv` extension,
and subject lines can contain unquoted delimiters that need to be folded
back into the Subject column — both handled the same way here as they were
there, since it's the same tenant's export format.

Needs `pandas` in the venv (not currently installed on the GPU workstation — add via
`pip install pandas` alongside `playwright` during deployment).
"""
import io

import pandas as pd

REQUIRED_COLUMNS = {"SenderAddress", "RecipientAddress"}


def clean_str(s) -> str:
    return str(s).strip().strip('"').strip("'")


def load_csv(raw: bytes, fname: str = "upload.csv") -> pd.DataFrame:
    """Parse an Exchange message-trace export robustly. Rows with missing
    optional fields are kept and padded with empty strings rather than
    dropped."""
    content = None
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            content = raw.decode(enc)
            break
        except Exception:
            pass
    if content is None:
        content = raw.decode("latin-1", errors="replace")

    lines = [l for l in content.splitlines() if l.strip()]
    if not lines:
        raise ValueError(f"{fname}: file is empty")

    header_line = lines[0]
    delimiter = "\t" if "\t" in header_line else ","

    # Strategy 1 — pandas standard (handles missing fields via NaN).
    try:
        return pd.read_csv(
            io.StringIO(content), sep=delimiter, engine="python", on_bad_lines="warn", dtype=str,
        )
    except Exception:
        pass

    # Strategy 2 — manual: pad short rows, collapse long rows into last col.
    header = [clean_str(h) for h in lines[0].split(delimiter)]
    ncols = len(header)
    rows = []
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split(delimiter)
        if len(parts) >= ncols:
            row = parts[: ncols - 1] + [delimiter.join(parts[ncols - 1 :])]
        else:
            row = parts + [""] * (ncols - len(parts))
        rows.append([clean_str(v) for v in row])

    return pd.DataFrame(rows, columns=header)


def normalize_rows(df: pd.DataFrame) -> list[dict]:
    """Clean + dedup, mirroring old_server.py's /analyze cleaning block
    (SenderAddress/RecipientAddress lowercased/stripped/quote-stripped, both
    must contain '@'). Returns a list of {sender_address, recipient_address,
    received, subject} dicts — the shape runner_exchange.py works from."""
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {missing}. Got: {list(df.columns)}")

    df = df.copy()
    df["SenderAddress"] = df["SenderAddress"].astype(str).str.strip().str.strip('"').str.strip("'").str.lower()
    df["RecipientAddress"] = df["RecipientAddress"].astype(str).str.strip().str.strip('"').str.strip("'").str.lower()
    df = df[df["SenderAddress"].str.contains("@", na=False)]
    df = df[df["RecipientAddress"].str.contains("@", na=False)]
    df = df.drop_duplicates()

    out = []
    for _, row in df.iterrows():
        out.append({
            "sender_address": row["SenderAddress"],
            "recipient_address": row["RecipientAddress"],
            "received": _normalize_received(row.get("Received", "")),
            "subject": str(row.get("Subject", "") or ""),
        })
    return out


def _normalize_received(raw) -> str:
    """Exchange's exact timestamp format hasn't been confirmed against a real
    export yet (see exchange_fetch.py's docstring on what's still unproven);
    pd.to_datetime handles the common variants (ISO8601, US-style, with/
    without timezone) the same way old_server.py's convert_to_utc_plus_4 did.
    Falls back to the raw string if parsing fails, so a format surprise
    degrades to "can't be time-windowed precisely" rather than crashing the
    whole run."""
    s = str(raw or "").strip()
    if not s or s.lower() in ("nan", "none"):
        return ""
    try:
        ts = pd.to_datetime(s, utc=True).tz_localize(None)
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s
