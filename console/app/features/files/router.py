"""File Analyzer — upload a file, get an AI confidentiality/risk assessment.

Ported from the standalone file_analyzer app (former port 8423); logic
unchanged, routes now live under /api/files/* behind the console's shared
auth. Fresh DB (the old standalone app's data was test-only).
"""
import re
import shutil
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel

from . import chat as chat_mod
from . import db
from . import ollama_client
from .analyze import analyze_file, sha256_of_file, REASONING_MODEL, VISION_MODEL
from .extract import SUPPORTED_EXTS

BASE_DIR = Path("./data")
UPLOAD_DIR = BASE_DIR / "uploads" / "files"

MAX_FILES_PER_JOB = 20
MAX_FILE_SIZE = 60 * 1024 * 1024  # 60MB
HISTORY_GRACE_SECONDS = 600  # how long un-saved scans stay queryable after a job finishes
SEGMENT_STEP_RE = re.compile(r"analyzing segment (\d+)/(\d+) with AI model")

router = APIRouter(prefix="/api/files", tags=["files"])


def init_db():
    db.init_db()
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/analyze")
async def analyze(
    files: list[UploadFile] = File(...),
    save_to_history: str = Form("true"),
    instructions: str = Form(""),
    depth: str = Form("thorough"),
):
    if not files:
        raise HTTPException(400, "No files provided")
    if len(files) > MAX_FILES_PER_JOB:
        raise HTTPException(400, f"Too many files (max {MAX_FILES_PER_JOB} per batch)")

    save = save_to_history.lower() in ("true", "1", "yes", "on")
    instructions = instructions.strip()
    depth = depth if depth in ("quick", "thorough") else "thorough"

    job_dir = None
    saved_paths = []
    conn = db.get_conn()
    try:
        job_id = db.create_job(conn, len(files), save)
        job_dir = UPLOAD_DIR / str(job_id)
        job_dir.mkdir(parents=True, exist_ok=True)

        for f in files:
            ext = Path(f.filename).suffix.lower()
            if ext not in SUPPORTED_EXTS:
                db.append_job_step(conn, job_id, f"Skipped '{f.filename}': unsupported file type '{ext}'")
                continue
            dest = job_dir / f.filename
            size = 0
            with open(dest, "wb") as out:
                while chunk := await f.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_FILE_SIZE:
                        out.close()
                        dest.unlink(missing_ok=True)
                        db.append_job_step(conn, job_id, f"Skipped '{f.filename}': exceeds {MAX_FILE_SIZE // (1024*1024)}MB limit")
                        break
                    out.write(chunk)
            if dest.exists():
                saved_paths.append((dest, f.filename, ext, size))
    finally:
        conn.close()

    thread = threading.Thread(target=_run_job, args=(job_id, saved_paths, save, job_dir, instructions, depth), daemon=True)
    thread.start()

    return {"job_id": job_id}


def _run_job(job_id, saved_paths, save_to_history, job_dir, instructions="", depth="thorough"):
    conn = db.get_conn()
    completed = 0
    try:
        for path, filename, ext, size in saved_paths:
            db.append_job_step(conn, job_id, f"Analyzing '{filename}'...")
            sha = sha256_of_file(path)
            scan_id = db.insert_scan(conn, job_id, filename, ext, size, sha, save_to_history, instructions, depth)

            def on_progress(stage, _filename=filename):
                db.append_job_step(conn, job_id, f"'{_filename}': {stage}")

            try:
                result = analyze_file(str(path), filename, instructions, on_progress=on_progress, depth=depth)
                db.update_scan_result(conn, scan_id, result)
                db.append_job_step(
                    conn, job_id,
                    f"'{filename}': risk score {result['risk_score']}, action '{result['recommended_action']}'",
                )
            except Exception as e:
                db.update_scan_error(conn, scan_id, str(e))
                db.append_job_step(conn, job_id, f"'{filename}' failed: {e}")
                traceback.print_exc()
            finally:
                path.unlink(missing_ok=True)
                completed += 1
                db.set_job_progress(conn, job_id, completed)

        db.finish_job(conn, job_id, "done")
        db.append_job_step(conn, job_id, "Job complete.")
    except Exception as e:
        db.finish_job(conn, job_id, "failed", str(e))
        db.append_job_step(conn, job_id, f"Job failed: {e}")
        traceback.print_exc()
    finally:
        conn.close()
        shutil.rmtree(job_dir, ignore_errors=True)
        if not save_to_history:
            timer = threading.Timer(HISTORY_GRACE_SECONDS, _purge_unsaved, args=(job_id,))
            timer.daemon = True
            timer.start()


def _purge_unsaved(job_id):
    conn = db.get_conn()
    try:
        db.delete_scans_not_saved(conn, job_id)
    finally:
        conn.close()


@router.get("/jobs/{job_id}")
def get_job(job_id: int):
    conn = db.get_conn()
    try:
        job = db.get_job(conn, job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        avg_seconds = db.get_avg_scan_duration(conn)
    finally:
        conn.close()

    total = job["total_files"] or 1
    completed = job["completed_files"]

    if job["status"] == "running":
        in_progress = next((s for s in job["scans"] if s["risk_score"] is None and not s["error"]), None)
        current_fraction = 0.0
        if in_progress:
            segment_match = None
            for step in reversed(job["steps"]):
                if step["t"] < in_progress["created_at"]:
                    break
                segment_match = SEGMENT_STEP_RE.search(step["msg"])
                if segment_match:
                    break
            if segment_match:
                seg_num, seg_total = int(segment_match.group(1)), int(segment_match.group(2))
                current_fraction = min(0.97, max(0.0, (seg_num - 0.5) / seg_total))
            else:
                started = datetime.fromisoformat(in_progress["created_at"])
                elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                current_fraction = min(0.97, elapsed / avg_seconds) if avg_seconds > 0 else 0.0
        job["progress_percent"] = round(min(100.0, ((completed + current_fraction) / total) * 100), 1)
        job["eta_seconds"] = round(max(0.0, total - completed - current_fraction) * avg_seconds)
    else:
        job["progress_percent"] = 100.0
        job["eta_seconds"] = 0

    job["avg_seconds_per_file"] = round(avg_seconds, 1)
    return job


@router.get("/history")
def history(limit: int = 50, offset: int = 0, min_score: int | None = None, related_to_company: bool | None = None):
    conn = db.get_conn()
    try:
        rows, total = db.list_history(conn, limit=limit, offset=offset, min_score=min_score, related_to_company=related_to_company)
    finally:
        conn.close()
    return {"scans": rows, "total": total, "limit": limit, "offset": offset}


@router.get("/history/{scan_id}")
def history_detail(scan_id: int):
    conn = db.get_conn()
    try:
        scan = db.get_scan(conn, scan_id)
    finally:
        conn.close()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.delete("/history/{scan_id}")
def history_delete(scan_id: int):
    conn = db.get_conn()
    try:
        scan = db.get_scan(conn, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        db.delete_scan(conn, scan_id)
    finally:
        conn.close()
    return {"ok": True}


class ChatRequest(BaseModel):
    question: str


@router.post("/history/{scan_id}/chat")
def scan_chat(scan_id: int, body: ChatRequest):
    question = body.question.strip()
    if not question:
        raise HTTPException(400, "Question is required")

    conn = db.get_conn()
    try:
        scan = db.get_scan(conn, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        if scan.get("risk_score") is None or scan.get("error"):
            raise HTTPException(400, "This file hasn't been successfully analyzed yet")

        prior = db.list_chat_messages(conn, scan_id)
        db.insert_chat_message(conn, scan_id, "user", question)
        try:
            answer = chat_mod.ask(scan, prior, question)
        except Exception as e:
            raise HTTPException(502, f"Chat failed: {e}")
        db.insert_chat_message(conn, scan_id, "assistant", answer)
    finally:
        conn.close()
    return {"answer": answer}


@router.get("/history/{scan_id}/chat")
def scan_chat_history(scan_id: int):
    conn = db.get_conn()
    try:
        scan = db.get_scan(conn, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        messages = db.list_chat_messages(conn, scan_id)
    finally:
        conn.close()
    return {"messages": messages}


@router.get("/config")
def config():
    try:
        available = ollama_client.list_models()
    except Exception:
        available = []
    return {
        "reasoning_model": REASONING_MODEL,
        "vision_model": VISION_MODEL,
        "available_models": available,
        "max_files_per_job": MAX_FILES_PER_JOB,
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
        "supported_extensions": sorted(SUPPORTED_EXTS),
    }
