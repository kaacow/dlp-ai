"""Thin wrapper around the local Ollama HTTP API for the content-analysis pipeline.
Kept separate from ollama_client.py (which implements streaming + real cancellation
for the interactive "Analyze event" flow) — content analysis runs as an unattended
background/batch pass with no cancel button, so the simpler non-streaming call shape
from the File Analyzer app is a better fit; ported from there unchanged."""
import base64
import json

import requests

OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_TIMEOUT = 300


def chat_json(model, system_prompt, user_prompt, num_ctx=32768, timeout=DEFAULT_TIMEOUT, seed=42):
    """Chat call that forces a JSON object response. Returns the parsed dict.

    temperature=0 + a fixed seed makes this near-deterministic: the same file
    analyzed twice should get the same score, rather than drifting run to run."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": "json",
        "stream": False,
        "options": {"num_ctx": num_ctx, "temperature": 0.0, "seed": seed},
    }
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
    resp.raise_for_status()
    content = resp.json()["message"]["content"]
    return json.loads(content)


def describe_image(model, image_bytes, prompt, num_ctx=8192, timeout=DEFAULT_TIMEOUT, seed=42):
    """Vision call: transcribe/describe a single image. Returns plain text."""
    b64 = base64.b64encode(image_bytes).decode("ascii")
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt, "images": [b64]},
        ],
        "stream": False,
        "options": {"num_ctx": num_ctx, "temperature": 0.0, "seed": seed},
    }
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()
