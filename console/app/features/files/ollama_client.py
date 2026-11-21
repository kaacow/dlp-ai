"""Thin wrapper around the local Ollama HTTP API."""
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


def chat(model, messages, num_ctx=32768, timeout=DEFAULT_TIMEOUT, temperature=0.2):
    """Freeform multi-turn chat call. `messages` is a list of {role, content} dicts
    (including the system message). Returns the assistant's plain-text reply."""
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"num_ctx": num_ctx, "temperature": temperature},
    }
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()


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


def list_models():
    resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=15)
    resp.raise_for_status()
    return [m["name"] for m in resp.json().get("models", [])]
