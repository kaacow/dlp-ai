"""Streaming Ollama client with real cancellation.

Why this exists: the original non-streaming (`stream: false`) calls had a "Cancel"
button in the UI that only stopped the frontend from polling — the backend thread,
and therefore the actual model inference on the GPU, kept running to completion
regardless. The user noticed this directly (GPU usage stayed high after clicking
Cancel) and asked for it to actually stop.

The fix: use Ollama's streaming API and close the HTTP connection early when a
cancel_event fires. Ollama detects the broken pipe on its next attempt to write a
token and aborts generation server-side — this is the standard mechanism for
stopping in-progress inference, not just abandoning interest in the result.
Confirmed streaming chunk shape against the live server: content arrives
incrementally token-by-token, tool_calls arrive as one complete chunk (not
token-by-token), final chunk has "done": true.
"""
import json

import requests


class Cancelled(Exception):
    pass


def stream_chat(url, payload, cancel_event=None, timeout=180, poll_every=1):
    """POSTs to {url} with stream=True, checks cancel_event between lines, and
    closes the connection (raising Cancelled) as soon as it's set. Returns a dict
    shaped like the non-streaming API's "message": {role, content, tool_calls}.
    """
    payload = {**payload, "stream": True}
    message = {"role": "assistant", "content": "", "tool_calls": []}
    resp = requests.post(url, json=payload, stream=True, timeout=timeout)
    try:
        resp.raise_for_status()
        for line in resp.iter_lines(decode_unicode=True):
            if cancel_event is not None and cancel_event.is_set():
                raise Cancelled()
            if not line:
                continue
            chunk = json.loads(line)
            msg = chunk.get("message") or {}
            if msg.get("content"):
                message["content"] += msg["content"]
            if msg.get("tool_calls"):
                message["tool_calls"] = msg["tool_calls"]
            if chunk.get("done"):
                break
        return message
    finally:
        resp.close()
