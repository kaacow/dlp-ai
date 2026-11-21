# DLP AI — LLM-assisted data-loss-prevention triage

A self-hosted system that helps a security team review data-loss-prevention (DLP) alerts
faster. It pulls file-send, e-mail and screen-activity events from an employee-monitoring
platform (EMP), triages them with a deterministic rule engine, and uses **local LLMs
(Ollama)** to read file contents and screenshots and produce an explainable verdict that an
analyst can accept or correct. Nothing leaves the host: all models run locally.

> This is a sanitized public version of a tool I built for an internal security team.
> Company names, hosts, credentials, destination lists and all data have been removed or
> replaced with placeholders (`example-corp.com`, `emp.example.internal`, ...). You must
> supply your own EMP endpoint, domains and keyword lists to run it.

## What it does

| Component | Path | Purpose |
|---|---|---|
| **Triage agent** | `triage_agent/` | Rule-engine triage of file-send events, then an agentic investigation (chat/window-activity/screenshot evidence, read-only SQL tool, max 5 tool rounds) that yields a verdict + reasoning. Analyst UI with login, roles and a feedback loop. |
| **Content analysis** | `triage_agent/app/content_*.py` | Downloads the real sent file, extracts text (PDF, Office, and legacy formats via LibreOffice conversion), segments long documents, and asks an LLM to score sensitivity and company relevance with strict, quote-the-evidence output rules. |
| **Console** | `console/` | One FastAPI app with several features behind a shared login/admin system: |
| – Secrets scanner | `console/app/features/secrets` | Finds credentials/keys in source files that were sent out; regex candidates are confirmed by an LLM to cut false positives. Scheduled runs + digest. |
| – Mail exfiltration detector | `console/app/features/mail` | Detects self-sends to corporate mailboxes and sends to personal webmail; correlates with DLP records; optional Telegram digest. |
| – File analyzer | `console/app/features/files` | Upload a file, get a risk score, categories and a chat about it. |
| – Screenshots | `console/app/features/shots` | Opens the evidence screenshots nearest to an event time; large event lists are split into reviewable batches with checked/hidden marks. |
| – Global search | `console/app/features/globalsearch` | Nightly check that the user typed into a BI tool matches the logged-in user. |

## How the AI "learns" — honestly

No model weights are trained or fine-tuned. Improvement comes from **in-context learning**:

- **Analyst feedback ("Feed to AI")** — analysts label verdicts; `agent.py`
  (`find_similar_precedent`) retrieves the most similar past labels and injects them into
  the prompt as few-shot precedent.
- **Company-knowledge feeder** — analysts add durable facts (terminology, numbering schemes)
  that are injected into the content labeler's prompt.
- **Content-label dataset** — `content_label_seed.py` produces destination-blind content-only
  labels with analyst agree/correct review, building a labeled dataset that could later be
  used for fine-tuning.
- **Model selection** — vision and reasoning models were benchmarked on real screenshots;
  the biggest accuracy gain came from using full-resolution images rather than thumbnails,
  not from a bigger model.

## Design notes

- Unreviewed destinations default to scrutiny (`uncategorized`), never to auto-clear.
- LLM prompts forbid fabrication: company relevance requires quoted/named evidence.
- Whole-word Unicode keyword matching fixed substring false positives (e.g. "nda" in "panda").
- Streaming Ollama client with real cancellation so a cancelled job frees the GPU.
- Passwords hashed with bcrypt; role-gated admin actions; SQLite storage.

## Running (sketch)

```bash
pip install -r requirements.txt
cp .env.example .env          # fill in EMP_* values
ollama pull qwen3:32b qwen2.5vl:32b
cd console/app && uvicorn main:app --port 8424
```

`triage_agent/app` runs the same way (`uvicorn main:app --port 8420`). The EMP integration
(`emp_sql.py`, `report_filesend.py`) targets a web report portal and will need adapting to
your platform. Tests: `cd console && python3 tests/test_analyze.py`.

## Status

Built for and used by a real security team (2026). This public copy is not runnable
end-to-end without an EMP backend, and has no bundled data.
