"""Track D's detection engine: a fast regex pre-filter for well-known secret shapes,
feeding candidate lines to a local code model (`qwen3-coder:30b`) for the real
judgment call — same layered approach real secret-scanners (gitleaks/trufflehog) use,
with an AI layer on top to catch what regex misses and to filter out obvious
placeholders/examples that would otherwise flood the report with noise.

Model choice: qwen3-coder:30b (Ollama, ~19GB, MoE 30B-total/3.3B-active so it stays
fast despite the "30B" label, native 256K context) — picked via live research this
session as the current best local option for code-security review, and pulled fresh
onto the GPU workstation for this project (the box previously only had qwen2.5vl and qwen3:32b,
neither code-specialized).
"""
import json
import re

from . import ollama_client

OLLAMA_URL = "http://localhost:11434/api/chat"
SCAN_MODEL = "qwen3-coder:30b"

# Not exhaustive by design — same "plain editable set the team can tune" philosophy as
# destinations.py's DESTINATION_CATEGORIES. Extend freely as new languages show up in
# real sent files.
CODE_EXTENSIONS = {
    # Python
    ".py", ".ipynb", ".pyw",
    # JS/TS family
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    # JVM
    ".java", ".class", ".jar", ".scala", ".sc", ".kt", ".kts", ".groovy", ".gvy",
    # C family
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".cs",
    # Go / Rust / Ruby / PHP / Swift
    ".go", ".rs", ".rb", ".rbw", ".php", ".phtml", ".swift",
    # Objective-C
    ".m", ".mm",
    # Scripting / shell
    ".pl", ".pm", ".lua", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1",
    ".bat", ".cmd", ".awk", ".sed", ".tcl",
    # R / Julia / Dart
    ".r", ".jl", ".dart",
    # Functional
    ".hs", ".lhs", ".erl", ".hrl", ".ex", ".exs", ".clj", ".cljs", ".cljc",
    ".elm", ".fs", ".fsx", ".fsi", ".ml", ".mli",
    # Systems / niche
    ".nim", ".cr", ".zig", ".v", ".vhd", ".vhdl", ".sv", ".svh", ".asm", ".s",
    ".f", ".f90", ".f95", ".for", ".pas", ".pp", ".d",
    # Legacy / enterprise
    ".vb", ".vbs", ".bas", ".cob", ".cbl", ".ada", ".adb", ".ads",
    # Blockchain / WASM
    ".sol", ".wasm", ".wat",
    # SQL
    ".sql", ".psql", ".plsql",
    # Web / markup / styling
    ".html", ".htm", ".xhtml", ".css", ".scss", ".sass", ".less", ".vue",
    ".svelte", ".astro",
    # Data / config
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg",
    ".conf", ".env", ".proto", ".graphql", ".gql",
    # Build / infra
    ".dockerfile", ".tf", ".tfvars", ".makefile", ".mk", ".cmake", ".gradle",
    ".rake", ".gemspec", ".cabal", ".nix",
    # Docs (can carry example creds/tokens)
    ".md", ".rst",
}

# Known secret/credential shapes, checked before the model ever sees the file. `\b`
# word-boundaries throughout — Track B's rule engine had a real bug (the "nda"
# keyword false-positiving inside "panda.jpg") from skipping this, don't repeat it.
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "db_connection_string": re.compile(r"\b(postgres|postgresql|mysql|mongodb(\+srv)?)://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+"),
    "generic_secret_assignment": re.compile(
        r"\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"\s]{4,}['\"]",
        re.IGNORECASE,
    ),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


def regex_prefilter(content: str):
    """Returns [{line, pattern_type, text}] — candidate lines for the model to weigh in
    on, not final findings (regex alone over-triggers, e.g. on `password = input(...)`
    or version strings that look like IPs)."""
    hits = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for pattern_type, regex in SECRET_PATTERNS.items():
            if regex.search(line):
                hits.append({"line": line_no, "pattern_type": pattern_type, "text": line.strip()[:300]})
    return hits


SYSTEM_PROMPT = (
    "You are a DLP (data-loss-prevention) security reviewer. You are given the "
    "content of a code file an employee sent outside standard internal channels. "
    "Your ONLY job is to find hardcoded sensitive literals: passwords, API keys/"
    "tokens, private keys, database connection strings with embedded credentials, "
    "and IP addresses. Do NOT explain what the code does, do NOT summarize its "
    "purpose, and do NOT flag anything that isn't a literal value in the "
    "file (e.g. a variable that reads from an environment variable or config is not "
    "a hardcoded secret, even if its name is 'password').\n\n"
    "A regex pre-filter already flagged some candidate lines (given below as a hint) "
    "— use them as a starting point but also scan the rest of the file yourself for "
    "anything the regex missed (a hardcoded credential doesn't have to match one of "
    "those exact patterns).\n\n"
    "For anything you find, judge whether it looks like a real value or an obvious "
    "placeholder/example (e.g. 'changeme', 'your_api_key_here', 'xxx', '123.45.67.89' "
    "used as a docs example, a well-known test/localhost IP) — set "
    "is_placeholder true for those rather than omitting them, so a human reviewer "
    "still sees them but they don't get treated as urgent.\n\n"
    "Respond with ONLY a JSON object (no other text) with this exact shape:\n"
    '{"findings": [{"line": <int>, "type": <string>, "severity": "low"|"medium"|"high", '
    '"snippet": <string, the relevant line trimmed to ~200 chars>, '
    '"explanation": <string, one short sentence>, "is_placeholder": <bool>}]}\n'
    'If nothing sensitive is found, respond with {"findings": []}.'
)


def build_user_content(filename: str, content: str, candidates: list, truncated: bool) -> str:
    payload = {
        "filename": filename,
        "truncated": truncated,
        "regex_flagged_candidate_lines": candidates,
        "file_content": content,
    }
    return json.dumps(payload, ensure_ascii=False)


def scan_file(content: str, filename: str, model: str = None, cancel_event=None):
    """Returns (findings, model_used). findings: list of dicts with line, type,
    severity, snippet, explanation, is_placeholder, regex_confirmed."""
    model = model or SCAN_MODEL
    candidates = regex_prefilter(content)
    candidate_lines = {c["line"] for c in candidates}

    message = ollama_client.stream_chat(
        OLLAMA_URL,
        {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_content(filename, content, candidates, len(content) == 0)},
            ],
            "format": "json",
            "think": False,
        },
        cancel_event=cancel_event, timeout=180,
    )

    try:
        parsed = json.loads(message["content"])
        findings = parsed.get("findings", [])
    except (json.JSONDecodeError, ValueError, KeyError):
        findings = []

    for f in findings:
        f["regex_confirmed"] = f.get("line") in candidate_lines

    return findings, model
