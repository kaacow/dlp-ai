"""Username-mismatch detection for the bi01 login check.

Report 247 ("Global database search") returns, per window event, the Windows user that was logged in
and the raw keystrokes typed in that window ("Text"). On bi01 that text may contain the bi01 login the
person typed. A listed bi01 username that is NOT the person's own = shared / borrowed credentials.

Verdicts:
  none     no typed text at all
  unknown  text has no username from the bi01 list (search terms, numbers ...) - nothing to judge
  ok       only the person's own bi01 username(s) appear
  alert    a listed username appears that is not theirs, and none of theirs does
  review   theirs AND someone else's appear together (could be a legit colleague name in a search)
"""
import re

TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-]+")


def norm(name):
    return (name or "").strip().lower()


def sam(user):
    """'CORP\\jdoe' / 'jdoe' -> 'jdoe'"""
    return norm(re.split(r"[\\/]", user or "")[-1])


def parse_list(text):
    """Lines 'bi01user' or 'bi01user=windowsuser' (',' ';' tab also split several per line is NOT supported:
    one entry per line, first column of a CSV is used). Returns ([(bi01, win)], [bad lines])."""
    out, bad, seen = [], [], set()
    for ln, raw in enumerate((text or "").splitlines(), 1):
        s = raw.strip().strip("﻿")
        if not s or s.startswith("#"):
            continue
        parts = re.split(r"[,;\t]", s)
        s = parts[0].strip()
        if "=" in s:
            a, b = (x.strip() for x in s.split("=", 1))
        else:
            a, b = s, ""
        a, b = sam(a), sam(b)
        if not a or not re.fullmatch(r"[a-z0-9_.\-]{1,64}", a) or (b and not re.fullmatch(r"[a-z0-9_.\-]{1,64}", b)):
            bad.append(f"line {ln}: '{raw.strip()[:40]}'")
            continue
        if (a, b) not in seen:
            seen.add((a, b))
            out.append((a, b))
    return out, bad


class Watch:
    """bi01 username list: lower-case bi01 name -> set of Windows names that legitimately own it."""
    def __init__(self, entries):
        self.owners = {}
        for a, b in entries:
            s = self.owners.setdefault(a, {a})
            if b:
                s.add(b)

    def __len__(self):
        return len(self.owners)


def tokens(text):
    out = []
    for m in TOKEN_RE.finditer(text or ""):
        t = m.group(0).strip(".-_").lower()      # "jdoe." at the end of a sentence
        if t:
            out.append(t)
    return out


def analyze(win_user, text, watch):
    """-> (verdict, own_found, foreign_found)"""
    if not (text or "").strip():
        return "none", [], []
    me = sam(win_user)
    found = {t for t in tokens(text) if t in watch.owners}
    if not found:
        return "unknown", [], []
    own = sorted(t for t in found if me in watch.owners[t])
    foreign = sorted(found - set(own))
    if not foreign:
        return "ok", own, []
    return ("review" if own else "alert"), own, foreign


MASK = "\u2022\u2022\u2022"


def snippet(text, watch):
    """Typed text can contain passwords (users often type 'login password'). Keep ONLY words that are bi01 usernames and
    mask every other typed word, so nothing secret is ever stored or shown. Only flagged rows get a snippet at all."""
    out = []
    for m in TOKEN_RE.finditer(text or ""):
        t = m.group(0)
        k = t.strip(".-_").lower()
        out.append(t if k in watch.owners else MASK)
        if len(out) >= 12:
            out.append("\u2026")
            break
    return " ".join(out)


def judge(win_user, keyword, title, text, watch, site):
    """The DLP found `keyword` (a bi01 username from the list) typed by `win_user`.
    -> None (not a bi01 window, or the keyword is only part of a longer word: not a real hit)
       'ok'    the person typed their own bi01 username
       'alert' the person typed somebody else's bi01 username"""
    if site not in (title or "").lower():
        return None
    k = norm(keyword)
    if k not in tokens(text):
        return None
    return "ok" if sam(win_user) in watch.owners.get(k, {k}) else "alert"
