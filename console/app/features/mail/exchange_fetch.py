"""Browser automation for pulling an Exchange message-trace CSV, since this
tenant has no CLI/API access (EWS/Graph) — only portal access, and that's
MFA-gated. **Fully live-confirmed end-to-end this session (2026-08-05)**
against the real tenant, including a real file download of real production
data (hundreds of rows for one day of gmail.com-recipient traffic) whose columns —
`MessageId,Received,SenderAddress,RecipientAddress,Subject,Status,ToIP,
FromIP,Size,MessageTraceId` — match `exchange_csv.py`'s parser with zero
changes needed.

The flow uses the default **"Summary report"** type (instant, in-browser),
not "Enhanced summary report"/"Extended report" — those are async downloadable
jobs that can take a long time to generate (confirmed live: still "Not
started"/"In progress" after 20+ minutes of polling). Per the user directly
(2026-08-05): they've always just used the instant Summary report + its
"Export results" button for exactly this gmail/mail.ru one-day use case, and
it's plenty. That's what this module does now — no async job, no "Downloadable
reports" polling.

Real portal specifics discovered live (this is the modern unified M365 shell,
not the older admin.exchange.microsoft.com):
- Portal URL shape: `https://admin.cloud.microsoft/exchange#/messagetrace`.
- Login is the standard Microsoft flow, EXCEPT: (1) the persistent profile
  remembers the account and shows an account-picker tile instead of a blank
  email field on repeat visits — must handle both; (2) clicking the classic
  `input[type=submit]` button after filling email did NOT reliably advance
  the SPA — pressing Enter in the field does; (3) this tenant's Conditional
  Access defaults to certificate-based auth ("AADSTS500192: No certificate
  detected") with **Microsoft Authenticator as the actual fallback** reachable
  via the "Sign in another way" link — that link must be clicked, then the
  human approves on their phone (this is the one step that genuinely needs a
  live person the first time / whenever the remembered-device session lapses,
  exactly per the user's description of their own normal workflow).
- Once past login, `[data-automation-id="newMessageTrace"]` ("Start a trace")
  opens a panel with `input[aria-label="Senders"]` / `input[aria-label=
  "Recipients"]` (placeholder "All", NOT literally "Recipient" — don't
  selector-match on placeholder). Pressing Enter after filling Recipients
  triggers an autocomplete dropdown that silently REPLACES the typed wildcard
  with its top suggestion (usually the org's own domain) — Escape dismisses
  the suggestion list while keeping the literal typed value; confirmed via
  reading `.value` afterward.
- "Summary report" is already the default-selected radio, so no click needed
  there. Start/End date fields (`data-automation-id="NewMessageTracePanel_
  {Start,End}Date_DatePicker"`) are NOT text inputs — they're read-only
  Fluent UI comboboxes (`role="combobox"`) that open a calendar popup on
  Enter (not just on click). Day cells are `button[aria-label="{day},
  {Month}, {year}"]` (e.g. `"5, August, 2026"`) inside a `.ms-Callout` —
  reliable and stable. Clicking a day button sometimes gets intercepted by
  its wrapping `<td>` (Playwright reports "intercepts pointer events") —
  `force=True` on the click reliably works around this, confirmed live.
  **Start must not equal End, and End must not be in the future** — either
  condition silently produces "0 items" with no error (see `_search_and_export`
  for the exact rule used to pick a valid pair from a single target day).
- With Summary report selected, "Search" (not "Next") is the live button —
  click it and the panel closes into an in-browser results grid ("Message
  trace search results", confirmed live showing 392 real rows with Date/
  Sender/Recipient/Subject/Status columns).
- The grid's "Export results" control is a DROPDOWN, not a direct download
  trigger — confirmed live it reveals "Export all results" / "Export loaded
  results" / "Export selected". "Export all results" then shows one more
  confirmation dialog ("Export all message trace" / "Export could take some
  time depending on the size of your search result") with a "Continue"
  button — THAT click is what actually fires the download, confirmed live
  via `page.expect_download()` catching a real `MessageTraceResult.csv`.

Design choices from the planning session that remain unchanged:
- Persistent browser profile on disk (`PROFILE_DIR`), so MFA-remembered-
  device cookies survive across daily cron runs — confirmed this session:
  a second launch against the same profile skipped login entirely.
- Headed (visible), not headless — lets a human watch/approve MFA in person.
- Two separate per-day, per-domain searches (gmail.com, then mail.ru) rather
  than one broad pull, per the truncation issue the user hit before.
- Any point where login/MFA blocks progress raises ReauthRequiredError
  instead of hanging the whole cron job indefinitely.
"""
import os
import re
from datetime import date
from pathlib import Path

from .errors import ReauthRequiredError

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except ImportError:  # playwright not installed yet — see deployment step 2
    sync_playwright = None
    PlaywrightTimeoutError = Exception


def _load_env():
    env_path = Path(__file__).parent / ".env"
    env = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


_env = _load_env()
PORTAL_URL = os.environ.get("EXCHANGE_PORTAL_URL", _env.get("EXCHANGE_PORTAL_URL", ""))
USERNAME = os.environ.get("EXCHANGE_USERNAME", _env.get("EXCHANGE_USERNAME", ""))
PASSWORD = os.environ.get("EXCHANGE_PASSWORD", _env.get("EXCHANGE_PASSWORD", ""))

PROFILE_DIR = Path("./data/exchange_profile")  # existing persistent browser login session, reused
CSV_DIR = Path("./data/exchange_csvs")
SCREENSHOT_DIR = Path("./data/exchange_failures")

LOGIN_WAIT_MS = 90_000   # how long to give a human to clear MFA in person
NAV_TIMEOUT_MS = 30_000

_MONTHS = ["January", "February", "March", "April", "May", "June", "July",
           "August", "September", "October", "November", "December"]


def _ensure_dirs():
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


def _fail_with_screenshot(page, tag: str, message: str):
    _ensure_dirs()
    shot_path = SCREENSHOT_DIR / f"{tag}.png"
    try:
        page.screenshot(path=str(shot_path))
    except Exception:
        shot_path = None
    raise RuntimeError(f"{message} (screenshot: {shot_path})")


def _on_login_domain(page) -> bool:
    return "login.microsoftonline.com" in page.url or "login.microsoft.com" in page.url


def _handle_login(page):
    """Handles every login shape confirmed live this session: fresh email
    entry, the remembered-account picker tile, password, and the cert/MFA
    fallback via "Sign in another way" -> Microsoft Authenticator (the human
    approves on their phone — unavoidable and by design, matches the user's
    own description of their normal login habit). Raises ReauthRequiredError
    if still stuck on a Microsoft sign-in page after waiting."""
    if not _on_login_domain(page):
        return  # already authenticated via the persistent profile

    if not USERNAME or not PASSWORD:
        raise ReauthRequiredError(
            "Exchange login required but EXCHANGE_USERNAME/EXCHANGE_PASSWORD are not set in .env"
        )

    page.wait_for_timeout(1500)

    # Remembered-account picker tile (shown once this profile has seen the
    # username before, even if a prior login never fully completed).
    try:
        tile = page.get_by_text(USERNAME, exact=False)
        if tile.count() > 0:
            tile.first.click(timeout=5_000)
            page.wait_for_timeout(1500)
    except Exception:
        pass

    # Fresh email field, if present.
    try:
        if page.locator("input[type='email']").count() > 0:
            page.fill("input[type='email']", USERNAME, timeout=5_000)
            page.press("input[type='email']", "Enter")
            page.wait_for_timeout(1500)
    except Exception:
        pass

    # Password — clicking the visible "Sign in" button was unreliable;
    # pressing Enter in the field submits the form reliably.
    try:
        page.wait_for_selector("input[type='password']", timeout=10_000)
        page.fill("input[type='password']", PASSWORD, timeout=5_000)
        page.press("input[type='password']", "Enter")
        page.wait_for_timeout(2000)
    except PlaywrightTimeoutError:
        pass  # may already be past this step

    # Certificate/smart-card prompt -> pick the real fallback (Authenticator).
    try:
        link = page.get_by_text("Sign in another way", exact=False)
        if link.count() > 0:
            link.first.click(timeout=5_000)
            page.wait_for_timeout(1500)
            # If a method chooser appears, prefer Microsoft Authenticator.
            auth_option = page.get_by_text("Microsoft Authenticator", exact=False)
            if auth_option.count() > 0:
                auth_option.first.click(timeout=5_000)
                page.wait_for_timeout(1000)
    except Exception:
        pass

    # Whatever's left (an MFA approval prompt) needs a human on their phone —
    # give them LOGIN_WAIT_MS, polling every 2s for the page to leave the
    # login domain.
    waited = 0
    while _on_login_domain(page) and waited < LOGIN_WAIT_MS:
        page.wait_for_timeout(2000)
        waited += 2000

    if _on_login_domain(page):
        raise ReauthRequiredError(
            "Exchange login is still on a Microsoft sign-in page after waiting for MFA approval — "
            "please log in manually on the GPU workstation (browser window is on display :2)."
        )


def _open_new_trace(page):
    page.click('[data-automation-id="newMessageTrace"]', timeout=NAV_TIMEOUT_MS)
    page.wait_for_timeout(3000)


def _set_recipient_filter(page, domain: str):
    """Fill + verify + retry: this field's autocomplete interaction proved
    flaky live — one production run silently ended up with an empty filter
    (search came back "0 items") despite the exact same fill+Escape sequence
    working in earlier testing. Reading the value back and retrying if it
    didn't stick catches that case instead of silently searching everything."""
    wanted = f"*@{domain}"
    sel = 'input[aria-label="Recipients"]'
    for attempt in range(3):
        page.fill(sel, wanted, timeout=NAV_TIMEOUT_MS)
        page.wait_for_timeout(500)
        page.keyboard.press("Escape")  # Enter here would accept an autocomplete suggestion instead
        page.wait_for_timeout(400)
        actual = page.eval_on_selector(sel, "el => el.value")
        if actual == wanted:
            return
    raise RuntimeError(f"Recipients field shows {actual!r} after 3 attempts, expected {wanted!r}")


def _field_value(page, picker_automation_id: str) -> str:
    return page.eval_on_selector(
        f'[data-automation-id="{picker_automation_id}"] [role="combobox"]', "el => el.textContent"
    )


def _pick_date(page, picker_automation_id: str, target: date):
    """Opens the given DatePicker's calendar and clicks the target day,
    navigating months if the initially-displayed month doesn't match.

    Confirmed live (2026-08-18) — this took real investigation, not blind
    waits, to get right: the Start and End date pickers **share a single
    reused `.ms-Callout` DOM node** for their calendar popup (confirmed by
    inspecting element count/content before vs. after opening each) — it is
    NOT recreated per picker. That means `wait_for_selector(".ms-Callout")`
    is a USELESS "did it open for THIS field" signal: the element is present
    the moment the panel loads, whichever field last used it. The real
    per-field signal is the combobox's own `aria-expanded` attribute — but
    even that flips to `"true"` before the shared callout's CONTENT has
    actually finished re-rendering for the new field (confirmed: an extra
    ~1s settle wait after aria-expanded is what actually fixed End-date
    picks landing on the wrong day). Verifying the field's displayed value
    after clicking, and retrying the whole pick from scratch if it doesn't
    match, remains as a second line of defense in case this timing is ever
    borderline again."""
    combobox_sel = f'[data-automation-id="{picker_automation_id}"] [role="combobox"]'
    target_label = f"{target.day}, {_MONTHS[target.month - 1]}, {target.year}"
    expected_value = f"{target.year}-{target.month}-{target.day}"

    actual = None
    for _attempt in range(3):
        opened = False
        for _ in range(3):
            page.click(combobox_sel, timeout=NAV_TIMEOUT_MS)
            page.wait_for_timeout(200)
            page.keyboard.press("Enter")
            try:
                page.wait_for_function(
                    "(sel) => document.querySelector(sel)?.getAttribute('aria-expanded') === 'true'",
                    arg=combobox_sel, timeout=3_000,
                )
                page.wait_for_timeout(1_000)  # let the shared callout's content re-bind to this field
                opened = True
                break
            except PlaywrightTimeoutError:
                continue
        if not opened:
            continue  # retry the whole pick from scratch

        for _ in range(6):  # up to 6 months of navigation either direction
            btn = page.locator(f'.ms-Callout button[aria-label="{target_label}"]')
            if btn.count() > 0:
                btn.first.click(timeout=5_000, force=True)
                page.wait_for_timeout(500)
                break
            # Not visible in the current month view — read the header to
            # decide which direction to navigate, then click the prev/next
            # arrow (the first/second headerIconButton in DOM order).
            header = page.locator(".ms-Callout .ms-DatePicker-monthAndYear, .ms-Callout [class*='monthAndYear']")
            header_text = header.first.inner_text() if header.count() > 0 else ""
            m = re.match(r"(\w+)\s+(\d{4})", header_text.strip())
            nav_buttons = page.locator(".ms-Callout button[class*='headerIconButton']")
            if not m or nav_buttons.count() < 2:
                break
            shown_month, shown_year = _MONTHS.index(m.group(1)) + 1, int(m.group(2))
            target_ord = target.year * 12 + target.month
            shown_ord = shown_year * 12 + shown_month
            nav_buttons.nth(0 if target_ord < shown_ord else 1).click(timeout=5_000)
            page.wait_for_timeout(500)

        actual = _field_value(page, picker_automation_id)
        if actual == expected_value:
            return
        page.keyboard.press("Escape")  # close any stray open callout before retrying
        page.wait_for_timeout(300)

    raise RuntimeError(
        f"Could not select {target_label} for {picker_automation_id} after 3 attempts (field shows {actual!r})"
    )


def _pick_time(page, dropdown_automation_id: str, hhmm: str):
    """The Start/End date fields each have an adjacent time-of-day dropdown
    (`NewMessageTracePanel_{Start,End}Time_Dropdown`, confirmed live) that
    defaults to the CURRENT wall-clock time and was never touched before —
    that's why a run at, say, 11:00 covered [day 11:00, day+1 11:00) instead
    of the full calendar day, silently missing that morning's early mail and
    bleeding into the next day's. Fixed 30-minute-increment options, 00:00
    through 23:30 (confirmed live: 48 options, no exact 23:59).

    Two things confirmed live and NOT to redo: (1) `force=True` on the
    option click is actively wrong here — it clicks the option's ORIGINAL
    (pre-render-settle) coordinates, which land on a different, already-
    shifted option by the time the click actually fires (confirmed: force
    click aimed at "00:00" landed on "11:00" instead). A plain click with a
    generous pre-click wait, letting Playwright's own stability check do its
    job, is correct. (2) the dropdown's own `textContent` includes a hidden
    chevron-icon glyph character appended after the visible text (e.g.
    `"00:00\\ue70d"`) — comparing that raw string against `hhmm` always
    fails even on a successful selection; read `.ms-Dropdown-title` instead,
    which holds just the clean value."""
    for _attempt in range(3):
        page.click(f'[data-automation-id="{dropdown_automation_id}"]', timeout=NAV_TIMEOUT_MS)
        page.wait_for_timeout(1_200)
        option = page.get_by_role("option", name=hhmm, exact=True)
        if option.count() == 0:
            page.keyboard.press("Escape")
            page.wait_for_timeout(300)
            continue
        option.click(timeout=10_000)
        page.wait_for_timeout(300)
        actual = page.eval_on_selector(
            f'[data-automation-id="{dropdown_automation_id}"] .ms-Dropdown-title', "el => el ? el.textContent : ''"
        )
        if actual and actual.strip() == hhmm:
            return
        page.keyboard.press("Escape")
        page.wait_for_timeout(300)

    raise RuntimeError(f"Could not select {hhmm!r} on {dropdown_automation_id} after 3 attempts")


def _search_and_export(page, domain: str, day: date) -> Path:
    """Fills the "New message trace" panel (Summary report, the default —
    instant, no async job), runs the search, and exports all results.
    Returns the raw downloaded file (caller renames/moves it)."""
    _open_new_trace(page)
    _set_recipient_filter(page, domain)
    # Start and End both on the SAME calendar day, 00:00 -> 23:30 (the full
    # day, modulo the last 30 minutes the dropdown can't express) — confirmed
    # live (2026-08-18) this returns real results (548 items) even though
    # 23:30 today is technically later than "now". That settles what the
    # 2026-08-05 A/B sweep left ambiguous: the "0 items" failure mode was
    # never about Start==End per se, it was the UNTOUCHED time dropdowns
    # both defaulting to the same current-time value, producing a genuinely
    # zero-width window — a real datetime span on the same calendar day was
    # never actually tested until now. Explicit day+1/day-1 branching for
    # "day is today" is no longer needed as a result.
    _pick_date(page, "NewMessageTracePanel_StartDate_DatePicker", day)
    _pick_time(page, "NewMessageTracePanel_StartTime_Dropdown", "00:00")
    _pick_date(page, "NewMessageTracePanel_EndDate_DatePicker", day)
    _pick_time(page, "NewMessageTracePanel_EndTime_Dropdown", "23:30")

    page.get_by_role("button", name="Search", exact=True).click(timeout=NAV_TIMEOUT_MS)
    # Wait for the grid to actually settle (either real rows or the genuine
    # empty state) instead of a fixed sleep — "0 items" can appear transiently
    # while the query is still in flight.
    page.wait_for_selector("text=/No data available|\\d+ items?/", timeout=NAV_TIMEOUT_MS)
    page.wait_for_timeout(1500)

    page.get_by_text("Export results", exact=False).first.click(timeout=NAV_TIMEOUT_MS)
    page.wait_for_timeout(1000)
    page.get_by_text("Export all results", exact=False).first.click(timeout=NAV_TIMEOUT_MS)
    page.wait_for_timeout(1000)  # "Export could take some time..." confirmation dialog

    with page.expect_download(timeout=NAV_TIMEOUT_MS) as download_info:
        page.get_by_role("button", name="Continue", exact=True).click(timeout=NAV_TIMEOUT_MS)
    return download_info.value


def run_message_trace(domain: str, day: date) -> Path:
    """Returns the path to the downloaded CSV for `recipient contains
    @{domain}` on `day`. Raises ReauthRequiredError if login/MFA blocks
    progress, or RuntimeError (with a saved screenshot) on any other
    unexpected page state."""
    if sync_playwright is None:
        raise RuntimeError("playwright is not installed — run: pip install playwright && playwright install chromium")
    if not PORTAL_URL:
        raise RuntimeError("EXCHANGE_PORTAL_URL is not set in .env")

    _ensure_dirs()
    day_str = day.strftime("%Y-%m-%d")
    tag = f"{domain.replace('.', '_')}_{day_str}"

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR), headless=False, accept_downloads=True,
        )
        try:
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(PORTAL_URL, timeout=NAV_TIMEOUT_MS)
            page.wait_for_timeout(3000)
            _handle_login(page)

            # Every successful live test this session included a reload here
            # before opening the trace panel; runs that skipped it (going
            # straight from goto() to opening the panel) consistently came
            # back with "0 items" despite an identical filter/date setup —
            # empirically necessary even though the exact SPA-state reason
            # isn't fully understood. Cheap, so keep it unconditionally.
            page.reload(timeout=NAV_TIMEOUT_MS)
            page.wait_for_timeout(2000)

            try:
                download = _search_and_export(page, domain, day)
                dest = CSV_DIR / f"{tag}.csv"
                download.save_as(str(dest))
                return dest
            except PlaywrightTimeoutError as e:
                _fail_with_screenshot(
                    page, tag,
                    f"Message trace flow for {domain} on {day_str} didn't match the expected page "
                    f"layout at some step ({e}) — see exchange_fetch.py's docstring for what's confirmed.",
                )
        finally:
            context.close()
