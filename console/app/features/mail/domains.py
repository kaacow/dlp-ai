"""Internal-domain list for the mail exfiltration detector, lifted straight from
`triage_agent/app/destinations.py`'s `INTERNAL_DOMAIN_SUFFIXES` (kept as a
separate tiny module here rather than pulling in that file's much larger
`DESTINATION_CATEGORIES` dict, which classifies file-send `app_desc` values and
isn't relevant to mail recipient domains).

Replace these with your own organisation's domains (or set DLP_INTERNAL_DOMAINS).
"""

INTERNAL_DOMAIN_SUFFIXES = [
    "example-corp.com",
    "examplecorp.sharepoint.com",
    "examplecorp-my.sharepoint.com",
    "shop.example-corp.com",
]

# The domain employees' own AD-username-pattern corporate mail addresses live
# on — used by detector.py's self_corporate rule to build the expected
# "{username}@{PRIMARY_INTERNAL_DOMAIN}" address.
PRIMARY_INTERNAL_DOMAIN = "example-corp.com"

# Domains where a self-send (sender mailing their own mailbox, and only their
# own mailbox — no other recipient) should be flagged as "self (corporate)"
# rather than silently cleared as ordinary internal traffic. A secondary
# corporate domain with employee mailboxes gets the same check as the primary one.
SELF_CORPORATE_DOMAINS = {PRIMARY_INTERNAL_DOMAIN, "shop.example-corp.com"}


def is_internal_domain(domain: str) -> bool:
    domain = (domain or "").lower()
    return any(domain == suf or domain.endswith("." + suf) for suf in INTERNAL_DOMAIN_SUFFIXES)


# Personal-webmail domains checked via the Exchange-sourced detector
# (exchange_csv.py / runner_exchange.py). Each domain needs its own per-day
# message-trace search — a wildcard "from:* to:*" search silently truncated
# results for the user in practice, while narrow per-domain recipient
# searches (what they already did for Gmail) come back complete. Kept short
# and explicit rather than a long guessed list: gmail.com is the primary target. Corporate self-send (sender == recipient) intentionally stays
# on the DLP-based detector (see SELF_CORPORATE_DOMAINS above) rather than
# being added here — Exchange has no server-side "sender equals recipient"
# filter, so that check would need the same kind of wildcard internal-mail
# pull that already proved unreliable.
PERSONAL_WATCH_DOMAINS = ["gmail.com", "mail.ru"]
