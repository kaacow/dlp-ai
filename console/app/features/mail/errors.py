"""Shared exception raised by any Exchange-side step (browser login, az CLI
lookup) that hit an authentication wall a human needs to clear — kept in its
own tiny module so azure_ad.py and exchange_fetch.py don't need to import
each other just to share this type."""


class ReauthRequiredError(Exception):
    pass
