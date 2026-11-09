"""Brands that phishers impersonate, and the domains those brands really use.

Lookalike detection compares every domain in an email against this list.
It is deliberately small and editable: in an interview, the honest answer is
that a real product would load this from a maintained feed and also learn
the user's own organisation's domains.
"""

from __future__ import annotations

# brand keyword -> registrable domains the brand legitimately sends from or links to
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypal.me", "paypalobjects.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
                  "office.com", "office365.com", "sharepoint.com", "onmicrosoft.com"},
    "office365": {"office.com", "office365.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "appleid": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com", "amazonaws.com"},
    "google": {"google.com", "google.co.uk", "gmail.com", "googlemail.com", "youtube.com"},
    "gmail": {"gmail.com", "google.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.co.uk", "dhl.de"},
    "fedex": {"fedex.com"},
    "royalmail": {"royalmail.com", "royalmail.co.uk"},
    "hmrc": {"hmrc.gov.uk", "service.gov.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "hsbc": {"hsbc.co.uk", "hsbc.com"},
    "lloyds": {"lloydsbank.com", "lloydsbank.co.uk", "lloydsbankinggroup.com"},
    "natwest": {"natwest.com", "natwestgroup.com"},
    "santander": {"santander.co.uk", "santander.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "coinbase": {"coinbase.com"},
}

# Free webmail providers. A Reply-To at one of these on a "corporate" email
# is a strong sign the scammer wants replies somewhere they control.
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk",
    "live.com", "yahoo.com", "yahoo.co.uk", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.ru", "yandex.com",
    "zoho.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc",
}

# TLDs heavily abused for phishing because they are cheap or free.
# Source idea: Spamhaus / Interisle "most abused TLDs" reports. Low weight on
# its own: plenty of legitimate sites use these too.
SUSPICIOUS_TLDS = {
    "xyz", "top", "zip", "mov", "click", "link", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "rest", "cam", "icu", "buzz", "monster", "live", "shop",
}

ALL_LEGIT_DOMAINS = set().union(*BRANDS.values())
