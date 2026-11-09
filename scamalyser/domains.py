"""Domain helpers.

The key idea here is the *registrable domain* (also called eTLD+1): the part
of a hostname that someone actually bought from a registrar.

    login.paypal.com          -> paypal.com
    paypal.com.secure-id.xyz  -> secure-id.xyz   (attacker owns this one!)
    mail.bbc.co.uk            -> bbc.co.uk       (co.uk is a public suffix)

Comparing registrable domains, not raw hostnames, is what stops
"paypal.com.secure-id.xyz" from looking like PayPal. We use the Public
Suffix List (via tldextract) rather than "last two labels", because the
naive approach gets "co.uk" style suffixes wrong.
"""

from __future__ import annotations

from email.utils import parseaddr

import tldextract

# suffix_list_urls=() forces tldextract to use the copy of the Public Suffix
# List bundled with the package, so analysis never makes a network request
# unless the user explicitly asks for online checks.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def normalise_host(host: str) -> str:
    """Lower-case a hostname and strip a trailing dot and any port."""
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:   # IPv6 literal like [::1]:443
        return host[1:host.index("]")]
    if host.count(":") == 1:                   # host:port
        host = host.split(":", 1)[0]
    return host


def registrable_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) of a hostname.

    Falls back to the cleaned host if it has no recognised public suffix
    (e.g. "localhost" or a bare IP address).
    """
    host = normalise_host(host)
    parts = _extract(host)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return host


def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, domain label, public suffix) for a hostname."""
    parts = _extract(normalise_host(host))
    return parts.subdomain, parts.domain, parts.suffix


def address_domain(header_value: str | None) -> str | None:
    """Extract the lower-cased domain from an address header value.

    "PayPal <service@paypal.com>" -> "paypal.com"
    """
    if not header_value:
        return None
    _, addr = parseaddr(header_value)
    if "@" not in addr:
        return None
    return normalise_host(addr.rsplit("@", 1)[1]) or None
