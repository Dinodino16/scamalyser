"""Link analysis: where would clicking actually take you?

The core phishing move is a link whose visible text says one thing
("https://www.paypal.com/account") while the href goes somewhere else. We
also flag URL patterns that legitimate companies avoid: raw IP addresses,
userinfo tricks (paypal.com@evil.com), punycode, shorteners hiding the
destination, and cheap throwaway TLDs.

Each kind of problem is reported once per domain, so a newsletter with
forty tracking links to the same host doesn't score forty times.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from ..brands import SUSPICIOUS_TLDS, URL_SHORTENERS
from ..domains import normalise_host, registrable_domain, split_host
from ..findings import Finding, Severity
from ..lookalike import LOOKALIKE_POINTS, decode_idn, find_lookalike
from ..parser import Link, ParsedEmail

# Anchor text that itself looks like a URL or bare domain, e.g. "www.paypal.com/login".
_DOMAIN_IN_TEXT_RE = re.compile(
    r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[/:\s]|$)", re.IGNORECASE)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyse_link(link: Link) -> list[Finding]:
    try:
        parts = urlsplit(link.url)
    except ValueError:
        return [Finding("links.malformed", Severity.LOW, 5, "Malformed link",
                        f"Could not parse {link.url!r}; malformed URLs are sometimes used "
                        "to confuse filters.")]
    host = normalise_host(parts.hostname or "")
    if not host:
        return []
    reg = registrable_domain(host)
    findings: list[Finding] = []

    if parts.username is not None or "@" in parts.netloc:
        findings.append(Finding(
            "links.userinfo", Severity.HIGH, 20, "Link hides its real destination with '@'",
            f"{link.url}: everything before '@' is ignored by the browser, so this goes to "
            f"{host}, not to the site named at the start.",
        ))

    if _is_ip(host):
        findings.append(Finding(
            "links.ip_address", Severity.HIGH, 20, "Link points to a raw IP address",
            f"{link.url}: legitimate companies link to their domain name, not to {host}. "
            "IP links are typical of throwaway phishing servers.",
        ))
        return findings  # domain-based checks below don't apply to an IP

    if link.text:
        shown = _DOMAIN_IN_TEXT_RE.search(link.text)
        if shown:
            shown_reg = registrable_domain(shown.group(1))
            if shown_reg != reg:
                findings.append(Finding(
                    "links.text_mismatch", Severity.HIGH, 25,
                    "Link text shows a different site than it opens",
                    f"The link says '{link.text}' but actually opens {host}.",
                ))

    hit = find_lookalike(host)
    if hit:
        findings.append(Finding(
            f"links.{hit.technique}", Severity.HIGH, LOOKALIKE_POINTS[hit.technique],
            f"Link domain imitates '{hit.brand}' ({hit.technique})",
            f"{host}: {hit.explanation}",
        ))

    if "xn--" in host:
        findings.append(Finding(
            "links.punycode", Severity.MEDIUM, 10, "Link uses an internationalised (punycode) domain",
            f"{host} displays as '{'.'.join(decode_idn(p) for p in host.split('.'))}'. "
            "Non-Latin characters can be used to imitate familiar domain names.",
        ))

    if reg in URL_SHORTENERS:
        findings.append(Finding(
            "links.shortener", Severity.LOW, 8, "Link uses a URL shortener",
            f"{link.url}: shorteners hide the final destination. Real companies rarely "
            "use them in account or payment emails.",
        ))

    _sub, _label, suffix = split_host(host)
    tld = suffix.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding(
            "links.suspicious_tld", Severity.LOW, 5, f"Link uses a frequently abused TLD (.{tld})",
            f"{host}: .{tld} domains are cheap and disproportionately used for phishing. "
            "Weak evidence alone.",
        ))

    if parts.scheme.lower() == "http":
        findings.append(Finding(
            "links.no_https", Severity.LOW, 3, "Link is not HTTPS",
            f"{link.url} is unencrypted. Any login or payment page should use HTTPS.",
        ))

    return findings


def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for link in email.links:
        try:
            host = normalise_host(urlsplit(link.url).hostname or "")
        except ValueError:
            host = ""
        key_domain = registrable_domain(host) if host else link.url
        for finding in analyse_link(link):
            key = (finding.check, key_domain)
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return findings
