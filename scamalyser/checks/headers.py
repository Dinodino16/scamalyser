"""Header spoofing checks: does the sender look like who they claim to be?

An email has several "who sent this" fields, and phishing often makes them
disagree:

* From:         what the user sees. Trivially forgeable without DMARC.
* Reply-To:     where replies go. Scammers point this at a mailbox they
                control while From: shows the real brand.
* Return-Path:  the envelope sender, where bounces go (and what SPF checks).
* Display name: the "PayPal Security" part. Many mail apps show *only* this,
                so it's the cheapest way to impersonate someone.
"""

from __future__ import annotations

import re

from ..brands import BRANDS, FREEMAIL_DOMAINS
from ..domains import address_domain, registrable_domain
from ..findings import Finding, Severity
from ..lookalike import LOOKALIKE_POINTS, find_lookalike, skeleton
from ..parser import ParsedEmail

_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

def check_reply_to(email: ParsedEmail, from_reg: str) -> list[Finding]:
    reply_domain = address_domain(email.reply_to)
    if not reply_domain:
        return []
    reply_reg = registrable_domain(reply_domain)
    if reply_reg == from_reg:
        return []
    if reply_reg in FREEMAIL_DOMAINS and from_reg not in FREEMAIL_DOMAINS:
        return [Finding(
            "headers.reply_to_freemail", Severity.HIGH, 25,
            "Replies go to a free webmail account",
            f"The email claims to be from {from_reg}, but replies are sent to {reply_domain}. "
            "A real organisation doesn't route replies to a personal Gmail/Outlook-style "
            "address; scammers do, because it's the inbox they actually read.",
        )]
    return [Finding(
        "headers.reply_to_mismatch", Severity.MEDIUM, 15,
        "Reply-To domain differs from From domain",
        f"From: is {from_reg} but Reply-To: is {reply_reg}. Replies would go to a "
        "different organisation than the one the email appears to come from.",
    )]


def check_return_path(email: ParsedEmail, from_reg: str) -> list[Finding]:
    rp_domain = address_domain(email.return_path)
    if not rp_domain:
        return []
    rp_reg = registrable_domain(rp_domain)
    if rp_reg == from_reg:
        return []
    # Low weight on purpose: newsletters sent through Mailchimp, SendGrid,
    # Amazon SES etc. legitimately use the provider's bounce domain here.
    return [Finding(
        "headers.return_path_mismatch", Severity.LOW, 5,
        "Return-Path domain differs from From domain",
        f"Bounces go to {rp_reg} while From: is {from_reg}. Common for legitimate "
        "mailing services, so weak on its own, but SPF then says nothing about the "
        "From: domain.",
    )]


def check_display_name(email: ParsedEmail, from_reg: str) -> list[Finding]:
    findings: list[Finding] = []
    name = email.from_name or ""

    # "service@paypal.com" <bob@evil.ru>: the name pretends to be an address.
    for embedded_domain in _EMAIL_IN_TEXT_RE.findall(name):
        if registrable_domain(embedded_domain) != from_reg:
            findings.append(Finding(
                "headers.display_name_spoof", Severity.HIGH, 25,
                "Display name contains a different email address",
                f"The sender's name is shown as '{name}', but the real address is "
                f"{email.from_address}. Mail apps that hide the real address make this "
                "look like a genuine sender.",
            ))
            break

    # "PayPal Support" <alerts@random-shop.biz>
    name_skel = skeleton(name.lower())
    tokens = set(re.split(r"[^a-z0-9]+", name_skel))
    compact = name_skel.replace(" ", "")
    for brand, legit in BRANDS.items():
        brand_skel = skeleton(brand)
        mentioned = brand_skel in tokens or (len(brand) >= 6 and brand_skel in compact)
        if mentioned and from_reg not in legit:
            findings.append(Finding(
                "headers.display_name_brand", Severity.HIGH, 20,
                f"Display name claims to be '{brand}' but address isn't",
                f"The name '{name}' suggests '{brand}', but the email was sent from "
                f"{from_reg}, which is not a domain '{brand}' uses.",
            ))
            break
    return findings


def check_from_lookalike(from_domain: str) -> list[Finding]:
    hit = find_lookalike(from_domain)
    if not hit:
        return []
    return [Finding(
        f"headers.from_{hit.technique}", Severity.HIGH, LOOKALIKE_POINTS[hit.technique],
        f"Sender domain imitates '{hit.brand}' ({hit.technique})",
        f"Sender domain {from_domain}: {hit.explanation}",
    )]


def run(email: ParsedEmail) -> list[Finding]:
    from_domain = address_domain(email.from_header)
    if not from_domain:
        return [Finding(
            "headers.no_from", Severity.MEDIUM, 10,
            "From: header missing or malformed",
            f"Could not read a sender address from {email.from_header!r}.",
        )]
    from_reg = registrable_domain(from_domain)
    return (
        check_from_lookalike(from_domain)
        + check_display_name(email, from_reg)
        + check_reply_to(email, from_reg)
        + check_return_path(email, from_reg)
    )
