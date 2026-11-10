"""SPF, DKIM and DMARC: did the sending domain actually authorise this email?

Quick refresher (expect to be asked about this):

* SPF   - the domain in the envelope sender (Return-Path) publishes a DNS list
          of IPs allowed to send for it. Checked against the connecting IP.
* DKIM  - the sending server signs selected headers + body with a private key;
          the public key lives in DNS. Proves the content wasn't altered and
          that the signing domain (d=) sent it.
* DMARC - ties the two together with the domain the *user sees* in From:.
          It passes only if SPF or DKIM passed AND that domain aligns with
          From:. The domain owner's policy (p=none/quarantine/reject) says what
          receivers should do on failure.

Why we read Authentication-Results instead of redoing SPF ourselves:
SPF needs the IP address of the server that connected to *your* mail server.
Only the receiving server knew that, and it records its verdict in the
Authentication-Results header. We trust only the topmost one, because headers
lower down were added before your server and can be forged by the sender.

Online mode (--online) adds what we *can* check independently afterwards:
re-verify the DKIM signature cryptographically and look up the From domain's
DMARC policy in DNS.
"""

from __future__ import annotations

import re

from ..domains import address_domain
from ..findings import Finding, Severity
from ..parser import ParsedEmail

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

# Points awarded for a failing result. DMARC fail is the strongest signal
# because it means the domain shown in From: did not authorise the message.
_FAIL_POINTS = {
    "spf": {"fail": 15, "softfail": 8},
    "dkim": {"fail": 15},
    "dmarc": {"fail": 30},
}


def parse_auth_results(email: ParsedEmail) -> dict[str, str]:
    """Return e.g. {"spf": "pass", "dkim": "fail", "dmarc": "fail"}.

    Uses only the topmost Authentication-Results header (see module docstring).
    Falls back to Received-SPF for SPF if Authentication-Results lacks it.
    """
    results: dict[str, str] = {}
    headers = email.headers.get_all("Authentication-Results") or []
    if headers:
        for method, verdict in _RESULT_RE.findall(str(headers[0])):
            # First verdict per method wins (multiple DKIM signatures can appear).
            results.setdefault(method.lower(), verdict.lower())
    received_spf = email.headers.get_all("Received-SPF") or []
    if "spf" not in results and received_spf:
        first_word = str(received_spf[0]).strip().split(None, 1)
        if first_word:
            results["spf"] = first_word[0].lower()
    return results


def check_auth_headers(email: ParsedEmail) -> list[Finding]:
    results = parse_auth_results(email)
    if not results:
        return [Finding(
            "auth.missing", Severity.INFO, 0,
            "No authentication results found",
            "The email has no Authentication-Results or Received-SPF header, so "
            "SPF/DKIM/DMARC verdicts from the receiving server are unknown. This "
            "is normal for emails saved from some clients; try --online.",
        )]

    findings: list[Finding] = []
    passed: list[str] = []
    for method in ("spf", "dkim", "dmarc"):
        verdict = results.get(method)
        if verdict is None:
            continue
        if verdict == "pass":
            passed.append(method.upper())
            continue
        points = _FAIL_POINTS[method].get(verdict, 0)
        severity = (Severity.HIGH if points >= 15 else
                    Severity.MEDIUM if points else Severity.INFO)
        findings.append(Finding(
            f"auth.{method}_{verdict}", severity, points,
            f"{method.upper()} {verdict}",
            _explain(method, verdict),
        ))
    if passed:
        findings.append(Finding(
            "auth.pass", Severity.INFO, 0,
            f"{'/'.join(passed)} pass",
            "The receiving server confirmed the sending domain authorised this email. "
            "This proves where it came from, not that the sender is honest: phishers "
            "pass these checks on domains they registered themselves, so a pass earns "
            "no points off.",
        ))
    return findings


def _explain(method: str, verdict: str) -> str:
    if verdict in ("none", "neutral"):
        return (f"No usable {method.upper()} result: the sending domain doesn't publish "
                "this protection or the message wasn't signed. Weak on its own, but "
                "large organisations almost always use SPF, DKIM and DMARC.")
    if verdict in ("temperror", "permerror"):
        return f"The receiving server hit an error checking {method.upper()} ({verdict})."
    if method == "spf":
        return ("The server that delivered this email is not on the sending domain's "
                f"list of allowed senders (SPF {verdict}).")
    if method == "dkim":
        return ("The DKIM signature did not verify: the message was altered in transit "
                "or the signature was forged.")
    return ("DMARC failed: the domain shown in the From: header did not authorise this "
            "message. This is the classic sign of a spoofed sender.")


# --------------------------------------------------------------------------
# Online checks. These need dnspython and dkimpy and make DNS queries, so they
# only run when the user passes --online.
# --------------------------------------------------------------------------

def check_dkim_signature(email: ParsedEmail) -> list[Finding]:
    import dkim  # dkimpy, imported lazily so offline use doesn't need it

    if not email.headers.get("DKIM-Signature"):
        return [Finding(
            "auth.dkim_unsigned", Severity.LOW, 5,
            "Email is not DKIM-signed",
            "Almost all legitimate bulk and corporate mail is DKIM-signed today. "
            "An unsigned email claiming to be from a large company is unusual.",
        )]
    try:
        valid = dkim.verify(email.raw)
    except Exception as exc:  # dkimpy raises a variety of DNS/parse errors
        return [Finding(
            "auth.dkim_error", Severity.INFO, 0,
            "DKIM signature could not be checked",
            f"Verification error: {exc}",
        )]
    if valid:
        return [Finding(
            "auth.dkim_verified", Severity.INFO, 0,
            "DKIM signature verified (online)",
            "The signature matches the public key currently published in DNS.",
        )]
    return [Finding(
        "auth.dkim_invalid", Severity.MEDIUM, 10,
        "DKIM signature invalid (online)",
        "Re-verifying the signature against the key in DNS failed. Either the email was "
        "modified, the key has since been rotated, or the signature is forged.",
    )]


def lookup_dmarc_policy(domain: str) -> str | None:
    """Return the DMARC policy ("none", "quarantine", "reject") or None if absent."""
    import dns.resolver

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    for rdata in answers:
        record = b"".join(rdata.strings).decode(errors="replace")
        if record.lower().startswith("v=dmarc1"):
            match = re.search(r"\bp\s*=\s*(\w+)", record, re.IGNORECASE)
            return match.group(1).lower() if match else "none"
    return None


def check_dmarc_policy(email: ParsedEmail) -> list[Finding]:
    domain = address_domain(email.from_header)
    if not domain:
        return []
    try:
        policy = lookup_dmarc_policy(domain)
    except Exception as exc:
        return [Finding("auth.dmarc_lookup_error", Severity.INFO, 0,
                        "DMARC policy lookup failed", f"DNS error for _dmarc.{domain}: {exc}")]
    if policy is None:
        return [Finding(
            "auth.dmarc_no_record", Severity.LOW, 5,
            f"{domain} publishes no DMARC policy",
            "Without DMARC, anyone can put this domain in the From: header and receivers "
            "have no instruction to reject it. Legitimate brands almost always have one.",
        )]
    if policy == "none":
        return [Finding(
            "auth.dmarc_policy_none", Severity.INFO, 0,
            f"{domain} has DMARC policy p=none",
            "The domain monitors spoofing but tells receivers not to block it.",
        )]
    return [Finding("auth.dmarc_policy", Severity.INFO, 0,
                    f"{domain} has DMARC policy p={policy}", "Spoofing of this domain should be blocked.")]


def run(email: ParsedEmail, online: bool = False) -> list[Finding]:
    findings = check_auth_headers(email)
    if online:
        findings += check_dkim_signature(email)
        findings += check_dmarc_policy(email)
    return findings
