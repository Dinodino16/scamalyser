# Scamalyser

Does the email look suspicious? Find out!

Scamalyser reads a saved email (`.eml`) and tells you how likely it is to be
phishing, **and exactly why**. Every point in the 0-100 risk score comes from
a specific, plain-English finding, so the result can be checked rather than
just trusted.

```
$ scamalyser samples/paypal_homoglyph.eml -q
Subject: Your account has been limited
From:    PayPal Security <service@paypa1-secure.com>
Links:   2 checked

Risk score: 100/100  ->  LIKELY PHISHING

[+25] HIGH   Sender domain imitates 'paypal' (combosquat)
       Sender domain paypa1-secure.com: 'paypa1-secure.com' contains the brand
       name 'paypal' with extra words, a common way to make a fake domain look
       official.
[+25] HIGH   Link text shows a different site than it opens
       The link says 'https://www.paypal.com/myaccount' but actually opens
       paypal.com.account-verify.xyz.
[+25] HIGH   Link domain imitates 'paypal' (subdomain)
       paypal.com.account-verify.xyz: 'paypal' appears at the start of the
       address, but the domain actually owned is 'account-verify.xyz'.
...
```

## Install and run

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[online,dev]"

scamalyser path/to/email.eml       # human-readable report
scamalyser email.eml --json        # JSON, for scripts and the upcoming web UI
scamalyser email.eml --online      # also re-verify DKIM and look up DMARC in DNS
scamalyser email.eml -q            # hide informational (0-point) findings
scamalyser email.eml --no-banner   # skip the start-up banner (it never shows with --json or when piped)
pytest                             # run the test suite
```

To get a `.eml` file: in Gmail open the email, then **⋮ → Download message**.
In Outlook, drag the email to your desktop or use **File → Save As**.

Exit codes: `0` low risk, `1` suspicious, `2` likely phishing, `3` file error.

## What it checks

| Area | Check | Points |
|---|---|---|
| **Authentication** | DMARC fail (From: domain didn't authorise the email) | 30 |
| | SPF fail / softfail | 15 / 8 |
| | DKIM fail | 15 |
| | *online:* DKIM signature invalid / missing | 10 / 5 |
| | *online:* sender domain has no DMARC record | 5 |
| **Sender headers** | Sender domain is a lookalike of a brand | 25-35 |
| | Display name contains a different email address | 25 |
| | Reply-To is a free webmail address (Gmail, Outlook...) | 25 |
| | Display name claims a brand the address doesn't belong to | 20 |
| | Reply-To goes to a different organisation | 15 |
| | Return-Path domain differs from From: | 5 |
| **Links** | Link domain is a lookalike of a brand | 25-35 |
| | Visible link text shows a different site than the real link | 25 |
| | Link goes to a raw IP address | 20 |
| | `user@host` trick (`https://paypal.com@evil.com`) | 20 |
| | Punycode / internationalised domain | 10 |
| | URL shortener | 8 |
| | Frequently abused TLD (`.xyz`, `.top`, ...) | 5 |
| | Plain HTTP | 3 |

**Score** = sum of points, capped at 100.
**Verdict:** 0-24 low risk, 25-49 suspicious, 50+ likely phishing.

### Lookalike domains

Scamalyser catches five ways of faking a brand's domain:

| Technique | Example | How it's detected |
|---|---|---|
| Homoglyph | `paypa1.com`, `rnicrosoft.com`, `pаypal.com` (Cyrillic а) | Map look-alike characters to the letters they imitate, then compare |
| Typosquat | `paypall.com`, `amazom.com` | Damerau-Levenshtein edit distance of 1 (2 for long names) |
| Combosquat | `paypal-account-verify.com` | Brand name inside the domain with extra words |
| Subdomain trick | `paypal.com.account-verify.xyz` | Brand on the left, but the *registrable* domain is the attacker's |
| Wrong TLD | `paypal.xyz` | Exact brand name, not one of the brand's real domains |

The *registrable domain* (eTLD+1) is worked out with the Public Suffix List,
so `bbc.co.uk` is treated correctly instead of as "co.uk".

## Project layout

```
scamalyser/
  parser.py        .eml -> ParsedEmail (headers, bodies, links, attachments)
  checks/auth.py   SPF / DKIM / DMARC
  checks/headers.py  From / Reply-To / Return-Path / display-name spoofing
  checks/links.py  link analysis
  lookalike.py     homoglyph, typo, combo and subdomain impersonation
  domains.py       registrable-domain helpers (Public Suffix List)
  brands.py        brands, their real domains, freemail, shorteners, TLDs
  analyser.py      runs all checks, computes score and verdict
  cli.py           command-line interface
samples/           example emails (one legitimate, three phishing)
tests/             pytest suite
```

Parsing is separate from detection: checks only see a clean `ParsedEmail`,
never raw MIME, so each check is small and easy to test on its own.

## Design decisions

**Why points instead of machine learning?** Explainability. A score you can't
explain is useless to the person deciding whether to click, and ML needs a
large labelled dataset. The trade-off is that weights are hand-picked; the
test suite pins the expected verdict for each sample so tuning is safe.

**Why does passing SPF/DKIM/DMARC not lower the score?** Because it only
proves the email came from the domain it claims, not that the domain is
honest. A phisher who registers `paypa1-secure.com` can pass all three.

**Why read `Authentication-Results` instead of checking SPF myself?** SPF is
checked against the IP address that connected to *your* mail server, which
only that server knew. It records its verdict in `Authentication-Results`.
Scamalyser trusts only the **topmost** one: headers further down were added
before the email reached you and can be forged by the sender.

**Why is a Return-Path mismatch only 5 points?** Legitimate newsletters sent
through Mailchimp, SendGrid or Amazon SES use the provider's bounce domain.
Weighting it higher would flag half your inbox.

## Known limitations

- The brand list in `brands.py` is small and hand-maintained. A real product
  would use a maintained feed and add the user's own organisation's domains.
- Lookalike detection can still misfire on real domains close to a brand
  (e.g. `floyds.com` is one letter from `lloyds`). Short brand names get no
  typo allowance for this reason.
- `--online` checks DNS as it is *today*: a DKIM key rotated since the email
  was sent will make an old genuine email look invalid.
- No content analysis yet (urgency words, credential requests).
- Attachments are listed but not yet analysed.

## Roadmap

- [x] Week 1: parsing, SPF/DKIM/DMARC, header spoofing, link + lookalike analysis, risk score
- [ ] Week 2: attachment checks, larger sample test set, web UI, polish
