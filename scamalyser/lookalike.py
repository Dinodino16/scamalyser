"""Lookalike (impersonation) domain detection.

Attackers register domains that *read* like a brand at a glance. We catch
four families of trick:

1. Homoglyphs     paypa1.com, rnicrosoft.com, pаypal.com (Cyrillic 'а')
                  -> after mapping lookalike characters to the letters they
                     imitate, the label becomes exactly the brand name.
2. Typosquats     paypall.com, amazom.com
                  -> one edit (insert/delete/substitute/swap) away from a brand.
3. Combosquats    paypal-account-verify.com
                  -> the brand name with extra words glued on.
4. Subdomain trick  paypal.com.account-verify.xyz
                  -> the brand appears on the left, but the registrable domain
                     (what the attacker owns) is account-verify.xyz.

Plus the simplest one: the exact brand on the wrong suffix (paypal.xyz).

Anything whose registrable domain is on the brand's real-domain list is
skipped, so login.paypal.com never triggers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .brands import ALL_LEGIT_DOMAINS, BRANDS
from .domains import registrable_domain, split_host

# Characters that imitate Latin letters. Cyrillic and Greek entries are the
# ones used in real IDN homograph attacks; digits cover "paypa1"-style tricks.
_CONFUSABLES = str.maketrans({
    # digits and symbols
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s",
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ӏ": "l", "ԁ": "d",
    "ѕ": "s", "ԛ": "q", "ԝ": "w", "һ": "h",
    # Greek
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x",
    # Latin letters with marks that are easy to miss
    "á": "a", "à": "a", "â": "a", "ä": "a", "ã": "a", "å": "a", "é": "e", "è": "e",
    "ê": "e", "ë": "e", "í": "i", "ì": "i", "ï": "i", "ó": "o", "ò": "o", "ô": "o",
    "ö": "o", "õ": "o", "ú": "u", "ù": "u", "ü": "u", "ý": "y", "ç": "c", "ñ": "n",
    "ł": "l", "ı": "i",
})
# Letter pairs that render like a single letter in many fonts.
_MULTI_CHAR = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def decode_idn(label: str) -> str:
    """Decode punycode (xn--...) labels to Unicode so homoglyphs are visible."""
    try:
        return label.encode("ascii").decode("idna") if "xn--" in label else label
    except (UnicodeError, ValueError):
        return label


def skeleton(label: str) -> str:
    """Reduce a domain label to the plain Latin letters it *looks* like."""
    s = decode_idn(label).lower().translate(_CONFUSABLES)
    for pair, single in _MULTI_CHAR:
        s = s.replace(pair, single)
    return s


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (optimal string alignment variant).

    Counts insertions, deletions, substitutions, and swaps of two adjacent
    letters, which are the four typos people actually make.
    """
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (prev2 is not None and i > 1 and j > 1
                    and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


# Risk points per technique, shared by the header and link checks.
LOOKALIKE_POINTS = {"homoglyph": 35, "typosquat": 30, "wrong-tld": 30,
                    "combosquat": 25, "subdomain": 25}


@dataclass(frozen=True)
class Lookalike:
    host: str
    brand: str
    technique: str    # "homoglyph" | "typosquat" | "combosquat" | "subdomain" | "wrong-tld"
    explanation: str


def _brand_in(text: str, brand: str) -> bool:
    """Is the brand present in text? Short brands must be a whole token
    (so "dhl" doesn't match "adhlab"); longer ones may be a substring
    (so "paypalsecure" still matches "paypal")."""
    if len(brand) >= 6:
        return brand in text
    return brand in re.split(r"[^a-z]+", text)


def find_lookalike(host: str) -> Lookalike | None:
    """Return the most serious impersonation technique detected, or None."""
    reg = registrable_domain(host)
    if reg in ALL_LEGIT_DOMAINS:
        return None
    subdomain, label, _suffix = split_host(host)
    if not label:
        return None
    raw = decode_idn(label).lower()
    skel = skeleton(label)
    skel_compact = skel.replace("-", "")

    # Brands are compared by skeleton too, so "office365" matches "office365"
    # even though its digits get mapped to letters.
    skel_brands = {brand: skeleton(brand) for brand in BRANDS}

    for brand, brand_skel in skel_brands.items():
        if raw == brand:
            return Lookalike(host, brand, "wrong-tld",
                             f"'{reg}' uses the exact name '{brand}' but is not one of "
                             f"{brand}'s real domains.")
        if skel_compact == brand_skel:
            return Lookalike(host, brand, "homoglyph",
                             f"'{raw}' looks like '{brand}' once look-alike characters are "
                             "swapped for the letters they imitate.")

    for brand, brand_skel in skel_brands.items():
        # Short names get no typo allowance: one edit from "steam" or "gmail" hits
        # innocent words ("stream", "email"). Long names tolerate two.
        max_typos = 2 if len(brand) >= 9 else 1 if len(brand) >= 6 else 0
        if not max_typos:
            continue
        # Check the whole label and each hyphen-separated word, so that
        # "mlcrosoft-online" is caught via its first word.
        for candidate in {skel_compact, *skel.split("-")}:
            distance = edit_distance(candidate, brand_skel)
            if 0 < distance <= max_typos:
                return Lookalike(host, brand, "typosquat",
                                 f"'{raw}' is {distance} typo(s) away from '{brand}'.")

    for brand, brand_skel in skel_brands.items():
        if _brand_in(skel, brand_skel):
            return Lookalike(host, brand, "combosquat",
                             f"'{reg}' contains the brand name '{brand}' with extra words, a "
                             "common way to make a fake domain look official.")

    sub_skel = skeleton(subdomain) if subdomain else ""
    for brand, brand_skel in skel_brands.items():
        if sub_skel and _brand_in(sub_skel, brand_skel):
            return Lookalike(host, brand, "subdomain",
                             f"'{brand}' appears at the start of the address, but the domain "
                             f"actually owned is '{reg}'.")
    return None
