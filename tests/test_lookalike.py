import pytest

from scamalyser.lookalike import edit_distance, find_lookalike, skeleton


@pytest.mark.parametrize("host, brand, technique", [
    ("paypa1.com", "paypal", "homoglyph"),
    ("rnicrosoft.com", "microsoft", "homoglyph"),
    ("xn--pypal-4ve.com", "paypal", "homoglyph"),      # Cyrillic 'а' in pаypal
    ("paypall.com", "paypal", "typosquat"),
    ("amazom.com", "amazon", "typosquat"),
    ("m1crosoft-online.top", "microsoft", "typosquat"),
    ("paypal-account-verify.com", "paypal", "combosquat"),
    ("appleid-verify.com", "appleid", "combosquat"),
    ("paypal.com.account-verify.xyz", "paypal", "subdomain"),
    ("paypal.xyz", "paypal", "wrong-tld"),
])
def test_detects_lookalikes(host, brand, technique):
    hit = find_lookalike(host)
    assert hit is not None, host
    assert (hit.brand, hit.technique) == (brand, technique)


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.co.uk", "login.microsoftonline.com", "accounts.google.com",
    "github.com", "stream.com", "email.com", "applebees.com", "amazing.com",
    "natwestgroup.com", "bbc.co.uk", "mailchimp.com",
])
def test_ignores_legitimate_domains(host):
    assert find_lookalike(host) is None


def test_skeleton_maps_lookalike_characters():
    assert skeleton("paypa1") == "paypal"
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("xn--pypal-4ve") == "paypal"


@pytest.mark.parametrize("a, b, expected", [
    ("paypal", "paypal", 0),
    ("paypall", "paypal", 1),   # insertion
    ("paypl", "paypal", 1),     # deletion
    ("paypak", "paypal", 1),    # substitution
    ("papyal", "paypal", 1),    # adjacent swap counts as one typo
    ("", "abc", 3),
])
def test_edit_distance(a, b, expected):
    assert edit_distance(a, b) == expected
