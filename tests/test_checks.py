from scamalyser.checks import auth, headers, links
from scamalyser.parser import Link


def checks(findings):
    return {f.check for f in findings}


# ---- authentication -------------------------------------------------------

def test_auth_reads_topmost_authentication_results_only(make_email):
    # The lower header was added before our server and could be forged by the
    # sender, so its "pass" must be ignored.
    email = make_email("""
Authentication-Results: mx.ours.org; spf=fail; dkim=fail; dmarc=fail
Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass
From: a@b.com
""")
    assert auth.parse_auth_results(email) == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}


def test_auth_falls_back_to_received_spf(make_email):
    email = make_email("Received-SPF: softfail (reason)\nFrom: a@b.com")
    assert auth.parse_auth_results(email) == {"spf": "softfail"}


def test_auth_pass_earns_no_points(make_email):
    email = make_email("Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nFrom: a@b.com")
    findings = auth.run(email)
    assert sum(f.points for f in findings) == 0
    assert checks(findings) == {"auth.pass"}


def test_auth_dmarc_fail_scores_highest(make_email):
    email = make_email("Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\nFrom: a@b.com")
    by_check = {f.check: f.points for f in auth.run(email)}
    assert by_check["auth.dmarc_fail"] > by_check["auth.spf_fail"]


def test_auth_missing_is_informational(make_email):
    findings = auth.run(make_email("From: a@b.com"))
    assert checks(findings) == {"auth.missing"} and findings[0].points == 0


# ---- headers --------------------------------------------------------------

def test_reply_to_freemail(make_email):
    email = make_email("From: Billing <billing@acme-corp.com>\nReply-To: acme.billing@gmail.com")
    assert "headers.reply_to_freemail" in checks(headers.run(email))


def test_reply_to_other_company(make_email):
    email = make_email("From: billing@acme-corp.com\nReply-To: billing@acme-c0rp.net")
    assert "headers.reply_to_mismatch" in checks(headers.run(email))


def test_reply_to_same_organisation_subdomain_is_fine(make_email):
    email = make_email("From: news@acme-corp.com\nReply-To: support@help.acme-corp.com")
    assert checks(headers.run(email)) == set()


def test_display_name_with_fake_address(make_email):
    email = make_email('From: "support@paypal.com" <x@evil.ru>')
    assert "headers.display_name_spoof" in checks(headers.run(email))


def test_display_name_brand_from_wrong_domain(make_email):
    email = make_email('From: "Netflix Billing" <billing@streaming-help.net>')
    assert "headers.display_name_brand" in checks(headers.run(email))


def test_display_name_brand_from_real_domain_is_fine(make_email):
    email = make_email('From: "Netflix" <info@mailer.netflix.com>')
    assert checks(headers.run(email)) == set()


def test_return_path_mismatch_is_low_weight(make_email):
    email = make_email("From: noreply@github.com\nReturn-Path: <b@em1.sendgrid.net>")
    (finding,) = headers.run(email)
    assert finding.check == "headers.return_path_mismatch" and finding.points <= 5


# ---- links ----------------------------------------------------------------

def test_link_text_mismatch():
    found = checks(links.analyse_link(Link("https://evil.example/login", "https://www.paypal.com")))
    assert "links.text_mismatch" in found


def test_link_text_matching_same_site_is_fine():
    assert links.analyse_link(Link("https://www.github.com/settings", "github.com/settings")) == []


def test_link_ip_address():
    assert "links.ip_address" in checks(links.analyse_link(Link("http://203.0.113.5/x", None)))


def test_link_userinfo_trick():
    found = checks(links.analyse_link(Link("https://paypal.com@evil.example/", None)))
    assert "links.userinfo" in found


def test_link_shortener_and_tld():
    assert "links.shortener" in checks(links.analyse_link(Link("https://bit.ly/abc", None)))
    assert "links.suspicious_tld" in checks(links.analyse_link(Link("https://free-prizes.xyz", None)))


def test_repeated_links_counted_once(make_email):
    html = "".join(f'<a href="http://203.0.113.5/{i}">click</a>' for i in range(20))
    email = make_email("From: a@b.com", html)
    assert [f.check for f in links.run(email)].count("links.ip_address") == 1
