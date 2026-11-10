"""End-to-end: each sample email should land in the expected verdict band."""

import json

import pytest

from scamalyser.analyser import Verdict, analyse, score_findings
from scamalyser.cli import main
from scamalyser.findings import Finding, Severity


@pytest.mark.parametrize("name, verdict", [
    ("legit_newsletter.eml", Verdict.LOW),
    ("paypal_homoglyph.eml", Verdict.PHISHING),
    ("invoice_reply_to.eml", Verdict.PHISHING),
    ("microsoft_ip_link.eml", Verdict.PHISHING),
])
def test_sample_verdicts(sample, name, verdict):
    assert analyse(sample(name)).verdict is verdict


def test_score_is_sum_of_points_capped_at_100():
    f = lambda pts: Finding("x", Severity.HIGH, pts, "t", "d")
    assert score_findings([f(10), f(15)]) == (25, Verdict.SUSPICIOUS)
    assert score_findings([f(60), f(60)]) == (100, Verdict.PHISHING)
    assert score_findings([]) == (0, Verdict.LOW)


def test_every_point_is_explained(sample):
    report = analyse(sample("paypal_homoglyph.eml"))
    assert report.score == min(100, sum(f.points for f in report.findings))
    assert all(f.title and f.detail for f in report.findings)


def test_cli_json_and_exit_code(capsys):
    from conftest import SAMPLES
    code = main([str(SAMPLES / "paypal_homoglyph.eml"), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 2
    assert data["verdict"] == "LIKELY PHISHING"
    assert data["findings"][0]["points"] >= data["findings"][-1]["points"]


def test_cli_missing_file(capsys):
    assert main(["does-not-exist.eml"]) == 3


class _FakeStream:
    def __init__(self, tty: bool):
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.mark.parametrize("argv, tty, expected", [
    ([], True, True),                    # interactive terminal: show it
    ([], False, False),                  # piped or redirected: hide it
    (["--json"], True, False),           # JSON must stay machine-readable
    (["--no-banner"], True, False),
])
def test_banner_only_for_interactive_text_output(argv, tty, expected):
    from scamalyser.cli import build_parser, should_show_banner
    args = build_parser().parse_args(["x.eml", *argv])
    assert should_show_banner(args, _FakeStream(tty)) is expected


def test_cli_output_has_no_banner_when_captured(capsys):
    from conftest import SAMPLES
    from scamalyser.banner import BANNER
    main([str(SAMPLES / "legit_newsletter.eml")])
    assert BANNER not in capsys.readouterr().out
