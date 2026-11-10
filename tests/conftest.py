from pathlib import Path

import pytest

from scamalyser.parser import parse_bytes, parse_file

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def sample():
    """Load one of the .eml files in samples/ by name."""
    return lambda name: parse_file(SAMPLES / name)


@pytest.fixture
def make_email():
    """Build a ParsedEmail from a few header lines and an optional HTML body."""
    def _make(headers: str, html: str = "") -> object:
        content_type = "text/html" if html else "text/plain"
        raw = (headers.strip() + f"\nContent-Type: {content_type}; charset=utf-8\n\n" + html)
        return parse_bytes(raw.encode())
    return _make
