"""Turn a raw .eml file into a ParsedEmail that the checks can work with.

Parsing is kept separate from detection on purpose: the checks never touch
raw MIME, they only look at the clean fields below. That makes each check
small and easy to unit-test with hand-built ParsedEmail objects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

# Good enough to find URLs in plain-text bodies. We deliberately stop at
# whitespace, quotes and angle brackets, which is where URLs end in practice.
_URL_RE = re.compile(r"""\bhttps?://[^\s<>"'()]+""", re.IGNORECASE)


@dataclass(frozen=True)
class Link:
    url: str
    text: str | None    # visible anchor text for HTML links, None for plain-text URLs


@dataclass
class ParsedEmail:
    raw: bytes
    headers: EmailMessage                  # full header access for checks that need it
    from_header: str
    from_name: str
    from_address: str
    reply_to: str | None
    return_path: str | None
    subject: str
    text_body: str
    html_body: str
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)


class _LinkExtractor(HTMLParser):
    """Collect every <a href="..."> together with the text the user sees."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append(Link(url=self._href.strip(), text=text or None))
            self._href = None


def _get_body(msg: EmailMessage, subtype: str) -> str:
    part = msg.get_body(preferencelist=(subtype,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        # Unknown or lying charset: phishing kits do this. Decode what we can.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def extract_links(text_body: str, html_body: str) -> list[Link]:
    links: list[Link] = []
    if html_body:
        extractor = _LinkExtractor()
        extractor.feed(html_body)
        links.extend(l for l in extractor.links if l.url.lower().startswith(("http://", "https://")))
    seen = {l.url for l in links}
    for match in _URL_RE.finditer(text_body):
        url = match.group(0).rstrip(".,;:!?")
        if url not in seen:
            links.append(Link(url=url, text=None))
            seen.add(url)
    return links


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    from_header = str(msg.get("From", ""))
    from_name, from_address = parseaddr(from_header)

    text_body = _get_body(msg, "plain")
    html_body = _get_body(msg, "html")

    attachments = [
        part.get_filename() or "(unnamed)"
        for part in msg.iter_attachments()
    ] if msg.is_multipart() else []

    return ParsedEmail(
        raw=raw,
        headers=msg,
        from_header=from_header,
        from_name=from_name,
        from_address=from_address.lower(),
        reply_to=str(msg["Reply-To"]) if msg["Reply-To"] else None,
        return_path=str(msg["Return-Path"]) if msg["Return-Path"] else None,
        subject=str(msg.get("Subject", "")),
        text_body=text_body,
        html_body=html_body,
        links=extract_links(text_body, html_body),
        attachments=attachments,
    )


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
