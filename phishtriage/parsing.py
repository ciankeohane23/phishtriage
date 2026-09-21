"""Turn a raw .eml file into the fields the indicator checks need.

Nothing in here decides whether a mail is suspicious. It only reads.
Keeping parsing and judgement apart means the checks in indicators.py can be
tested against plain dataclasses instead of against raw MIME.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar",
    ".iso", ".img", ".lnk", ".hta", ".html", ".htm", ".zip", ".7z", ".rar",
}


@dataclass(frozen=True)
class Link:
    """A URL found in the mail, with the text it was hyperlinked from."""

    href: str
    text: str = ""

    @property
    def host(self) -> str:
        return (urlparse(self.href).hostname or "").lower()


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str

    @property
    def extension(self) -> str:
        _, _, ext = self.filename.rpartition(".")
        return f".{ext.lower()}" if ext else ""


@dataclass
class AuthResults:
    """What the receiving mail server said about SPF, DKIM and DMARC.

    `None` means the header did not mention that mechanism at all, which is
    different from it being present and failing.
    """

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    raw: str = ""

    @property
    def present(self) -> bool:
        return bool(self.raw.strip())


@dataclass
class ParsedEmail:
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    auth: AuthResults = field(default_factory=AuthResults)
    body_text: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)

    @property
    def reply_to_domain(self) -> str:
        return domain_of(self.reply_to)

    @property
    def return_path_domain(self) -> str:
        return domain_of(self.return_path)


def domain_of(address: str) -> str:
    """The domain part of an email address, lowercased. '' if there isn't one."""
    _, addr = parseaddr(address or "")
    _, _, dom = addr.partition("@")
    return dom.strip().strip(">").lower()


class _AnchorCollector(HTMLParser):
    """Pull out <a href> pairs so a link's text can be compared to where it goes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href.strip(), "".join(self._text).strip()))
            self._href, self._text = None, []


URL_PATTERN = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)


def _auth_results(raw: str) -> AuthResults:
    def mechanism(name: str) -> str | None:
        m = re.search(rf"\b{name}\s*=\s*([a-z]+)", raw, re.I)
        return m.group(1).lower() if m else None

    return AuthResults(
        spf=mechanism("spf"),
        dkim=mechanism("dkim"),
        dmarc=mechanism("dmarc"),
        raw=raw,
    )


def parse_bytes(data: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    return _from_message(msg)


def parse_file(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:
        return parse_bytes(fh.read())


def _from_message(msg) -> ParsedEmail:
    display, addr = parseaddr(str(msg.get("From", "")))

    parsed = ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_display=display.strip(),
        from_addr=addr.strip(),
        reply_to=str(msg.get("Reply-To", "")).strip(),
        return_path=str(msg.get("Return-Path", "")).strip(),
        to=str(msg.get("To", "")).strip(),
        date=str(msg.get("Date", "")).strip(),
        auth=_auth_results(str(msg.get("Authentication-Results", ""))),
    )

    text_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            parsed.attachments.append(
                Attachment(filename=str(filename), content_type=part.get_content_type())
            )
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            continue
        if not isinstance(content, str):
            continue
        if part.get_content_type() == "text/html":
            html_parts.append(content)
        else:
            text_parts.append(content)

    parsed.body_text = "\n".join(text_parts)

    seen: set[tuple[str, str]] = set()
    links: list[Link] = []

    for html in html_parts:
        collector = _AnchorCollector()
        collector.feed(html)
        for link in collector.links:
            if link.href.lower().startswith(("http://", "https://")):
                key = (link.href, link.text)
                if key not in seen:
                    seen.add(key)
                    links.append(link)

    for url in URL_PATTERN.findall(parsed.body_text):
        key = (url, "")
        if key not in seen:
            seen.add(key)
            links.append(Link(url))

    parsed.links = links
    return parsed
