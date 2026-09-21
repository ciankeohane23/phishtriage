"""The detection rules.

Every check here is deterministic: same email in, same findings out, with a
reason a human can verify. No model is involved at this stage. That is on
purpose, because a triage note that cannot be checked is worse than no note.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .parsing import RISKY_EXTENSIONS, ParsedEmail, domain_of

SEVERITIES = ("high", "medium", "low")

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

URGENCY_PHRASES = [
    "act now", "immediate action", "immediately", "within 24 hours", "expires today",
    "final notice", "last warning", "urgent", "suspended", "will be closed",
    "failure to comply", "avoid termination", "verify now",
]

CREDENTIAL_PHRASES = [
    "verify your account", "confirm your password", "update your password",
    "re-enter your credentials", "validate your login", "confirm your identity",
    "sign in to avoid", "update your payment details", "confirm your bank",
]

IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_LIKE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.I)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    detail: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")


@dataclass
class Config:
    """Domains this mailbox legitimately deals with.

    Lookalike detection is only meaningful relative to a list of things worth
    imitating, so this is the knob an analyst actually tunes.
    """

    trusted_domains: set[str] = field(default_factory=lambda: {
        "microsoft.com", "office365.com", "google.com", "apple.com",
        "adventinternational.com", "ucc.ie", "revenue.ie", "aib.ie", "boi.com",
    })
    similarity_threshold: float = 0.78


def _similar(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def check_authentication(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    auth = mail.auth
    if not auth.present:
        return [Finding(
            "AUTH_ABSENT", "low", "No authentication results",
            "The receiving server recorded no SPF, DKIM or DMARC result. "
            "Nothing can be concluded from this either way.",
        )]

    out = []
    for name, value in (("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)):
        if value in {"fail", "softfail", "permerror", "temperror"}:
            out.append(Finding(
                f"AUTH_{name}_FAIL", "high", f"{name} did not pass",
                f"{name} result was '{value}'. The sender is not authorised to send "
                f"for {mail.from_domain or 'this domain'}, or the message was altered.",
            ))
        elif value is None:
            out.append(Finding(
                f"AUTH_{name}_MISSING", "low", f"No {name} result",
                f"The authentication header did not report a {name} result.",
            ))
    return out


def check_reply_path(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    out = []
    if mail.reply_to_domain and mail.reply_to_domain != mail.from_domain:
        out.append(Finding(
            "REPLY_TO_MISMATCH", "high", "Replies go to a different domain",
            f"From is {mail.from_domain} but Reply-To is {mail.reply_to_domain}. "
            "A reply would leave the conversation the sender appears to be in.",
        ))
    if mail.return_path_domain and mail.return_path_domain != mail.from_domain:
        out.append(Finding(
            "RETURN_PATH_MISMATCH", "medium", "Bounce address differs from sender",
            f"From is {mail.from_domain} but Return-Path is {mail.return_path_domain}. "
            "Common in legitimate bulk mail, so weigh it with the other findings.",
        ))
    return out


def check_lookalike_sender(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    sender = mail.from_domain
    if not sender or sender in cfg.trusted_domains:
        return []

    for trusted in cfg.trusted_domains:
        score = _similar(sender, trusted)
        if score >= cfg.similarity_threshold:
            return [Finding(
                "LOOKALIKE_DOMAIN", "high", "Sender domain resembles a known domain",
                f"{sender} is {score:.0%} similar to {trusted} without being it.",
            )]
    return []


def check_display_name(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    display = mail.from_display.lower()
    if not display or not mail.from_domain:
        return []

    for trusted in cfg.trusted_domains:
        brand = trusted.split(".")[0]
        if brand and brand in display and not mail.from_domain.endswith(trusted):
            return [Finding(
                "DISPLAY_NAME_IMPERSONATION", "high", "Display name claims another organisation",
                f"The sender shows as '{mail.from_display}' but the address is on "
                f"{mail.from_domain}, which is not {trusted}.",
            )]
    return []


def check_link_text(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    out = []
    for link in mail.links:
        if not link.text or not link.host:
            continue

        # Text that reads like a URL is a promise about where the link goes.
        claimed = None
        if link.text.lower().startswith(("http://", "https://")):
            claimed = (urlparse(link.text).hostname or "").lower()
        else:
            match = DOMAIN_LIKE.search(link.text)
            if match and "." in match.group(1):
                claimed = match.group(1).lower()

        if claimed and claimed != link.host and not link.host.endswith("." + claimed):
            out.append(Finding(
                "LINK_TEXT_MISMATCH", "high", "Link text does not match its destination",
                f"The text reads '{link.text.strip()}' but the link goes to {link.host}.",
            ))
    return out


def check_link_hosts(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    out, seen = [], set()
    for link in mail.links:
        host = link.host
        if not host or host in seen:
            continue
        seen.add(host)

        if IPV4.match(host):
            out.append(Finding(
                "URL_IP_LITERAL", "high", "Link points at a bare IP address",
                f"{link.href} uses {host} instead of a hostname, which avoids anything "
                "a domain name would reveal.",
            ))
        if host.startswith("xn--") or ".xn--" in host:
            out.append(Finding(
                "URL_PUNYCODE", "high", "Link uses a punycode domain",
                f"{host} is an encoded internationalised domain, often used to build "
                "a domain that reads like a familiar one.",
            ))
        if host in URL_SHORTENERS:
            out.append(Finding(
                "URL_SHORTENER", "medium", "Link is behind a shortener",
                f"{host} hides the real destination until it is followed.",
            ))
    return out


def check_attachments(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    out = []
    for att in mail.attachments:
        if att.extension in RISKY_EXTENSIONS:
            out.append(Finding(
                "RISKY_ATTACHMENT", "high", "Attachment of a type used to deliver malware",
                f"'{att.filename}' is a {att.extension} file ({att.content_type}).",
            ))
    return out


def _phrase_hits(haystack: str, phrases: list[str]) -> list[str]:
    low = haystack.lower()
    return [p for p in phrases if p in low]


def check_pressure_language(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    text = f"{mail.subject}\n{mail.body_text}"
    hits = _phrase_hits(text, URGENCY_PHRASES)
    if len(hits) < 2:
        return []
    return [Finding(
        "URGENCY_LANGUAGE", "low", "Language pushes for a fast decision",
        "Phrases found: " + ", ".join(sorted(hits)[:5]) + ". Weak on its own; it matters "
        "when it sits beside a failed check.",
    )]


def check_credential_request(mail: ParsedEmail, cfg: Config) -> list[Finding]:
    hits = _phrase_hits(f"{mail.subject}\n{mail.body_text}", CREDENTIAL_PHRASES)
    if not hits:
        return []
    return [Finding(
        "CREDENTIAL_REQUEST", "medium", "Message asks for credentials or payment details",
        "Phrases found: " + ", ".join(sorted(hits)[:5]) + ".",
    )]


CHECKS = (
    check_authentication,
    check_reply_path,
    check_lookalike_sender,
    check_display_name,
    check_link_text,
    check_link_hosts,
    check_attachments,
    check_pressure_language,
    check_credential_request,
)


def run_all(mail: ParsedEmail, cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(mail, cfg))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f.severity], f.code))
    return findings
