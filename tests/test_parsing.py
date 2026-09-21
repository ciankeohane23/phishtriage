from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from phishtriage.parsing import ParsedEmail, domain_of, parse_bytes

SIMPLE = b"""From: Real Name <sender@example.com>
Reply-To: other@elsewhere.net
Return-Path: <bounce@mail.example.com>
Authentication-Results: mx.test; spf=pass smtp.mailfrom=example.com; dkim=fail; dmarc=none
Subject: A subject line
To: someone@example.org
Content-Type: text/plain; charset="utf-8"

Visit https://example.com/page for details.
"""

HTML_MAIL = b"""From: Sender <s@example.com>
Subject: Links
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<a href="https://evil.test/login">https://bank.example.com</a>
<a href="https://good.test/ok">Click here</a>
<a href="mailto:someone@example.com">mail me</a>
</body></html>
"""

WITH_ATTACHMENT = b"""From: A <a@example.com>
Subject: Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="xx"

--xx
Content-Type: text/plain

See attached.

--xx
Content-Type: application/zip; name="invoice.zip"
Content-Disposition: attachment; filename="invoice.zip"

cGxhY2Vob2xkZXI=

--xx--
"""


def test_headers_are_split_into_display_name_and_address():
    mail = parse_bytes(SIMPLE)
    assert mail.from_display == "Real Name"
    assert mail.from_addr == "sender@example.com"
    assert mail.from_domain == "example.com"
    assert mail.subject == "A subject line"


def test_reply_to_and_return_path_domains():
    mail = parse_bytes(SIMPLE)
    assert mail.reply_to_domain == "elsewhere.net"
    assert mail.return_path_domain == "mail.example.com"


def test_authentication_results_are_read_per_mechanism():
    auth = parse_bytes(SIMPLE).auth
    assert auth.spf == "pass"
    assert auth.dkim == "fail"
    assert auth.dmarc == "none"
    assert auth.present


def test_missing_authentication_header_is_distinguishable_from_a_failure():
    mail = parse_bytes(b"From: a@b.com\nSubject: none\n\nbody\n")
    assert mail.auth.present is False
    assert mail.auth.spf is None


def test_urls_in_plain_text_are_collected():
    mail = parse_bytes(SIMPLE)
    assert [l.href for l in mail.links] == ["https://example.com/page"]


def test_anchor_text_is_kept_with_its_destination():
    links = parse_bytes(HTML_MAIL).links
    hrefs = {l.href: l.text for l in links}
    assert hrefs["https://evil.test/login"] == "https://bank.example.com"
    assert hrefs["https://good.test/ok"] == "Click here"


def test_non_http_schemes_are_ignored():
    hosts = {l.href for l in parse_bytes(HTML_MAIL).links}
    assert not any(h.startswith("mailto:") for h in hosts)


def test_attachments_are_listed_with_their_extension():
    attachments = parse_bytes(WITH_ATTACHMENT).attachments
    assert len(attachments) == 1
    assert attachments[0].filename == "invoice.zip"
    assert attachments[0].extension == ".zip"


def test_domain_of_handles_junk():
    assert domain_of("") == ""
    assert domain_of("not an address") == ""
    assert domain_of("Name <UPPER@Example.COM>") == "example.com"


# Parsing runs on whatever arrives in the mailbox, including malformed and
# hostile input. It has to come back with a ParsedEmail rather than raise,
# because a crash here is a message that never gets triaged.
@settings(max_examples=250, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=2000))
def test_parsing_arbitrary_bytes_never_raises(data):
    assert isinstance(parse_bytes(data), ParsedEmail)
