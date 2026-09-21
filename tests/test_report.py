import hashlib
import re

from hypothesis import given
from hypothesis import strategies as st

from phishtriage.cli import main
from phishtriage.parsing import parse_bytes
from phishtriage.report import defang, next_steps, observables

from test_parsing import WITH_ATTACHMENT

LIVE_URL = re.compile(r"https?://", re.I)


def result(**overrides):
    base = {
        "file": "x.eml", "subject": "s", "from": "a@evil.com", "from_display": "A",
        "reply_to": "", "return_path": "", "to": "", "date": "", "message_id": "",
        "link_hrefs": [], "attachments": [],
        "verdict": {"band": "Low", "score": 0, "counts": {}},
        "findings": [], "note": "n", "note_source": "rules",
    }
    base.update(overrides)
    return base


# --- defanging ---

def test_defang_url():
    assert defang("https://evil.com/login") == "hxxps://evil[.]com/login"


def test_defang_address_and_ip():
    assert defang("bob@evil.com") == "bob[@]evil[.]com"
    assert defang("198.51.100.24") == "198[.]51[.]100[.]24"


def test_defang_is_idempotent():
    once = defang("http://a.b.example.com")
    assert defang(once) == once


@given(st.from_regex(r"https?://[a-z0-9.-]{1,30}(/[a-z0-9./?=&-]{0,30})?", fullmatch=True))
def test_defanged_url_is_never_clickable(url):
    # The whole point: nothing in a ticket should be a live link.
    out = defang(url)
    assert not LIVE_URL.search(out)
    assert "." not in out.replace("[.]", "")


# --- observables ---

def test_observables_pull_addresses_domains_and_ips():
    obs = observables(result(
        reply_to="Help <help@other.net>",
        link_hrefs=["http://198.51.100.24/pay", "https://login.other.net/x"],
    ))
    assert obs["addresses"] == ["a@evil.com", "help@other.net"]
    assert obs["domains"] == ["evil.com", "other.net", "login.other.net"]
    assert obs["ips"] == ["198.51.100.24"]


def test_observables_are_deduplicated():
    obs = observables(result(return_path="<a@evil.com>",
                             link_hrefs=["https://evil.com/a", "https://evil.com/a"]))
    assert obs["addresses"] == ["a@evil.com"]
    assert obs["domains"] == ["evil.com"]
    assert obs["urls"] == ["https://evil.com/a"]


def test_attachment_hash_is_of_the_decoded_file():
    att = parse_bytes(WITH_ATTACHMENT).attachments[0]
    assert re.fullmatch(r"[0-9a-f]{64}", att.sha256)
    assert att.sha256 != hashlib.sha256(b"").hexdigest()


# --- next steps ---

def test_high_always_escalates_first():
    assert next_steps("High", set())[0].startswith("Escalate")


def test_attachment_step_only_when_there_is_a_risky_attachment():
    assert not any("attachment" in s for s in next_steps("High", set()))
    assert any("attachment" in s for s in next_steps("High", {"RISKY_ATTACHMENT"}))


def test_low_never_claims_the_message_is_safe():
    text = " ".join(next_steps("Low", set())).lower()
    assert "not that the message is safe" in text


# --- end to end ---

def test_report_on_samples_has_no_live_links(capsys):
    code = main(["samples/phish_credential_harvest.eml",
                 "samples/phish_invoice_attachment.eml", "--report", "--no-ai"])
    out = capsys.readouterr().out
    assert code == 1
    assert out.count("## Phishing triage:") == 2
    assert "### Recommended next steps" in out
    assert not LIVE_URL.search(out)
