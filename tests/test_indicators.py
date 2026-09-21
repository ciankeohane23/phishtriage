import pytest

from phishtriage.indicators import (
    Config, check_attachments, check_authentication, check_credential_request,
    check_display_name, check_lookalike_sender, check_link_hosts, check_link_text,
    check_pressure_language, check_reply_path, run_all,
)
from phishtriage.parsing import Attachment, AuthResults, Link, ParsedEmail

CFG = Config()


def codes(findings):
    return {f.code for f in findings}


def mail(**kwargs) -> ParsedEmail:
    return ParsedEmail(**kwargs)


# --- authentication -------------------------------------------------------

def test_spf_failure_is_high():
    m = mail(from_addr="a@example.com",
             auth=AuthResults(spf="fail", dkim="pass", dmarc="pass", raw="spf=fail"))
    findings = check_authentication(m, CFG)
    assert "AUTH_SPF_FAIL" in codes(findings)
    assert all(f.severity == "high" for f in findings if f.code == "AUTH_SPF_FAIL")


def test_softfail_counts_as_a_failure():
    m = mail(auth=AuthResults(spf="softfail", dkim="pass", dmarc="pass", raw="spf=softfail"))
    assert "AUTH_SPF_FAIL" in codes(check_authentication(m, CFG))


def test_all_passing_produces_nothing():
    m = mail(auth=AuthResults(spf="pass", dkim="pass", dmarc="pass", raw="spf=pass"))
    assert check_authentication(m, CFG) == []


def test_absent_header_is_low_not_high():
    findings = check_authentication(mail(), CFG)
    assert codes(findings) == {"AUTH_ABSENT"}
    assert findings[0].severity == "low"


# --- reply path -----------------------------------------------------------

def test_reply_to_on_another_domain_is_flagged():
    m = mail(from_addr="a@example.com", reply_to="b@attacker.test")
    assert "REPLY_TO_MISMATCH" in codes(check_reply_path(m, CFG))


def test_matching_reply_to_is_not_flagged():
    m = mail(from_addr="a@example.com", reply_to="support@example.com")
    assert "REPLY_TO_MISMATCH" not in codes(check_reply_path(m, CFG))


def test_return_path_mismatch_is_only_medium():
    m = mail(from_addr="a@example.com", return_path="<bounce@sendgrid.test>")
    findings = [f for f in check_reply_path(m, CFG) if f.code == "RETURN_PATH_MISMATCH"]
    assert findings and findings[0].severity == "medium"


# --- sender identity ------------------------------------------------------

def test_near_miss_domain_is_caught():
    m = mail(from_addr="alerts@micros0ft.com")
    assert "LOOKALIKE_DOMAIN" in codes(check_lookalike_sender(m, CFG))


def test_the_real_domain_is_not_flagged_against_itself():
    m = mail(from_addr="alerts@microsoft.com")
    assert check_lookalike_sender(m, CFG) == []


def test_an_unrelated_domain_is_not_flagged():
    m = mail(from_addr="hello@cork-bakery.ie")
    assert check_lookalike_sender(m, CFG) == []


def test_display_name_claiming_another_brand_is_flagged():
    m = mail(from_display="Microsoft Security", from_addr="x@totally-unrelated.test")
    assert "DISPLAY_NAME_IMPERSONATION" in codes(check_display_name(m, CFG))


def test_display_name_matching_its_own_domain_is_fine():
    m = mail(from_display="Microsoft Security", from_addr="x@microsoft.com")
    assert check_display_name(m, CFG) == []


# --- links ----------------------------------------------------------------

def test_link_text_promising_one_domain_and_going_elsewhere():
    m = mail(links=[Link("https://evil.test/login", "https://bank.example.com")])
    assert "LINK_TEXT_MISMATCH" in codes(check_link_text(m, CFG))


def test_subdomain_of_the_claimed_domain_is_allowed():
    m = mail(links=[Link("https://login.example.com/x", "example.com")])
    assert check_link_text(m, CFG) == []


def test_plain_call_to_action_text_is_not_a_promise():
    m = mail(links=[Link("https://anywhere.test/x", "Click here")])
    assert check_link_text(m, CFG) == []


def test_bare_ip_destination_is_high():
    m = mail(links=[Link("http://198.51.100.24/pay")])
    assert "URL_IP_LITERAL" in codes(check_link_hosts(m, CFG))


def test_punycode_host_is_flagged():
    m = mail(links=[Link("https://xn--80ak6aa92e.com/login")])
    assert "URL_PUNYCODE" in codes(check_link_hosts(m, CFG))


def test_shortener_is_medium():
    m = mail(links=[Link("https://bit.ly/abc")])
    findings = check_link_hosts(m, CFG)
    assert findings and findings[0].severity == "medium"


def test_each_host_is_only_reported_once():
    m = mail(links=[Link("https://bit.ly/a"), Link("https://bit.ly/b")])
    assert len(check_link_hosts(m, CFG)) == 1


# --- attachments and language --------------------------------------------

def test_zip_attachment_is_flagged():
    m = mail(attachments=[Attachment("invoice.zip", "application/zip")])
    assert "RISKY_ATTACHMENT" in codes(check_attachments(m, CFG))


def test_pdf_attachment_is_not_flagged():
    m = mail(attachments=[Attachment("invoice.pdf", "application/pdf")])
    assert check_attachments(m, CFG) == []


def test_a_single_urgent_word_is_not_enough():
    m = mail(subject="Urgent", body_text="Please read.")
    assert check_pressure_language(m, CFG) == []


def test_several_pressure_phrases_together_do_fire():
    m = mail(subject="Urgent: account suspended",
             body_text="Act now. Failure to comply will mean access is removed.")
    assert "URGENCY_LANGUAGE" in codes(check_pressure_language(m, CFG))


def test_credential_request_is_detected():
    m = mail(body_text="Please verify your account to continue.")
    assert "CREDENTIAL_REQUEST" in codes(check_credential_request(m, CFG))


# --- the whole set --------------------------------------------------------

def test_findings_come_back_sorted_with_high_first():
    m = mail(
        from_display="Microsoft Security",
        from_addr="a@micros0ft.com",
        reply_to="b@attacker.test",
        auth=AuthResults(spf="fail", dkim="fail", dmarc="fail", raw="spf=fail"),
        body_text="Verify your account. Act now. Urgent. Failure to comply is bad.",
        links=[Link("https://bit.ly/x")],
    )
    severities = [f.severity for f in run_all(m, CFG)]
    assert severities == sorted(severities, key=lambda s: ["high", "medium", "low"].index(s))


def test_a_clean_message_produces_no_findings():
    m = mail(
        from_display="UCC Student News",
        from_addr="news@ucc.ie",
        return_path="<news@ucc.ie>",
        auth=AuthResults(spf="pass", dkim="pass", dmarc="pass", raw="spf=pass"),
        body_text="The library opens at eight.",
        links=[Link("https://ucc.ie/library", "Library page")],
    )
    assert run_all(m, CFG) == []


def test_unknown_severity_is_rejected():
    from phishtriage.indicators import Finding
    with pytest.raises(ValueError):
        Finding("X", "catastrophic", "t", "d")
