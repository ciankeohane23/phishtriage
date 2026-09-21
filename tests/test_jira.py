"""Tests against a fake Jira: a real HTTP server on localhost that records what it receives."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from phishtriage.cli import main
from phishtriage.jira import JiraConfig, JiraError, create_issue, issue_payload, to_adf
from phishtriage.report import Code

TOKEN = "not-a-real-token-123"


@pytest.fixture
def fake_jira():
    """Yields (base_url, state). Set state["status"] / state["reply"] to change the response."""
    state = {"requests": [], "status": 201, "reply": {"id": "10001", "key": "SEC-1"}}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            state["requests"].append({"path": self.path, "headers": dict(self.headers),
                                      "body": json.loads(body)})
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(state["reply"]).encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}", state
    server.shutdown()


def env_for(url):
    return {"JIRA_URL": url, "JIRA_EMAIL": "me@example.com",
            "JIRA_API_TOKEN": TOKEN, "JIRA_PROJECT": "SEC"}


def result(**overrides):
    base = {
        "file": "x.eml", "subject": "Pay now", "from": "a@evil.com", "from_display": "A",
        "reply_to": "", "return_path": "", "to": "", "date": "", "message_id": "",
        "link_hrefs": ["https://evil.com/login"], "attachments": [],
        "verdict": {"band": "High", "score": 12, "counts": {}},
        "findings": [{"code": "LINK_TEXT_MISMATCH", "severity": "high",
                      "title": "Link text does not match", "detail": "goes to evil.com"}],
        "note": "n", "note_source": "rules",
    }
    base.update(overrides)
    return base


# --- configuration ---

def test_missing_settings_are_named():
    with pytest.raises(JiraError, match="JIRA_API_TOKEN, JIRA_PROJECT"):
        JiraConfig.from_env({"JIRA_URL": "https://x.atlassian.net", "JIRA_EMAIL": "e"})


def test_plain_http_is_refused_for_a_real_site():
    # Basic auth over http would send the token in the clear.
    with pytest.raises(JiraError, match="https"):
        JiraConfig.from_env(env_for("http://x.atlassian.net"))


def test_trailing_slash_is_tolerated():
    assert JiraConfig.from_env(env_for("https://x.atlassian.net/")).url == "https://x.atlassian.net"


# --- payload ---

def test_payload_fields():
    cfg = JiraConfig.from_env(env_for("https://x.atlassian.net"))
    fields = issue_payload(result(), cfg)["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Task"}
    assert fields["summary"] == "Phishing triage [High, score 12]: Pay now"
    assert fields["labels"] == ["phishtriage", "risk-high"]
    assert fields["description"]["type"] == "doc"


def test_long_subject_is_cut_to_jiras_limit():
    cfg = JiraConfig.from_env(env_for("https://x.atlassian.net"))
    summary = issue_payload(result(subject="x" * 400), cfg)["fields"]["summary"]
    assert len(summary) == 255 and summary.endswith("...")


def test_observables_stay_defanged_in_jira():
    cfg = JiraConfig.from_env(env_for("https://x.atlassian.net"))
    body = json.dumps(issue_payload(result(), cfg))
    assert "https://evil.com" not in body
    assert "hxxps://evil[.]com/login" in body


def test_adf_text_nodes_are_never_empty():
    # Jira rejects the whole issue if any text node is empty.
    doc = to_adf([("table", ["A", "B"], [["", Code("")]]), ("para", "")])

    def texts(node):
        if node.get("type") == "text":
            yield node["text"]
        for child in node.get("content", []):
            yield from texts(child)

    assert all(t for t in texts(doc))


def test_code_cells_get_the_code_mark():
    doc = to_adf([("table", None, [["IP", Code("1[.]2[.]3[.]4")]])])
    value = doc["content"][0]["content"][0]["content"][1]["content"][0]["content"][0]
    assert value["marks"] == [{"type": "code"}]


# --- against the fake server ---

def test_create_issue_posts_with_basic_auth(fake_jira):
    url, state = fake_jira
    link = create_issue(result(), JiraConfig.from_env(env_for(url)))
    assert link == f"{url}/browse/SEC-1"
    req = state["requests"][0]
    assert req["path"] == "/rest/api/3/issue"
    expected = base64.b64encode(f"me@example.com:{TOKEN}".encode()).decode()
    assert req["headers"]["Authorization"] == f"Basic {expected}"


def test_jira_error_messages_come_through(fake_jira):
    url, state = fake_jira
    state["status"] = 400
    state["reply"] = {"errorMessages": [], "errors": {"issuetype": "Specify a valid issue type"}}
    with pytest.raises(JiraError, match="400: issuetype: Specify a valid issue type"):
        create_issue(result(), JiraConfig.from_env(env_for(url)))


def test_bad_token_gives_a_useful_message_without_the_token(fake_jira):
    url, state = fake_jira
    state["status"] = 401
    with pytest.raises(JiraError) as err:
        create_issue(result(), JiraConfig.from_env(env_for(url)))
    assert "JIRA_API_TOKEN" in str(err.value)
    assert TOKEN not in str(err.value)


def test_unreachable_jira_is_an_error_not_a_crash():
    with pytest.raises(JiraError, match="could not reach"):
        create_issue(result(), JiraConfig.from_env(env_for("http://127.0.0.1:9")), timeout=2)


def test_cli_creates_one_ticket_per_email(fake_jira, monkeypatch, capsys):
    url, state = fake_jira
    for k, v in env_for(url).items():
        monkeypatch.setenv(k, v)
    code = main(["samples/phish_credential_harvest.eml", "samples/legit_newsletter.eml",
                 "--jira", "--no-ai"])
    err = capsys.readouterr().err
    assert code == 1  # still reports that something was High
    assert len(state["requests"]) == 2
    assert err.count("jira: created") == 2
    assert TOKEN not in err


def test_cli_jira_failure_exits_3_and_still_prints_the_report(monkeypatch, capsys):
    for k in ("JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT"):
        monkeypatch.delenv(k, raising=False)
    code = main(["samples/legit_newsletter.eml", "--jira", "--no-ai"])
    captured = capsys.readouterr()
    assert code == 3
    assert "RISK" in captured.out
    assert "missing environment variable" in captured.err
