"""Send the investigation ticket to Jira Cloud.

Uses the REST API v3 "create issue" endpoint with only the standard library, so
the detection engine still has no third-party dependencies.

The ticket body is the same `report.ticket()` structure the Markdown report is
rendered from, converted to Atlassian Document Format (ADF), which is the JSON
shape v3 expects for rich text. Observables stay defanged in Jira too.

Configuration comes from the environment and never from the command line, so the
API token does not end up in shell history or in a process listing:

    JIRA_URL        https://your-site.atlassian.net
    JIRA_EMAIL      the Atlassian account the token belongs to
    JIRA_API_TOKEN  from id.atlassian.com, Security, API tokens
    JIRA_PROJECT    the project key, e.g. SEC
    JIRA_ISSUE_TYPE optional, defaults to Task
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from .report import Code, ticket

SUMMARY_LIMIT = 255  # Jira rejects longer summaries


class JiraError(Exception):
    """Anything that stopped a ticket being created, with a message safe to print."""


@dataclass(frozen=True)
class JiraConfig:
    url: str
    email: str
    token: str
    project: str
    issue_type: str = "Task"

    @classmethod
    def from_env(cls, env: dict | None = None) -> "JiraConfig":
        env = os.environ if env is None else env
        names = ("JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT")
        missing = [n for n in names if not env.get(n)]
        if missing:
            raise JiraError("missing environment variable(s): " + ", ".join(missing))

        url = env["JIRA_URL"].rstrip("/")
        parsed = urlparse(url)
        local = parsed.hostname in ("localhost", "127.0.0.1")
        # Basic auth over plain HTTP would send the token in the clear.
        if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
            raise JiraError("JIRA_URL must start with https://")

        return cls(url=url, email=env["JIRA_EMAIL"], token=env["JIRA_API_TOKEN"],
                   project=env["JIRA_PROJECT"],
                   issue_type=env.get("JIRA_ISSUE_TYPE") or "Task")

    def auth_header(self) -> str:
        pair = f"{self.email}:{self.token}".encode()
        return "Basic " + base64.b64encode(pair).decode()


# ---------- ticket -> ADF ----------

def _text(value: str, *marks: str) -> dict:
    node = {"type": "text", "text": str(value) or " "}
    if marks:
        node["marks"] = [{"type": m} for m in marks]
    return node


def _para(*content: dict) -> dict:
    return {"type": "paragraph", "content": list(content)}


def _cell(value, header: bool = False) -> dict:
    marks = ("code",) if isinstance(value, Code) else ()
    return {"type": "tableHeader" if header else "tableCell",
            "content": [_para(_text(value, *marks))]}


def _list(kind: str, items: list[str]) -> dict:
    return {"type": kind,
            "content": [{"type": "listItem", "content": [_para(_text(i))]} for i in items]}


def to_adf(blocks: list[tuple]) -> dict:
    content = []
    for block in blocks:
        kind = block[0]
        if kind == "heading":
            content.append({"type": "heading", "attrs": {"level": 3},
                            "content": [_text(block[1])]})
        elif kind == "para":
            content.append(_para(_text(block[1])))
        elif kind == "italic":
            content.append(_para(_text(block[1], "em")))
        elif kind == "table":
            _, headers, rows = block
            table_rows = []
            if headers:
                table_rows.append({"type": "tableRow",
                                   "content": [_cell(h, header=True) for h in headers]})
            table_rows += [{"type": "tableRow", "content": [_cell(c) for c in row]}
                           for row in rows]
            content.append({"type": "table", "content": table_rows})
        elif kind == "checklist":
            # A plain bullet list: task lists need IDs and are fussier across Jira sites.
            content.append(_list("bulletList", [f"[ ] {i}" for i in block[1]]))
        elif kind == "numbered":
            content.append(_list("orderedList", block[1]))
    return {"type": "doc", "version": 1, "content": content}


def issue_payload(result: dict, cfg: JiraConfig) -> dict:
    _, blocks = ticket(result)
    v = result["verdict"]
    band = v["band"]
    summary = f"Phishing triage [{band}, score {v['score']}]: {result['subject'] or '(no subject)'}"
    if len(summary) > SUMMARY_LIMIT:
        summary = summary[:SUMMARY_LIMIT - 3] + "..."
    return {"fields": {
        "project": {"key": cfg.project},
        "issuetype": {"name": cfg.issue_type},
        "summary": summary,
        "labels": ["phishtriage", f"risk-{band.lower()}"],
        "description": to_adf(blocks),
    }}


# ---------- sending ----------

def create_issue(result: dict, cfg: JiraConfig, timeout: float = 15) -> str:
    """Create the ticket and return a link to it. Raises JiraError on any failure."""
    request = urllib.request.Request(
        f"{cfg.url}/rest/api/3/issue",
        data=json.dumps(issue_payload(result, cfg)).encode(),
        method="POST",
        headers={"Authorization": cfg.auth_header(),
                 "Content-Type": "application/json",
                 "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as err:
        raise JiraError(f"Jira returned {err.code}: {_jira_reason(err)}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise JiraError(f"could not reach Jira at {cfg.url}: {err}") from None

    key = body.get("key")
    if not key:
        raise JiraError("Jira did not return an issue key")
    return f"{cfg.url}/browse/{key}"


def _jira_reason(err: urllib.error.HTTPError) -> str:
    """Jira's own explanation if it sent one. Never includes the request, so never the token."""
    if err.code == 401:
        return "authentication failed; check JIRA_EMAIL and JIRA_API_TOKEN"
    try:
        body = json.loads(err.read() or b"{}")
    except ValueError:
        return err.reason or "no details"
    messages = list(body.get("errorMessages") or [])
    messages += [f"{k}: {v}" for k, v in (body.get("errors") or {}).items()]
    return "; ".join(messages) or (err.reason or "no details")
