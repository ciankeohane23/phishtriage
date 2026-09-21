"""Write the investigation ticket.

The terminal report is for the person running the tool. This is for the ticket
queue: a Markdown write-up that can be pasted into Jira or a case note as it is,
with the verdict, the evidence, the observables and what to do next.

Two things matter here more than layout:

**Observables are defanged.** `https://evil.com` becomes `hxxps://evil[.]com`.
A ticket gets read, forwarded and pasted into chat by people who did not do the
triage, and a live link in it is one mis-click away from the thing the ticket is
about. Defanged values are still searchable and easy to re-fang for a blocklist.

**Next steps come from the verdict and the findings, not from a model.** The
same email always gets the same recommended actions, and each one can be traced
back to why it is there.
"""

from __future__ import annotations

import ipaddress
from email.utils import parseaddr
from urllib.parse import urlparse

from .parsing import domain_of


def defang(value: str) -> str:
    """Make a URL, domain, address or IP safe to paste. Idempotent."""
    if not value:
        return value
    out = value
    for scheme in ("https://", "http://"):
        if out.lower().startswith(scheme):
            out = "hxxp" + out[4:]
            break
    out = out.replace("[.]", ".").replace(".", "[.]")
    out = out.replace("[@]", "@").replace("@", "[@]")
    return out


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def observables(result: dict) -> dict:
    """Everything worth searching for or blocking, deduplicated, not yet defanged."""
    addresses = []
    for addr in (result["from"], result.get("reply_to", ""), result.get("return_path", "")):
        bare = parseaddr(addr or "")[1].lower()
        if bare and bare not in addresses:
            addresses.append(bare)

    domains = []
    for addr in addresses:
        dom = domain_of(addr)
        if dom and dom not in domains:
            domains.append(dom)

    urls, ips = [], []
    for href in result.get("link_hrefs", []):
        if href not in urls:
            urls.append(href)
        host = (urlparse(href).hostname or "").lower()
        if not host:
            continue
        if _is_ip(host):
            if host not in ips:
                ips.append(host)
        elif host not in domains:
            domains.append(host)

    return {
        "addresses": addresses,
        "domains": domains,
        "ips": ips,
        "urls": urls,
        "attachments": result.get("attachments", []),
    }


# Questions the analyst needs answered by whoever reported the email. Each is tied
# to a finding code, so the ticket only asks what is relevant to this message.
QUESTIONS = {
    "CREDENTIAL_REQUEST": "Did the recipient enter a password or payment details anywhere?",
    "LINK_TEXT_MISMATCH": "Did the recipient click any link in the message?",
    "URL_IP_LITERAL": "Did the recipient click any link in the message?",
    "URL_PUNYCODE": "Did the recipient click any link in the message?",
    "URL_SHORTENER": "Did the recipient click any link in the message?",
    "RISKY_ATTACHMENT": "Did the recipient open or download the attachment?",
    "REPLY_TO_MISMATCH": "Did the recipient reply, and if so what did they send?",
}


def next_steps(band: str, codes: set[str]) -> list[str]:
    if band == "Low":
        steps = ["No action beyond closing the ticket and thanking the reporter.",
                 "A Low result means the checks found nothing serious, not that the message "
                 "is safe. Reopen if the reporter has context the headers do not show."]
        return steps

    steps = []
    if band == "High":
        steps.append("Escalate to a senior analyst before taking any containment action.")
        steps.append("Search the mail gateway for the same sender, subject or link hosts to "
                     "find other recipients.")
        steps.append("Propose the sender domain and link hosts listed above for blocking.")
    else:
        steps.append("Hold the message; do not release it to the recipient yet.")
        steps.append("Verify with the apparent sender through a channel already on file, "
                     "not one given in the email.")

    if codes & {"LINK_TEXT_MISMATCH", "URL_IP_LITERAL", "URL_PUNYCODE", "URL_SHORTENER",
                "CREDENTIAL_REQUEST"}:
        steps.append("If anyone entered credentials: reset the password, revoke active "
                     "sessions and check sign-in logs from the time of the click.")
    if "RISKY_ATTACHMENT" in codes:
        steps.append("If the attachment was opened: check the endpoint tool for activity on "
                     "that device and look up the file hash listed above.")
    if band == "Medium":
        steps.append("Escalate if the recipient interacted with the message or the sender "
                     "cannot be verified.")
    return steps


class Code(str):
    """A value to show as literal code: a defanged observable, a hash, a file name."""


def ticket(result: dict) -> tuple[str, list[tuple]]:
    """The ticket as (title, blocks), independent of how it will be rendered.

    Blocks are ("heading", text), ("para", text), ("italic", text),
    ("table", headers, rows), ("checklist", items) or ("numbered", items).
    Table cells are plain strings or `Code`. Markdown and Jira both render from
    this, so the pasted ticket and the created one can never disagree.
    """
    v = result["verdict"]
    codes = {f["code"] for f in result["findings"]}
    obs = observables(result)
    title = f"Phishing triage: {v['band']} risk (score {v['score']})"

    header = [["Subject", result["subject"] or "(none)"],
              ["From", Code(f"{result['from_display']} <{defang(result['from'])}>".strip())]]
    if result.get("reply_to"):
        header.append(["Reply-To", Code(defang(result["reply_to"]))])
    if result.get("to"):
        header.append(["To", Code(defang(result["to"]))])
    if result.get("date"):
        header.append(["Date", result["date"]])
    if result.get("message_id"):
        header.append(["Message-ID", Code(defang(result["message_id"]))])
    header.append(["File", Code(result["file"])])

    blocks: list[tuple] = [("table", None, header)]

    blocks += [("heading", "Summary"), ("para", result["note"])]
    source = "model, from the findings below" if result["note_source"] == "model" else "rules template"
    blocks.append(("italic", f"Written by: {source}."))

    blocks.append(("heading", f"Findings ({len(result['findings'])})"))
    if result["findings"]:
        blocks.append(("table", ["Severity", "Finding", "Evidence"],
                       [[f["severity"], f["title"], _defang_text(f["detail"])]
                        for f in result["findings"]]))
    else:
        blocks.append(("para", "None of the checks fired."))

    blocks.append(("heading", "Observables (defanged)"))
    rows = [["Address", Code(defang(a))] for a in obs["addresses"]]
    rows += [["Domain", Code(defang(d))] for d in obs["domains"]]
    rows += [["IP", Code(defang(i))] for i in obs["ips"]]
    rows += [["URL", Code(defang(u))] for u in obs["urls"]]
    for a in obs["attachments"]:
        rows.append(["Attachment", Code(f"{a['filename']} ({a['content_type']})")])
        if a.get("sha256"):
            rows.append(["SHA-256", Code(a["sha256"])])
    blocks.append(("table", ["Type", "Value"], rows) if rows else ("para", "None."))

    questions = sorted({QUESTIONS[c] for c in codes if c in QUESTIONS})
    if questions:
        blocks += [("heading", "Ask the reporter"), ("checklist", questions)]

    blocks += [("heading", "Recommended next steps"),
               ("numbered", next_steps(v["band"], codes))]
    return title, blocks


def render_report(result: dict) -> str:
    """The ticket as Markdown, for pasting into a ticket or case note."""
    title, blocks = ticket(result)
    out = [f"## {title}"]
    for block in blocks:
        kind = block[0]
        if kind == "heading":
            out += ["", f"### {block[1]}"]
        elif kind == "para":
            out += ["", block[1]]
        elif kind == "italic":
            out += ["", f"_{block[1]}_"]
        elif kind == "table":
            _, headers, rows = block
            out += ["", "| " + " | ".join(headers or ["", ""]) + " |",
                    "|" + "---|" * len(rows[0])]
            out += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in rows]
        elif kind == "checklist":
            out += [""] + [f"- [ ] {item}" for item in block[1]]
        elif kind == "numbered":
            out += [""] + [f"{i}. {item}" for i, item in enumerate(block[1], 1)]
    out.append("")
    return "\n".join(out)


def _md_cell(value: str) -> str:
    """Keep a value from breaking the Markdown table it sits in."""
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return f"`{text}`" if isinstance(value, Code) else text


def _defang_text(text: str) -> str:
    """Defang anything URL- or domain-shaped inside a free-text finding detail."""
    words = []
    for word in text.split(" "):
        core = word.strip(".,;:'\"()")
        if core and ("://" in core or ("." in core and _looks_like_host(core))):
            word = word.replace(core, defang(core))
        words.append(word)
    return " ".join(words)


def _looks_like_host(token: str) -> bool:
    host = token.rpartition("@")[2]
    labels = host.split(".")
    return len(labels) >= 2 and all(labels) and labels[-1].isalpha() or _is_ip(host)
