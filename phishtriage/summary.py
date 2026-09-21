"""Write the analyst note.

This is the only part of the tool that uses a model, and it is deliberately the
last step. By the time anything gets here the findings and the verdict are
already fixed by indicators.py and scoring.py, so the model is summarising a
decision rather than making one. If the API key is missing or the call fails,
`fallback_note` produces the same information without it and the tool still works.
"""

from __future__ import annotations

import os

from .indicators import Finding
from .parsing import ParsedEmail
from .scoring import Verdict

DEFAULT_MODEL = "claude-opus-5"

SYSTEM = """You are helping a junior analyst write up a phishing triage.

You will be given an email's metadata and a list of findings that have already
been produced by deterministic checks, plus a verdict that has already been
decided. Write a short note for the ticket.

Rules:
- Use only the findings given. Do not introduce indicators that are not listed.
- Do not change or argue with the verdict. Explain what drove it.
- If the findings are weak, say so plainly rather than inflating them.
- Three or four sentences. Plain English. No headings, no bullet points.
- Write for someone who will check your reasoning against the findings."""


def _facts(mail: ParsedEmail, findings: list[Finding], verdict: Verdict) -> str:
    lines = [
        f"Subject: {mail.subject}",
        f"From: {mail.from_display} <{mail.from_addr}>",
        f"Reply-To: {mail.reply_to or '(none)'}",
        f"Authentication: spf={mail.auth.spf} dkim={mail.auth.dkim} dmarc={mail.auth.dmarc}",
        f"Link hosts: {', '.join(sorted({l.host for l in mail.links if l.host})) or '(none)'}",
        f"Attachments: {', '.join(a.filename for a in mail.attachments) or '(none)'}",
        "",
        f"Verdict: {verdict.headline}",
        "",
        "Findings:",
    ]
    if findings:
        lines += [f"- [{f.severity}] {f.title}: {f.detail}" for f in findings]
    else:
        lines.append("- none")
    return "\n".join(lines)


def fallback_note(findings: list[Finding], verdict: Verdict) -> str:
    """Deterministic write-up, used when no model is available."""
    if not findings:
        return (
            f"{verdict.headline}. No indicators fired. This does not prove the message "
            "is safe, only that the checks in this tool found nothing."
        )

    top = [f for f in findings if f.severity == "high"] or findings[:2]
    reasons = "; ".join(f.title.lower() for f in top[:3])
    return (
        f"{verdict.headline}, driven by {len(findings)} finding(s): {reasons}. "
        f"Counts by severity: "
        + ", ".join(f"{n} {sev}" for sev, n in verdict.counts.items() if n)
        + ". See the findings list for the evidence behind each one."
    )


def model_note(
    mail: ParsedEmail,
    findings: list[Finding],
    verdict: Verdict,
    model: str = DEFAULT_MODEL,
) -> str | None:
    """Ask Claude to write the note. Returns None if that isn't possible."""
    try:
        import anthropic
    except ImportError:
        return None

    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return None

    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=SYSTEM,
            messages=[{"role": "user", "content": _facts(mail, findings, verdict)}],
        )
    except Exception:
        # A triage tool that dies because an API call failed is worse than one
        # that falls back to the deterministic note.
        return None

    parts = [b.text for b in response.content if b.type == "text"]
    text = "\n".join(parts).strip()
    return text or None


def note(
    mail: ParsedEmail,
    findings: list[Finding],
    verdict: Verdict,
    use_model: bool = True,
    model: str = DEFAULT_MODEL,
) -> tuple[str, str]:
    """Return (note, source) where source is 'model' or 'rules'."""
    if use_model:
        written = model_note(mail, findings, verdict, model)
        if written:
            return written, "model"
    return fallback_note(findings, verdict), "rules"
