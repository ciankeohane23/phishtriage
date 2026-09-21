"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .indicators import Config, run_all
from .parsing import parse_file
from .scoring import score
from .summary import DEFAULT_MODEL, note

BAND_MARK = {"High": "!!", "Medium": "!", "Low": "."}


def analyse(path: str, cfg: Config, use_model: bool, model: str) -> dict:
    mail = parse_file(path)
    findings = run_all(mail, cfg)
    verdict = score(findings)
    text, source = note(mail, findings, verdict, use_model=use_model, model=model)

    return {
        "file": path,
        "subject": mail.subject,
        "from": mail.from_addr,
        "from_display": mail.from_display,
        "reply_to": mail.reply_to,
        "verdict": {"band": verdict.band, "score": verdict.score, "counts": verdict.counts},
        "findings": [asdict(f) for f in findings],
        "note": text,
        "note_source": source,
    }


def render(result: dict) -> str:
    v = result["verdict"]
    out = [
        "",
        f"{BAND_MARK.get(v['band'], '?')}  {v['band'].upper()} RISK   (score {v['score']})",
        "",
        f"   Subject   {result['subject'] or '(none)'}",
        f"   From      {result['from_display']} <{result['from']}>",
    ]
    if result["reply_to"]:
        out.append(f"   Reply-To  {result['reply_to']}")

    out += ["", f"   Findings ({len(result['findings'])})", ""]
    if result["findings"]:
        for f in result["findings"]:
            out.append(f"   [{f['severity']:<6}] {f['title']}")
            out.append(f"            {f['detail']}")
            out.append("")
    else:
        out += ["   Nothing fired.", ""]

    out += [f"   Note ({result['note_source']})", "", f"   {result['note']}", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="phishtriage",
        description="Triage a suspicious email and explain the verdict.",
    )
    ap.add_argument("paths", nargs="+", metavar="EML", help=".eml file(s) to analyse")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("--no-ai", action="store_true",
                    help="skip the model and use the deterministic note")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"model id (default {DEFAULT_MODEL})")
    ap.add_argument("--trusted", action="append", default=[], metavar="DOMAIN",
                    help="add a domain to compare sender lookalikes against (repeatable)")
    args = ap.parse_args(argv)

    cfg = Config()
    cfg.trusted_domains |= {d.lower() for d in args.trusted}

    results = []
    for path in args.paths:
        try:
            results.append(analyse(path, cfg, use_model=not args.no_ai, model=args.model))
        except FileNotFoundError:
            print(f"no such file: {path}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for result in results:
            print(render(result))

    return 1 if any(r["verdict"]["band"] == "High" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
