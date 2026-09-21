# phishtriage

A command line tool that reads a suspicious `.eml` file, works out what is wrong
with it, and writes the note that goes on the ticket.

```
$ phishtriage samples/phish_credential_harvest.eml

!!  HIGH RISK   (score 37)

   Subject   Urgent: your account will be suspended within 24 hours
   From      Microsoft Account Team <security-alert@micros0ft.com>
   Reply-To  helpdesk@account-recovery-portal.net

   Findings (10)

   [high  ] Sender domain resembles a known domain
            micros0ft.com is 92% similar to microsoft.com without being it.

   [high  ] Link text does not match its destination
            The text reads 'https://login.microsoftonline.com' but the link
            goes to account-recovery-portal.net.
   ...
```

## Why it is built this way

The detection and the write-up are separate, and that is the main design decision
in the project.

**Every check is deterministic.** `indicators.py` decides whether SPF failed,
whether the reply address leaves the sender's domain, whether the text of a link
matches where it actually goes. Same email in, same findings out, every time, with
a reason you can verify by looking at the headers yourself.

**A model only writes the note.** By the time `summary.py` runs, the findings and
the verdict are already fixed. The model is told what was found and asked to
explain it in a few sentences. It is explicitly instructed not to introduce
indicators that are not in the list and not to argue with the verdict.

I did it this way because a triage note that cannot be checked is worse than no
note at all. If a model decided the verdict, an analyst would have to re-do the
work to trust it. This way the model is doing the part it is good at, turning a
structured list into readable English, and none of the part where being
confidently wrong would matter.

The practical proof of the split: `--no-ai` turns the model off entirely and the
tool still produces a full report from a deterministic template. There is no path
where a failed API call stops an email being triaged.

## What it checks

| Area | Checks |
|---|---|
| Authentication | SPF, DKIM and DMARC results, including telling *absent* apart from *failed* |
| Sender identity | Reply-To and Return-Path leaving the sending domain, lookalike domains, display names claiming an organisation the address does not belong to |
| Links | Anchor text promising one destination and going to another, bare IP addresses, punycode hosts, URL shorteners |
| Attachments | File types commonly used to deliver malware |
| Content | Pressure language, requests for credentials or payment details |

Findings are weighted (high 5, medium 2, low 1) and summed into a band. The
weights are deliberately blunt and visible so that a disagreement about a verdict
is a disagreement about one finding, not about a black box.

One deliberate choice: a single high finding lands on **Medium**, not High. One
failed check is often a misconfigured mail server. It takes two to reach High.

## Usage

```bash
python -m phishtriage.cli suspicious.eml              # full report
python -m phishtriage.cli *.eml --json                # machine readable
python -m phishtriage.cli suspicious.eml --no-ai      # no model call
python -m phishtriage.cli suspicious.eml --trusted mycompany.com
```

`--trusted` adds a domain to the list that lookalike detection compares against.
Lookalike detection only means something relative to domains worth imitating, so
this is the knob that actually gets tuned in use.

Exit code is 1 when anything lands on High, so it can be used in a pipeline.

## Install

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...    # optional, only for the written note
```

The detection engine has no third-party dependencies at all. It uses the standard
library `email`, `html.parser` and `difflib`. Only the optional note needs
`anthropic`, and only the tests need `pytest` and `hypothesis`.

## Tests

```bash
python -m pytest
```

45 tests. Most are ordinary cases, one per check, including the cases that should
*not* fire, which are the ones that matter for false positives.

Two are property-based, using Hypothesis:

- **Parsing arbitrary bytes never raises.** Mail arrives in whatever shape the
  sender chose, including deliberately malformed. A crash in the parser is an
  email that never gets triaged, so this generates random byte strings and
  asserts a result comes back rather than an exception.
- **Adding a finding never lowers the score.** Generated across random
  combinations of findings. If some combination could lower the score, an analyst
  could make a message look safer by noticing more wrong with it.

Both of these are properties that are true for every input, which is hard to
express as example tests and easy to express as a property.

## What it does not do

- It does not follow links or detonate attachments. Everything is static analysis
  of the file.
- It has no threat intelligence feeds, so a clean report means "none of these
  checks fired", not "safe".
- Lookalike detection uses string similarity, which catches `micros0ft.com` but
  will not catch an unrelated domain that happens to be hosting a convincing
  login page.
- Pressure language matching is English and phrase based. It is weighted low on
  purpose, because on its own it means very little.

## Layout

```
phishtriage/
  parsing.py      reads the .eml into plain dataclasses, decides nothing
  indicators.py   the checks, all deterministic
  scoring.py      weights and bands
  summary.py      the optional written note, and the fallback that replaces it
  cli.py          argument handling and output
```

Parsing is kept apart from judgement so the checks can be tested against
dataclasses instead of raw MIME, which is why the test file for indicators
constructs emails directly instead of round-tripping through sample files.
