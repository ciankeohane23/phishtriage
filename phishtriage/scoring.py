"""Turn a list of findings into one number and one word.

The weights are deliberately blunt and visible. An analyst who disagrees with a
verdict can see exactly which finding moved it and by how much, which is not
true of a score that comes out of a model.
"""

from __future__ import annotations

from dataclasses import dataclass

from .indicators import Finding

WEIGHTS = {"high": 5, "medium": 2, "low": 1}

# Score at or above which each band starts.
BANDS = (("High", 7), ("Medium", 3), ("Low", 0))


@dataclass(frozen=True)
class Verdict:
    score: int
    band: str
    counts: dict[str, int]

    @property
    def headline(self) -> str:
        return f"{self.band} risk (score {self.score})"


def score(findings: list[Finding]) -> Verdict:
    counts = {sev: 0 for sev in WEIGHTS}
    total = 0
    for finding in findings:
        counts[finding.severity] += 1
        total += WEIGHTS[finding.severity]

    band = next(name for name, floor in BANDS if total >= floor)
    return Verdict(score=total, band=band, counts=counts)
