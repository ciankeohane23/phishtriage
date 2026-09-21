from hypothesis import given
from hypothesis import strategies as st

from phishtriage.indicators import SEVERITIES, Finding
from phishtriage.scoring import WEIGHTS, score


def finding(severity: str, n: int = 0) -> Finding:
    return Finding(f"CODE_{severity}_{n}", severity, "title", "detail")


def test_no_findings_is_low_and_zero():
    verdict = score([])
    assert verdict.score == 0
    assert verdict.band == "Low"


def test_two_high_findings_reach_high():
    assert score([finding("high", 1), finding("high", 2)]).band == "High"


def test_one_high_finding_is_medium_not_high():
    # A single failed check can be a misconfiguration. It should raise
    # attention without being called a confirmed phish on its own.
    assert score([finding("high")]).band == "Medium"


def test_lows_alone_stay_low():
    assert score([finding("low", i) for i in range(2)]).band == "Low"


def test_counts_are_broken_down_by_severity():
    verdict = score([finding("high"), finding("low", 1), finding("low", 2)])
    assert verdict.counts == {"high": 1, "medium": 0, "low": 2}


severities = st.sampled_from(SEVERITIES)
finding_lists = st.lists(severities, max_size=25).map(
    lambda sevs: [finding(s, i) for i, s in enumerate(sevs)]
)


# Evidence should only ever push the score up. If some combination of findings
# could lower it, an analyst could make a message look safer by noticing more
# wrong with it, which would be a bug worth catching automatically.
@given(finding_lists, severities)
def test_adding_a_finding_never_lowers_the_score(findings, extra):
    before = score(findings).score
    after = score(findings + [finding(extra, 999)]).score
    assert after >= before
    assert after == before + WEIGHTS[extra]


@given(finding_lists)
def test_band_is_consistent_with_score(findings):
    verdict = score(findings)
    if verdict.score >= 7:
        assert verdict.band == "High"
    elif verdict.score >= 3:
        assert verdict.band == "Medium"
    else:
        assert verdict.band == "Low"


@given(finding_lists)
def test_counts_always_add_up_to_the_number_of_findings(findings):
    verdict = score(findings)
    assert sum(verdict.counts.values()) == len(findings)
