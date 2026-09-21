"""phishtriage — triage a suspicious email and explain why.

Detection is deterministic (indicators.py). A model is used only to write the
note at the end, and only after the verdict is already decided.
"""

from .indicators import Config, Finding, run_all
from .parsing import ParsedEmail, parse_bytes, parse_file
from .scoring import Verdict, score

__all__ = [
    "Config", "Finding", "ParsedEmail", "Verdict",
    "parse_bytes", "parse_file", "run_all", "score",
]
__version__ = "0.1.0"
