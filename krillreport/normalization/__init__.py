"""Normalization package: merge/dedupe/group parse results into one report.

Public API::

    from krillreport.normalization import normalize, collect_warnings
"""

from __future__ import annotations

from .normalizer import collect_warnings, normalize
from .severity import reconcile_severity, risk_posture

__all__ = ["normalize", "collect_warnings", "reconcile_severity", "risk_posture"]
