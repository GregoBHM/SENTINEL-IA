"""Conservative correlation policy which avoids duplicate evidence inflation."""
from __future__ import annotations

from collections import defaultdict

from core.models import AggregatedFinding, Finding, Severity


_SEVERITY_RANGES = (
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
    (0, Severity.INFO),
)


def severity_from_score(score: int) -> Severity:
    """Convert a bounded illustrative risk score to a severity label."""
    return next(level for minimum, level in _SEVERITY_RANGES if score >= minimum)


class FindingAggregator:
    """Group evidence per target and correlate independent engine families."""

    def aggregate(
        self, findings: list[Finding], *, whitelisted_hashes: set[str] | None = None,
        target_sha256: str | None = None
    ) -> list[AggregatedFinding]:
        """Preserve evidence; add a small bonus for independent engines only."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            groups[finding.target].append(finding)

        results: list[AggregatedFinding] = []
        allowlist = whitelisted_hashes or set()
        for target, evidence in groups.items():
            # Repeated similar rules in one engine should not count as new sources.
            per_engine: dict[str, Finding] = {}
            for signal in evidence:
                previous = per_engine.get(signal.engine)
                if previous is None or signal.risk_score > previous.risk_score:
                    per_engine[signal.engine] = signal
            strongest = max(evidence, key=lambda item: item.risk_score)
            number_engines = len(per_engine)
            bonus = min(12, (number_engines - 1) * 6)
            score = min(100, strongest.risk_score + bonus)
            # Zero-risk test rules remain informational.
            if strongest.risk_score == 0:
                score = 0
            confidence = min(100, max(s.confidence for s in evidence) +
                             min(8, (number_engines - 1) * 4))
            engines = tuple(sorted(per_engine))
            sha256 = target_sha256 or next((s.sha256 for s in evidence if s.sha256), None)
            suppressed = bool(sha256 and sha256 in allowlist)
            results.append(AggregatedFinding(
                target=target,
                threat_type=strongest.threat_type,
                severity=severity_from_score(score),
                risk_score=score,
                confidence=confidence,
                reason=strongest.reason,
                engines=engines,
                evidence=tuple(evidence),
                sha256=sha256,
                suppressed=suppressed,
            ))
        return sorted(results, key=lambda f: (-f.risk_score, f.target))
