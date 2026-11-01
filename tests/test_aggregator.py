"""Correlation avoids false risk inflation and respects allowlisted hashes."""
from core.aggregator import FindingAggregator
from core.models import Finding, Severity


def signal(engine: str, score: int, sha: str | None = None) -> Finding:
    """Construct harmless independent mock evidence."""
    return Finding(target="safe.exe", engine=engine, threat_type="Synthetic",
                   reason="Fixture", severity=Severity.MEDIUM, risk_score=score,
                   confidence=50, sha256=sha)


def test_same_engine_does_not_inflate() -> None:
    """Several weak YARA rules count as one family of evidence."""
    verdict = FindingAggregator().aggregate([signal("yara", 45), signal("yara", 40)])[0]
    assert verdict.risk_score == 45
    assert verdict.engines == ("yara",)


def test_independent_engines_have_bounded_bonus() -> None:
    """Cross-engine correlation is conservative and explained."""
    verdict = FindingAggregator().aggregate([signal("yara", 45), signal("hash", 50)])[0]
    assert verdict.risk_score == 56
    assert verdict.severity == Severity.MEDIUM
    assert len(verdict.evidence) == 2


def test_whitelist_preserves_auditable_finding() -> None:
    """Whitelisting marks a verdict suppressed without removing evidence."""
    sha = "a" * 64
    verdict = FindingAggregator().aggregate(
        [signal("yara", 45)], target_sha256=sha, whitelisted_hashes={sha}
    )[0]
    assert verdict.suppressed
    assert verdict.sha256 == sha
    assert len(verdict.evidence) == 1
