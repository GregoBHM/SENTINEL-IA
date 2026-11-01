"""Test evidence correlation without inventing infection sequences."""
from core.aggregator import FindingAggregator
from core.investigation import IncidentInvestigator
from core.models import Finding, Severity


def signal(target: str, *, exe: str = "") -> Finding:
    """Create a harmless synthetic finding record."""
    return Finding(target=target, engine="synthetic", threat_type="Fixture",
                   reason="Synthetic only", severity=Severity.LOW, risk_score=30,
                   confidence=40, details={"executable_path": exe} if exe else {})


def test_link_persistence_to_file_via_path() -> None:
    """Same executable can be linked without claiming causation."""
    file_path = r"C:\Users\tester\AppData\Roaming\svch0st.exe"
    aggregator = FindingAggregator()
    fs = aggregator.aggregate([signal(file_path)])
    ps = aggregator.aggregate([signal(r"HKCU\Run\Fixture", exe=file_path)])
    report = IncidentInvestigator().investigate(fs + ps)
    assert len(report.links) == 1
    assert "no confirmada" in report.links[0].relationship
    assert "Sin telemetría histórica" in report.limitations[0]


def test_no_causal_links_from_single_finding() -> None:
    """A standalone weak signal cannot prove a chain of compromise."""
    report = IncidentInvestigator().investigate(FindingAggregator().aggregate([
        signal("C:\\work\\tool.exe")]))
    assert report.links == ()
