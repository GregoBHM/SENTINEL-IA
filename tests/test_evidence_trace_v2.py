"""Local evidence trace must not manufacture infection or process relationships."""
from __future__ import annotations

from pathlib import Path

from core.archive_members import ArchiveMemberCoverage
from core.evidence_trace import read_evidence_trace
from core.models import AggregatedFinding, Finding, Severity
from core.performance import EngineTiming
from db.database import SQLiteStore


def test_trace_links_findings_engines_archive_members_and_omissions(
    tmp_path: Path,
) -> None:
    store = SQLiteStore(tmp_path / "evidence.db")
    store.start_session("scan-1")
    path = tmp_path / "example.zip"
    member = str(path) + "::harmless.exe"
    store.record_target_engine_runs(
        "scan-1", path, "partial",
        [EngineTiming("archive", "success", 0.1, 500)],
        archive_members=[
            ArchiveMemberCoverage(
                str(path), "zip", "partial", reason="Archivo interno cifrado"
            ),
            ArchiveMemberCoverage(
                member, "file", "uninspected",
                reason="Cifrado", depth=2
            ),
        ],
    )
    source = Finding(
        target=member, engine="yara", threat_type="Prueba sintética",
        reason="Regla de laboratorio, no detección real", severity=Severity.INFO,
        risk_score=0, confidence=40, rule_id="LAB_ONLY",
        details={"test_only": True},
    )
    result = AggregatedFinding(
        target=member, threat_type="Prueba sintética", severity=Severity.INFO,
        risk_score=0, confidence=40,
        reason="Solo laboratorio", engines=("yara",), evidence=(source,),
    )
    store.save_finding("scan-1", result)
    store.record_coverage(
        "scan-1", path, "archive", "SCAN.ARCHIVE.PARTIAL",
        {"uninspected_members": 1}, "Un miembro no inspeccionado",
    )
    trace = read_evidence_trace(store, "scan-1")
    types = {row.kind for row in trace.relations}
    assert {"finding", "engine", "archive", "coverage"} <= types
    assert any(
        row.source == str(path) and row.target == member
        and row.relation == "Contiene entrada enumerada"
        and "uninspected" in row.evidence
        for row in trace.relations
    )
    assert any(
        row.kind == "engine" and "LAB_ONLY" in row.target
        for row in trace.relations
    )
    assert not any(
        "punto de entrada confirmado" in row.evidence.lower()
        for row in trace.relations
    )
    assert not trace.truncated


def test_identical_hash_relates_files_but_not_sessions(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "hashes.db")
    store.start_session("s1")
    store.start_session("s2")
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    store.record_target_engine_runs(
        "s1", a, "scanned",
        [EngineTiming("hash", "success", 0.01, 8)], sha256="e" * 64,
    )
    store.record_target_engine_runs(
        "s1", b, "scanned",
        [EngineTiming("hash", "success", 0.01, 8)], sha256="e" * 64,
    )
    store.record_target_engine_runs(
        "s2", b, "scanned",
        [EngineTiming("hash", "success", 0.01, 8)], sha256="e" * 64,
    )
    trace = read_evidence_trace(store, "s1")
    same = [row for row in trace.relations if row.kind == "hash"]
    assert len(same) == 1
    assert "no implica propagación" in same[0].evidence
    assert not [
        row for row in read_evidence_trace(store, "s2").relations
        if row.kind == "hash"
    ]


def test_executable_reference_is_explicitly_noncausal(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "references.db")
    store.start_session("process-session")
    signal = Finding(
        target="process_122", engine="process_network",
        threat_type="Identidad anómala", reason="Fixture", severity=Severity.LOW,
        risk_score=25, confidence=35,
        details={"executable_path": r"C:\\Synthetic\\sample.exe"},
    )
    aggregated = AggregatedFinding(
        target="process_122", threat_type=signal.threat_type,
        reason=signal.reason, severity=signal.severity, risk_score=25,
        confidence=35, engines=(signal.engine,), evidence=(signal,),
    )
    store.save_finding("process-session", aggregated)
    trace = read_evidence_trace(store, "process-session")
    refs = [x for x in trace.relations if x.kind == "context"]
    assert len(refs) == 1
    assert "no implica ejecución actual" in refs[0].evidence
    assert refs[0].target.endswith("sample.exe")


def test_report_is_bounded_and_marks_truncation(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "bounded.db")
    store.start_session("many")
    for i in range(4):
        signal = Finding(
            target=f"synthetic-{i}", engine="test", threat_type="Prueba",
            reason="Inerte", severity=Severity.INFO,
            risk_score=0, confidence=0,
        )
        store.save_finding("many", AggregatedFinding(
            target=f"synthetic-{i}", threat_type="Prueba",
            severity=Severity.INFO, risk_score=0, confidence=0,
            reason="Inerte", engines=("test",), evidence=(signal,),
        ))
    trace = read_evidence_trace(store, "many", limit=2)
    assert trace.truncated
    assert len(trace.relations) <= 2
    assert "cadenas" not in "".join(item.relation for item in trace.relations).lower()
