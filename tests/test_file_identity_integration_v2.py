"""End-to-end synthetic coverage for 3D.3 local evidence."""
import hashlib
from pathlib import Path

from app.config import ScanConfig
from core.evidence_trace import read_evidence_trace
from core.models import ScanStatus
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def test_pe_identity_saved_and_traced(tmp_path: Path):
    sample = tmp_path / "harmless.exe"
    payload = b"MZ" + b"synthetic-only" * 64
    sample.write_bytes(payload)
    store = SQLiteStore(tmp_path / "scan.db")
    # Reuse actual production orchestration; no sample is executed.
    manager = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=1, max_pending=2),
        store, [HashEngine(store)],
    )
    result = manager.run([sample])
    assert result.status == ScanStatus.COMPLETED
    rows = store.get_file_identities(result.session_id)
    assert len(rows) == 1
    assert rows[0]["status"] == "observed"
    assert rows[0]["sha256"] == hashlib.sha256(payload).hexdigest()
    trace = read_evidence_trace(store, result.session_id)
    assert any(item.kind == "content_identity" for item in trace.relations)


def test_plain_text_does_not_trigger_second_hash(tmp_path: Path):
    sample = tmp_path / "ordinary.txt"
    sample.write_text("harmless text", encoding="utf-8")
    store = SQLiteStore(tmp_path / "scan.db")
    manager = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=1, max_pending=2),
        store, [HashEngine(store)],
    )
    result = manager.run([sample])
    assert result.status == ScanStatus.COMPLETED
    assert store.get_file_identities(result.session_id) == []


def test_database_isolation_and_local_evidence(tmp_path: Path):
    store = SQLiteStore(tmp_path / "scan.db")
    store.start_session("one")
    store.start_session("two")
    from core.file_identity import FileIdentity
    store.record_target_engine_runs(
        "one", Path("synthetic.exe"), "scanned", [],
        file_identity=FileIdentity("synthetic.exe", "limited", reason="Byte budget"),
    )
    assert store.get_file_identities("two") == []
    assert store.get_file_identities("one")[0]["status"] == "limited"
    trace = read_evidence_trace(store, "one")
    assert any(item.kind == "identity_limit" for item in trace.relations)
