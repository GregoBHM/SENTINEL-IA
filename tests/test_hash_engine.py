"""Hash matching and stable-file cache tests."""
import hashlib
from pathlib import Path

from core.models import ScanTarget
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def test_hash_signature_detection(store: SQLiteStore, tmp_path: Path) -> None:
    """Recognize an explicitly registered benign test file digest."""
    sample = tmp_path / "harmless.bin"
    sample.write_bytes(b"SYNTHETIC ONLY")
    sha = hashlib.sha256(sample.read_bytes()).hexdigest()
    store.add_hash_signature(sha, "lab-test", "Synthetic", "Only a controlled fixture")
    findings = HashEngine(store).scan(ScanTarget(sample))
    assert len(findings) == 1
    assert findings[0].sha256 == sha
    assert findings[0].reason == "Only a controlled fixture"


def test_unknown_hash_is_not_malicious(store: SQLiteStore, tmp_path: Path) -> None:
    """Unknown reputation is not proof of safety or maliciousness."""
    sample = tmp_path / "unknown.txt"
    sample.write_text("benign", encoding="utf-8")
    assert HashEngine(store).scan(ScanTarget(sample)) == []


def test_hash_cache_invalidates_on_change(store: SQLiteStore, tmp_path: Path) -> None:
    """Modifying file contents invalidates the cached fingerprint."""
    sample = tmp_path / "changing.txt"
    sample.write_text("before", encoding="utf-8")
    engine = HashEngine(store)
    first = engine.compute_hashes(sample)
    assert engine.compute_hashes(sample) == first
    sample.write_text("after-longer", encoding="utf-8")
    assert engine.compute_hashes(sample).sha256 != first.sha256
