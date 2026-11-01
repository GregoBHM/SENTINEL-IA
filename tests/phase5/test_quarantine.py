"""Quarantine tests never read, download or execute real malicious samples."""
import os
from pathlib import Path

import pytest

from core.quarantine import QuarantineService
from core.remediation_policy import RemediationDenied, validate_mutable_file


@pytest.mark.skipif(os.name == "nt", reason="Windows vault requires elevated isolated VM and known ProgramData root")
def test_quarantine_and_restore_preserves_bytes(sample):
    """A confirmed harmless sample can move and return without overwrites."""
    store, file, digest, finding_id, vault = sample
    svc = QuarantineService(store, vault)
    with pytest.raises(RemediationDenied):
        svc.quarantine(finding_id, confirmation="")
    item = svc.quarantine(finding_id, confirmation="CUARENTENA")
    assert item.status == "quarantined"
    assert not file.exists()
    assert Path(item.stored_path).read_bytes() == b"SENTINEL_ONEGUARD_SAFE_TEST_SAMPLE\n"
    assert Path(item.stored_path).suffix == ".blob"
    assert (Path(item.stored_path).stat().st_mode & 0o777) == 0o600
    with pytest.raises(RemediationDenied):
        svc.restore(item.id, confirmation="wrong")
    assert svc.restore(item.id, confirmation="RESTAURAR").status == "restored"
    assert file.exists()
    assert not Path(item.stored_path).exists()
    with store.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 2


@pytest.mark.skipif(os.name == "nt", reason="Windows native isolation test in VM")
def test_quarantine_delete_is_only_vault_object(sample):
    """Deletion is limited to the already isolated object with double approval."""
    store, file, digest, finding_id, vault = sample
    svc = QuarantineService(store, vault)
    item = svc.quarantine(finding_id, confirmation="CUARENTENA")
    with pytest.raises(RemediationDenied):
        svc.delete(item.id, confirmation="ELIMINAR")
    assert Path(item.stored_path).exists()
    assert svc.delete(item.id, confirmation="ELIMINAR DEFINITIVAMENTE").status == "deleted"
    assert not Path(item.stored_path).exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows native isolation test in VM")
def test_file_modified_since_scan_is_rejected(sample):
    """A modified object must be rescanned before any quarantine attempt."""
    store, file, _, finding_id, vault = sample
    file.write_text("different contents", encoding="utf-8")
    with pytest.raises(RemediationDenied, match="cambió"):
        QuarantineService(store, vault).quarantine(finding_id, confirmation="CUARENTENA")
    assert file.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows native isolation test in VM")
def test_refuses_to_overwrite_restore_destination(sample):
    """Pre-existing destinations remain intact and prevent restoration."""
    store, file, _, finding_id, vault = sample
    svc = QuarantineService(store, vault)
    item = svc.quarantine(finding_id, confirmation="CUARENTENA")
    file.write_bytes(b"do not overwrite")
    with pytest.raises(RemediationDenied, match="existe"):
        svc.restore(item.id, confirmation="RESTAURAR")
    assert file.read_bytes() == b"do not overwrite"
    assert Path(item.stored_path).exists()


@pytest.mark.skipif(os.name == "nt", reason="Hardlink test uses POSIX semantics")
def test_hardlinks_are_refused(sample):
    """Refuse a path with multiple directory entries for the same inode."""
    _, file, _, _, _ = sample
    os.link(file, file.parent / "second-link")
    with pytest.raises(RemediationDenied, match="hard links"):
        validate_mutable_file(file)


def test_symlink_is_refused(sample):
    """An indirect path must not be followed into an unexpected target."""
    _, file, _, _, _ = sample
    link = file.parent / "symlink"
    try:
        link.symlink_to(file)
    except (NotImplementedError, OSError):
        pytest.skip("Symlink requires additional privileges on this host")
    with pytest.raises(RemediationDenied, match="enlace"):
        validate_mutable_file(link)


@pytest.mark.skipif(os.name == "nt", reason="POSIX protected-directory test")
def test_protected_path_denied():
    """Never permit remediation on system executables on POSIX."""
    path = Path("/bin/sh")
    if path.exists():
        with pytest.raises(RemediationDenied):
            validate_mutable_file(path)


@pytest.mark.skipif(os.name == "nt", reason="Windows native isolation test in VM")
def test_interrupted_operations_visible_not_auto_repaired(sample):
    """An incomplete transaction is observable but not auto-restored/deleted."""
    store, file, _, finding_id, vault = sample
    svc = QuarantineService(store, vault)
    item = svc.quarantine(finding_id, confirmation="CUARENTENA")
    svc._status(item.id, "needs_review", "simulated_restart")
    reloaded = QuarantineService(store, vault)
    assert reloaded.items()[0].status == "needs_review"
    with pytest.raises(RemediationDenied):
        reloaded.restore(item.id, confirmation="RESTAURAR")
    assert Path(item.stored_path).exists()

@pytest.mark.skipif(os.name == "nt", reason="Windows native isolation test in VM")
def test_quarantine_rejects_malicious_record_ids(sample):
    """An injected SQLite record ID must not become an arbitrary vault pathname."""
    store, file, _, finding_id, vault = sample
    svc = QuarantineService(store, vault)
    with pytest.raises(RemediationDenied, match="Identificador"):
        svc.delete("../../another_file", confirmation="ELIMINAR DEFINITIVAMENTE")
    assert file.exists()
