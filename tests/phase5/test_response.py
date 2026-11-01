"""Explicit approvals, fail-closed system actions and contextual guidance."""
import os

import pytest

from core.persistence_response import PersistenceResponse
from core.process_response import ProcessResponse
from core.recovery_guidance import guidance_for
from core.remediation_policy import RemediationDenied, require_approval


def test_explicit_confirmation_is_mandatory():
    """Backends reject calls that bypass the UI confirmation phrase."""
    with pytest.raises(RemediationDenied):
        require_approval("", "CUARENTENA")
    with pytest.raises(RemediationDenied):
        require_approval("CUARENTENA ", "CUARENTENA")
    require_approval("CUARENTENA", "CUARENTENA")


def test_user_hash_exclusion_is_audited(sample):
    """An explicit benign exception retains the original finding."""
    store, file, sha, fid, vault = sample
    with pytest.raises(RemediationDenied):
        store.add_whitelist_entry(fid, "false positive", confirmation="")
    assert store.add_whitelist_entry(fid, "Reviewed synthetic test", confirmation="IGNORAR HASH") == sha
    with store.connection() as conn:
        assert conn.execute("SELECT suppressed FROM findings WHERE id=?", (fid,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    assert store.is_whitelisted(sha)


def test_guidance_mentions_account_session_revocation():
    """Credential compromise needs external account response, not only scanning."""
    recommendations = " ".join(guidance_for("Info stealer", "critical", is_partial=True))
    assert "revoca sesiones" in recommendations
    assert "reinstalación" in recommendations
    assert "Cobertura incompleta" in recommendations


@pytest.mark.skipif(os.name == "nt", reason="Windows tests require isolated VM and approved autorun fixture")
def test_registry_changes_are_unavailable_off_windows(sample):
    """No registry fallback tries arbitrary scripts or writes off Windows."""
    store, _, _, fid, _ = sample
    with pytest.raises(RemediationDenied, match="Windows"):
        PersistenceResponse(store).disable_hkcu_run(fid, confirmation="DESACTIVAR INICIO")


@pytest.mark.skipif(os.name == "nt", reason="Native process response requires isolated VM")
def test_process_termination_is_not_available_off_windows(sample):
    """No POSIX process is accidentally killed by a test of the Windows handler."""
    store, _, _, _, _ = sample
    with pytest.raises(RemediationDenied, match="Windows"):
        ProcessResponse(store).terminate(os.getpid(), 0, "none", confirmation="FINALIZAR PROCESO")
