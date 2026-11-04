"""Qt smoke: nested member inspection uses local DB evidence only."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_archive_details_action_is_available_only_for_recorded_members(
    tmp_path: Path,
) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    from core.archive_members import ArchiveMemberCoverage
    from core.performance import EngineTiming
    from db.database import SQLiteStore
    from ui.file_coverage import FileCoverageDialog

    app = QApplication.instance() or QApplication([])
    store = SQLiteStore(tmp_path / "members.db")
    store.start_session("testscan")
    archive = Path("C:/Synthetic/harmless.zip")
    store.record_target_engine_runs(
        "testscan", archive, "partial",
        [EngineTiming("archive", "success", 0.1, 200)],
        archive_members=[
            ArchiveMemberCoverage(
                member_path=str(archive), archive_format="zip",
                status="partial", reason="Miembro omitido"
            ),
            ArchiveMemberCoverage(
                member_path=str(archive) + "::large.txt",
                archive_format="file", status="uninspected",
                reason="Tamaño superior al límite", depth=2
            ),
        ],
    )
    dialog = FileCoverageDialog(store, "testscan")
    assert dialog.members_button.isEnabled()
    assert dialog.selector.currentText() == str(archive)
    dialog.selector.setEditText("C:/Synthetic/no-record.dat")
    dialog.populate_for_path()
    assert not dialog.members_button.isEnabled()
    dialog.close()
    assert app is not None
