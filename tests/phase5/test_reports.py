"""Reports escape externally supplied data and do not execute formulas."""
import csv
import os
from pathlib import Path

import pytest

from core.report import ReportService, _safe_csv_cell


def test_csv_export_contains_true_scan_records(sample, tmp_path):
    """CSV reports can be parsed by a standard CSV reader."""
    store, *_ = sample
    dest = tmp_path / "report.csv"
    path = ReportService(store).export_csv("test-session", dest)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["risk_score"] == "72"
    assert rows[0]["session_status"] == "completed"
    with pytest.raises(FileExistsError):
        ReportService(store).export_csv("test-session", dest)


def test_html_export_disallows_scripts(sample, tmp_path):
    """HTML report includes a restrictive CSP and escaped content."""
    store, *_ = sample
    with store.connection() as conn:
        conn.execute("UPDATE findings SET reason=?", ("<script>alert('x')</script>",))
    output = ReportService(store).export_html("test-session", tmp_path / "report.html")
    html = output.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html
    assert 'default-src \'none\'' in html
    assert "Un análisis sin alertas" in html


@pytest.mark.parametrize("value", ["=SUM(1)", "+cmd", "-1+2", "@cmd", " \t=1"])
def test_csv_formula_injection_prefix(value):
    """Cells beginning with Excel trigger characters receive a text prefix."""
    assert _safe_csv_cell(value).startswith("'")


def test_report_unknown_session_does_not_create_file(sample, tmp_path):
    """No report can silently invent an analysis session."""
    store, *_ = sample
    target = tmp_path / "no.html"
    with pytest.raises(ValueError):
        ReportService(store).export_html("unknown", target)
    assert not target.exists()
