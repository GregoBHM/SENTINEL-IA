"""Read-only local investigation table with explicit provenance and scope."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout,
    QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from core.evidence_trace import EvidenceTrace, read_evidence_trace
from db.database import SQLiteStore


_CATEGORIES = {
    "finding": "Hallazgo",
    "engine": "Motor",
    "archive": "Comprimido",
    "coverage": "Cobertura parcial",
    "context": "Ruta declarada",
    "hash": "Hash idéntico",
}


class EvidenceTraceDialog(QDialog):
    """Show only relationships grounded in the selected local scan session."""

    def __init__(self, store: SQLiteStore, session_id: str, parent=None) -> None:
        """Query SQLite on demand; no network, file opening or process execution."""
        super().__init__(parent)
        self.setWindowTitle("Investigación · relaciones verificables")
        self.resize(1150, 620)
        self.trace: EvidenceTrace = read_evidence_trace(
            store, session_id, limit=350
        )
        layout = QVBoxLayout(self)
        intro = QLabel(
            f"Sesión {session_id[:14]} · "
            f"{len(self.trace.relations)} relaciones registradas"
            + (" · vista limitada" if self.trace.truncated else "")
            + ". Estas relaciones no demuestran una cadena de infección."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Tipo de evidencia"))
        self.category = QComboBox()
        self.category.addItem("Todas", "all")
        for key, title in _CATEGORIES.items():
            self.category.addItem(title, key)
        self.category.currentIndexChanged.connect(self.refresh)
        bar.addWidget(self.category)
        bar.addStretch()
        layout.addLayout(bar)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([
            "Tipo", "Origen", "Relación", "Destino", "Evidencia / límite",
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(1, 300)
        self.table.setColumnWidth(2, 195)
        self.table.setColumnWidth(3, 290)
        layout.addWidget(self.table, 1)
        note = QLabel(
            "Cada vínculo se deriva de datos guardados por los motores. "
            "Rutas similares, contenido idéntico o un hallazgo no prueban infección. "
            "Las omisiones y objetos no inspeccionados siguen siendo relevantes."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        layout.addWidget(close)
        self.refresh()

    def refresh(self) -> None:
        """Filter locally without modifying the underlying investigation."""
        category = self.category.currentData()
        rows = [
            item for item in self.trace.relations
            if category == "all" or item.kind == category
        ]
        self.table.setRowCount(len(rows))
        for i, item in enumerate(rows):
            cells = (
                _CATEGORIES.get(item.kind, "Evidencia"),
                item.source, item.relation, item.target, item.evidence,
            )
            for j, value in enumerate(cells):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                self.table.setItem(i, j, cell)
