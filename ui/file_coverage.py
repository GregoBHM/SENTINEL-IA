"""Read-only per-target engine coverage drilldown.

Never performs a scan, executes a file or uploads paths. All information comes
from previously persisted local SQLite session records.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from db.database import SQLiteStore


_STATES = {
    "success": "Comprobación finalizada",
    "skipped": "Omitido · cobertura parcial",
    "error": "Error · no concluyente",
    "not_applicable": "No corresponde",
    "not_run": "No iniciado",
}


class FileCoverageDialog(QDialog):
    """Show precise motor outcomes for one local target in a selected session."""

    def __init__(
        self, store: SQLiteStore, session_id: str, parent=None,
    ) -> None:
        """Populate a bounded recent-file selector and a five-column detail table."""
        super().__init__(parent)
        self.store = store
        self.session_id = session_id
        self.setWindowTitle("Inspección por archivo · evidencias locales")
        self.resize(1000, 560)
        layout = QVBoxLayout(self)
        explanation = QLabel(
            "Cada fila indica si el motor completó una comprobación, "
            "se omitió, falló o no correspondía a este objetivo."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        search = QHBoxLayout()
        self.selector = QComboBox()
        self.selector.setEditable(True)
        self.selector.setMinimumWidth(400)
        self.selector.setPlaceholderText("Ruta exacta de un objetivo de esta sesión")
        try:
            paths = self.store.get_recent_target_paths(session_id, limit=250)
        except (sqlite3.Error, OSError):
            paths = []
        self.selector.addItems(paths)
        search.addWidget(self.selector, 1)
        inspect = QPushButton("Consultar")
        inspect.clicked.connect(self.populate_for_path)
        search.addWidget(inspect)
        layout.addLayout(search)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([
            "Motor", "Resultado", "Duración", "Señales", "Motivo",
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)
        self.status = QLabel(
            "0 señales no demuestra que el archivo sea seguro. "
            "El contenido de comprimidos puede tener evidencias propias."
        )
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        layout.addWidget(close)
        if paths:
            # Editable combos with a placeholder may retain currentIndex=-1
            # after addItems on Windows Qt; explicitly select the first record.
            self.selector.setCurrentIndex(0)
            self.populate_for_path()

    def populate_for_path(self) -> None:
        """Read an exact target path, never globbing or scanning arbitrary files."""
        target = self.selector.currentText().strip()
        try:
            rows = self.store.get_target_engine_runs(self.session_id, target) if target else []
        except (sqlite3.Error, OSError):
            rows = []
            self.status.setText("No se pudo consultar la sesión local; revisa SQLite.")
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = (
                str(row["engine"]),
                _STATES.get(str(row["state"]), "Estado desconocido"),
                f"{float(row['duration_seconds']):.3f} s",
                str(row["signal_count"]),
                str(row["reason"]) or "Sin incidencias registradas",
            )
            for col, value in enumerate(values):
                self.table.setItem(index, col, QTableWidgetItem(value))
        if not rows:
            self.status.setText(
                "No hay resultados por motor para esta ruta o esta sesión es anterior "
                "a la medición por archivo. No equivale a cobertura completa."
            )
        else:
            self.status.setText(
                f"{len(rows)} estados de motor registrados para este objetivo. "
                "La ausencia de señales no demuestra que sea seguro."
            )
