"""Read-only live engine overview for Sentinel OneGuard's scan screen.

All inputs are already-collected local inventory and timing snapshots.
No scanning, network access, or remediation is performed in this widget.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem, QVBoxLayout,
)

from ui.theme import COLORS


def engine_rows(inventory: dict, metrics: dict) -> list[dict]:
    """Build a bounded-view description without inventing engine success."""
    inventory = inventory if isinstance(inventory, dict) else {}
    metrics = metrics if isinstance(metrics, dict) else {}
    ids = list(dict.fromkeys([*inventory, *metrics]))[:24]
    result = []
    for engine_id in ids:
        info = inventory.get(engine_id, {})
        numbers = metrics.get(engine_id, {})
        info = info if isinstance(info, dict) else {}
        numbers = numbers if isinstance(numbers, dict) else {}
        checks = max(0, int(numbers.get("checks", 0)))
        completed = max(0, int(numbers.get("completed", 0)))
        skipped = max(0, int(numbers.get("skipped", 0)))
        errors = max(0, int(numbers.get("errors", 0)))
        signals = max(0, int(numbers.get("signals", 0)))
        availability = str(info.get("state") or "")
        status = {
            "prepared": "Preparado",
            "partial": "Inventario parcial",
            "unavailable": "No disponible",
            "not_requested": "No solicitado",
        }.get(availability, "Sin inventario")
        if availability == "prepared" and checks:
            status = "Con errores" if errors else (
                "Con omisiones" if skipped else "Invocado"
            )
        result.append({
            "id": str(engine_id),
            "name": str(info.get("title") or engine_id)[:70],
            "status": status,
            "checks": checks,
            "completed": completed,
            "skipped": skipped,
            "errors": errors,
            "signals": signals,
            "note": str(info.get("note") or "Sin explicación de inventario.")[:300],
        })
    return result


class EngineOverview(QFrame):
    """Compact dashboard table; detailed per-engine diagnostics remain available."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("EngineDeck")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 14)
        outer.setSpacing(10)

        self.heading = QLabel("MOTORES / ACTIVIDAD OBSERVADA")
        self.heading.setObjectName("Eyebrow")
        outer.addWidget(self.heading)

        self.summary = QLabel("Esperando inventario de motores…")
        self.summary.setObjectName("SectionHeading")
        outer.addWidget(self.summary)

        self.table = QTableWidget(0, 6)
        self.table.setObjectName("EngineTable")
        self.table.setHorizontalHeaderLabels([
            "Motor", "Estado", "Intentos", "Finalizadas", "Omitidas", "Señales",
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        for column in (1, 2, 3, 4, 5):
            self.table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.setFixedHeight(220)
        outer.addWidget(self.table)

        self.caveat = QLabel(
            "Preparado no equivale a inspeccionado. Las señales no confirman "
            "infección; las omisiones y errores requieren revisión."
        )
        self.caveat.setObjectName("SmallHelp")
        self.caveat.setWordWrap(True)
        outer.addWidget(self.caveat)

    def update_snapshot(self, inventory: dict, metrics: dict) -> None:
        """Render immutable snapshot values on the GUI thread."""
        rows = engine_rows(inventory, metrics)
        self.table.setRowCount(len(rows))
        if not rows:
            self.summary.setText("Sin datos todavía · preparando escáner")
            return
        prepared = sum(r.get("state") == "prepared" for r in inventory.values()) if isinstance(inventory, dict) else 0
        limited = sum(
            r.get("state") in ("unavailable", "partial")
            for r in inventory.values()
        ) if isinstance(inventory, dict) else 0
        checked = sum(row["completed"] for row in rows)
        self.summary.setText(
            f"{len(rows)} motores listados · {prepared} preparados · "
            f"{limited} limitados · {checked} comprobaciones finalizadas"
        )
        for i, record in enumerate(rows):
            values = (
                record["name"], record["status"],
                str(record["checks"]) if record["checks"] else "—",
                str(record["completed"]) if record["checks"] else "—",
                str(record["skipped"]) if record["checks"] else "—",
                str(record["signals"]) if record["checks"] else "—",
            )
            for j, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setToolTip(
                    record["note"] + (
                        f"  Errores de motor: {record['errors']}."
                        if record["errors"] else ""
                    )
                )
                cell.setTextAlignment(
                    Qt.AlignmentFlag.AlignVCenter |
                    (Qt.AlignmentFlag.AlignLeft if j < 2
                     else Qt.AlignmentFlag.AlignHCenter)
                )
                if j == 1:
                    color = (
                        COLORS["danger"] if record["errors"]
                        else COLORS["amber"] if (
                            record["skipped"] or record["status"]
                            in ("Inventario parcial", "No disponible")
                        )
                        else COLORS["muted"] if record["status"] == "No solicitado"
                        else COLORS["green"] if record["completed"]
                        else COLORS["text"]
                    )
                    cell.setForeground(QColor(color))
                self.table.setItem(i, j, cell)

    def reset(self):
        """Clear previous scan data before a new user-authorized scan."""
        self.update_snapshot({}, {})
