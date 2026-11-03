"""OneGuard desktop dashboard with explicitly confirmed Phase 5 responses.

All scanning and potentially slow remediation are performed in worker threads;
Qt objects are only accessed from the GUI thread.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from queue import Queue
from datetime import datetime
from time import monotonic
from queue import Empty

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QTextCursor, QPixmap, QIcon
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QComboBox, QFrame, QGridLayout,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QMainWindow,
    QInputDialog, QFileDialog,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
    QDialog, QDialogButtonBox,
    QSplitter, QStackedWidget, QTableView, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from app.config import ScanConfig
from core.models import ScanEvent
from core.events import present_event
from core.scan_clock import ScanClock, format_duration
from core.quarantine import QuarantineService
from core.report import ReportService
from core.recovery_guidance import guidance_for
from core.process_response import ProcessResponse
from core.persistence_response import PersistenceResponse
from core.remediation_policy import RemediationDenied
from db.database import SQLiteStore
from ui.branding import logo_path, icon_path
from ui.controller import ScanController
from ui.repository import FindingRow, HistoryRepository
from ui.theme import COLORS, severity_color
from ui.scan_messages import explain_scan_error
from ui.profiles import ScanPlan
from ui.wizard import ConsentWizard

LOG = logging.getLogger("oneguard.ui")


def label(text: str, style: str = "Muted", *, wrap: bool = True) -> QLabel:
    """Create consistent, accessible labels without inline HTML styles."""
    item = QLabel(text)
    item.setObjectName(style)
    item.setWordWrap(wrap)
    item.setTextFormat(Qt.TextFormat.PlainText)
    item.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return item


def panel(layout: QVBoxLayout | QHBoxLayout | QGridLayout, name: str = "Panel") -> QFrame:
    """Wrap a visual panel with reusable spacing."""
    widget = QFrame()
    widget.setObjectName(name)
    widget.setLayout(layout)
    layout.setContentsMargins(19, 19, 19, 19)
    layout.setSpacing(12)
    return widget


def vertical_page() -> tuple[QWidget, QVBoxLayout]:
    """Provide one spacious scroll-friendly page container."""
    page = QWidget()
    page.setObjectName("PageSurface")
    layout = QVBoxLayout(page)
    layout.setContentsMargins(26, 24, 26, 22)
    layout.setSpacing(16)
    return page, layout


class FindingsModel(QAbstractTableModel):
    """Fixed-size paginated SQLite view, suitable for responsive Qt filtering."""

    COLUMNS = ("Severidad", "Ubicación", "Tipo", "Motor", "Motivo", "Acción")

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[FindingRow] = []

    def set_rows(self, rows: list[FindingRow]) -> None:
        """Replace rows atomically when new SQLite records become available."""
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        """Return visible source row count."""
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        """Return the six public columns."""
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802
        """Provide unambiguous table headers."""
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        """Return presentation values and severity foregrounds."""
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        row = self.rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                f"{row.severity.upper()} · {row.score}", row.target,
                row.threat_type, ", ".join(row.engines), row.reason,
                "Excluido" if row.suppressed else "Ver detalles",
            )[col]
        if role == Qt.ItemDataRole.ForegroundRole and col == 0:
            return QColor(severity_color(row.severity))
        if role == Qt.ItemDataRole.ForegroundRole and col == 5:
            return QColor(COLORS["muted"] if row.suppressed else COLORS["accent"])
        if role == Qt.ItemDataRole.ToolTipRole:
            return row.reason if col == 4 else row.target
        if role == Qt.ItemDataRole.UserRole:
            return row
        return None


class FindingFilter(QSortFilterProxyModel):
    """Severity, threat-category and text search without changing stored data."""

    def __init__(self) -> None:
        super().__init__()
        self.severity = "Todas"
        self.threat_type = "Todos"
        self.search = ""

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        """Check row against all active result filters."""
        source = self.sourceModel()
        if source is None or source_row >= len(source.rows):
            return False
        record = source.rows[source_row]
        if self.severity != "Todas" and record.severity != self.severity:
            return False
        if self.threat_type != "Todos" and record.threat_type != self.threat_type:
            return False
        combined = " ".join((record.target, record.reason, record.threat_type,
                             " ".join(record.engines))).lower()
        return self.search.lower() in combined

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # noqa: N802
        """Sort risk numerically and other columns by readable text."""
        source = self.sourceModel()
        if source is None:
            return False
        if left.column() == 0:
            return source.rows[left.row()].score < source.rows[right.row()].score
        a = str(source.data(left, Qt.ItemDataRole.DisplayRole) or "").casefold()
        b = str(source.data(right, Qt.ItemDataRole.DisplayRole) or "").casefold()
        return a < b

    def update_filters(self, severity: str, threat_type: str, search: str) -> None:
        """Update model filtering without costly independent SQL queries."""
        self.severity = severity
        self.threat_type = threat_type
        self.search = search
        self.invalidateFilter()


class MetricTile(QFrame):
    """Named numeric metric with emphasis used only for actual scan counts."""

    def __init__(self, caption: str, color: str) -> None:
        super().__init__()
        self.setObjectName("Metric")
        column = QVBoxLayout(self)
        column.setContentsMargins(15, 13, 15, 13)
        caption_widget = label(caption.upper(), "Eyebrow")
        caption_widget.setStyleSheet(f"color: {color};")
        self.number = label("0", "MetricNumber")
        column.addWidget(caption_widget)
        column.addWidget(self.number)

    def set_count(self, number: int) -> None:
        """Update an observed value rather than a synthetic statistic."""
        self.number.setText(f"{number:,}".replace(",", "."))


class OneGuardWindow(QMainWindow):
    """Main responsive shell with live queue polling and evidence drill-down."""

    PAGE_NAMES = ("Inicio", "Análisis", "Hallazgos", "Investigación", "Historial", "Ajustes", "Cuarentena")

    def __init__(self, config: ScanConfig | None = None) -> None:
        super().__init__()
        self.config = config or ScanConfig()
        self.repository = HistoryRepository(self.config.database_path)
        self.controller = ScanController(self.config)
        self.scan_clock = ScanClock()
        self._last_clock_refresh = 0.0
        self._latest_performance: dict | None = None
        self._phase_started_at = monotonic()
        self._phase_finished_at: float | None = None
        self.session_id: str | None = None
        self.vt_key = ""
        self.mb_key = ""
        self._seen_warnings = 0
        self._coverage_groups: dict[str, int] = {}
        self._coverage_titles: dict[str, str] = {}
        self._current_error_count = 0
        self._found = 0
        self._is_paused = False
        self._completion_seen = False
        self._view_mode = "live"
        self._last_fetch_count = 0
        self._event_counter = 0
        self._action_queue: Queue[tuple[bool, str]] = Queue()
        self._action_busy = False
        self._active_finding: FindingRow | None = None
        self._display_session_id: str | None = None
        self.setWindowTitle("Sentinel OneGuard · Investigación de amenazas")
        self.setWindowIcon(QIcon(str(icon_path())))
        self.resize(1390, 900)
        self.setMinimumSize(1050, 680)
        self._setup_shell()
        self._setup_home()
        self._setup_scan()
        self._setup_findings()
        self._setup_investigation()
        self._setup_history()
        self._setup_settings()
        self._setup_quarantine()
        self._switch_page(0)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._drain_events)
        self.timer.start(90)
        self.refresh_history()

    def _setup_shell(self) -> None:
        """Create the fixed sidebar and independent content stack."""
        root = QWidget()
        root.setObjectName("RootSurface")
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(236)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(18, 23, 18, 17)
        side.setSpacing(7)
        brand_bar = QHBoxLayout()
        brand_mark = QLabel()
        brand_mark.setObjectName("BrandMark")
        brand_mark.setFixedSize(44, 44)
        pixmap = QPixmap(str(logo_path()))
        if not pixmap.isNull():
            brand_mark.setPixmap(pixmap.scaled(44, 44,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation))
        brand_bar.addWidget(brand_mark)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        brand_text.addWidget(label("SENTINEL", "Brand"))
        brand_text.addWidget(label("ONEGUARD", "Eyebrow"))
        brand_bar.addLayout(brand_text)
        brand_bar.addStretch()
        side.addLayout(brand_bar)
        side.addWidget(label("CENTRO DE ANÁLISIS", "Eyebrow", wrap=False))
        side.addSpacing(20)
        self.nav_buttons = []
        for index, title in enumerate(self.PAGE_NAMES):
            item = QPushButton(title)
            item.setObjectName("Nav")
            item.setCursor(Qt.CursorShape.PointingHandCursor)
            item.clicked.connect(lambda _, i=index: self._switch_page(i))
            side.addWidget(item)
            self.nav_buttons.append(item)
        side.addStretch()
        note = QVBoxLayout()
        note.addWidget(label("ESTADO", "Eyebrow", wrap=False))
        self.sidebar_status = label("Sin evaluación reciente.")
        self.sidebar_status.setToolTip(
            "Un resultado sin hallazgos no certifica que Windows esté limpio."
        )
        note.addWidget(self.sidebar_status)
        side.addWidget(panel(note))
        side.addWidget(label("MITIGACIÓN MANUAL", "Eyebrow", wrap=False))
        self.pages = QStackedWidget()
        for _ in self.PAGE_NAMES:
            self.pages.addWidget(QWidget())
        outer.addWidget(sidebar)
        outer.addWidget(self.pages, 1)
        self.setCentralWidget(root)

    def _switch_page(self, index: int) -> None:
        """Navigate without resetting an active scan."""
        self.pages.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setProperty("active", i == index)
            button.style().unpolish(button)
            button.style().polish(button)
        if index == 4:
            self.refresh_history()
        elif index == 6:
            self.refresh_quarantine()

    def _setup_home(self) -> None:
        """Provide action-first navigation without pretending the device is safe."""
        page, column = vertical_page()
        column.addWidget(label("CENTRO DE SEGURIDAD  /  SENTINEL ONEGUARD", "Eyebrow"))
        column.addWidget(label("Investiga antes de actuar.", "Title"))
        column.addWidget(label(
            "Escanea, compara evidencias y elige acciones de respuesta. "
            "Un resultado sin detecciones nunca certifica que Windows esté limpio."
        ))

        overview = QVBoxLayout()
        overview.addWidget(label("ÚLTIMA EVALUACIÓN", "Eyebrow"))
        self.home_status = label("Todavía no se ha evaluado este equipo.", "SectionHeading")
        self.home_last_scan = label(
            "Inicia un análisis para registrar hallazgos, errores y cobertura real."
        )
        overview.addWidget(self.home_status)
        overview.addWidget(self.home_last_scan)
        column.addWidget(panel(overview, "Hero"))

        column.addWidget(label("ELIGE CÓMO INSPECCIONAR", "Eyebrow"))
        options = QHBoxLayout()
        for kind, heading, detail in (
            ("quick", "Rápido", "Ubicaciones frecuentes y carpetas críticas del usuario."),
            ("full", "Completo", "Unidades fijas locales; duración variable."),
            ("custom", "Personalizado", "Selecciona archivos o carpetas concretas."),
        ):
            contents = QVBoxLayout()
            contents.addWidget(label(heading.upper(), "Eyebrow"))
            contents.addWidget(label(heading, "Heading"))
            contents.addWidget(label(detail))
            contents.addStretch()
            button = QPushButton("Configurar análisis")
            button.setObjectName("Primary" if kind == "quick" else "ScanAction")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(
                lambda _checked=False, selected=kind: self._open_with_profile(selected)
            )
            contents.addWidget(button)
            options.addWidget(panel(contents), 1)
        column.addLayout(options)

        foot = QHBoxLayout()
        foot.addWidget(label(
            "DETECTAR → INVESTIGAR → REVISAR → MITIGAR  ·  "
            "Nada se elimina sin aprobación.", "Eyebrow"
        ), 1)
        history = QPushButton("Consultar historial")
        history.clicked.connect(lambda: self._switch_page(4))
        foot.addWidget(history)
        column.addLayout(foot)
        column.addStretch()
        self.pages.removeWidget(self.pages.widget(0))
        self.pages.insertWidget(0, page)

    def _setup_scan(self) -> None:
        """Build real-time metrics, phases, progress and bounded log console."""
        page, column = vertical_page()
        upper = QHBoxLayout()
        heading_col = QVBoxLayout()
        heading_col.addWidget(label("ESCÁNER / EN DIRECTO", "Eyebrow"))
        heading_col.addWidget(label("Análisis del dispositivo", "Title"))
        self.scan_status = label("Sin análisis en curso")
        heading_col.addWidget(self.scan_status)
        upper.addLayout(heading_col, 1)
        self.new_scan_button = QPushButton("Nuevo análisis")
        self.new_scan_button.setObjectName("Primary")
        self.new_scan_button.clicked.connect(self.open_wizard)
        upper.addWidget(self.new_scan_button, alignment=Qt.AlignmentFlag.AlignBottom)
        column.addLayout(upper)
        metrics = QHBoxLayout()
        self.scanned_tile = MetricTile("Inspeccionados", COLORS["accent"])
        self.threats_tile = MetricTile("Hallazgos", COLORS["danger"])
        self.partial_tile = MetricTile("Cobertura parcial", COLORS["amber"])
        self.error_tile = MetricTile("Errores", COLORS["muted"])
        for tile in (self.scanned_tile, self.threats_tile, self.partial_tile, self.error_tile):
            metrics.addWidget(tile, 1)
        column.addLayout(metrics)
        center = QHBoxLayout()
        work_layout = QVBoxLayout()
        work_layout.addWidget(label("ESTADO DEL ANÁLISIS", "Eyebrow"))
        self.scan_phase = label("Preparado para iniciar")
        self.scan_phase.setObjectName("SectionHeading")
        work_layout.addWidget(self.scan_phase)
        self.failure_hint = label("", "FailureHint")
        self.failure_hint.setVisible(False)
        work_layout.addWidget(self.failure_hint)
        timing = QHBoxLayout()
        self.elapsed_label = label("Transcurrido  00:00", "Eyebrow")
        self.rate_label = label("Ritmo observado  — archivos/s", "Eyebrow")
        timing.addWidget(self.elapsed_label)
        timing.addStretch()
        timing.addWidget(self.rate_label)
        work_layout.addLayout(timing)
        self.eta_label = label("Tiempo restante · recopilando mediciones", "SmallHelp")
        work_layout.addWidget(self.eta_label)
        self.resources_label = label("Recursos · recopilando datos", "SmallHelp")
        self.pending_label = label("Objetivos pendientes · sin inventario completo", "SmallHelp")
        work_layout.addWidget(self.resources_label)
        work_layout.addWidget(self.pending_label)
        self.engine_perf_button = QPushButton("Rendimiento por motor")
        self.engine_perf_button.setEnabled(False)
        self.engine_perf_button.clicked.connect(self.show_engine_performance)
        work_layout.addWidget(self.engine_perf_button)
        self.phase_time_label = label("Fase en curso  00:00")
        work_layout.addWidget(self.phase_time_label)
        self.global_label = label("Progreso global · aún no disponible")
        work_layout.addWidget(self.global_label)
        self.global_progress = QProgressBar()
        self.global_progress.setRange(0, 100)
        self.global_progress.setValue(0)
        work_layout.addWidget(self.global_progress)
        self.phase_label = label("Tareas conocidas · 0 / 0")
        work_layout.addWidget(self.phase_label)
        self.phase_progress = QProgressBar()
        self.phase_progress.setRange(0, 100)
        self.phase_progress.setValue(0)
        work_layout.addWidget(self.phase_progress)
        self.current_target = label("Esperando un objetivo…")
        self.current_target.setWordWrap(True)
        work_layout.addWidget(self.current_target)
        center.addWidget(panel(work_layout), 3)
        notes = QVBoxLayout()
        notes.addWidget(label("ALCANCE AUTORIZADO", "Eyebrow", wrap=False))
        self.coverage_files = label("Archivos · aún sin selección")
        self.coverage_processes = label("Procesos y red · sin autorización")
        self.coverage_persistence = label("Persistencia · sin autorización")
        self.coverage_online = label("Reputación · local")
        for coverage in (
            self.coverage_files, self.coverage_processes,
            self.coverage_persistence, self.coverage_online,
        ):
            notes.addWidget(coverage)
        notes.addStretch()
        notes.addWidget(label(
            "Los motores disponibles y las omisiones se registran "
            "durante el análisis.", "SmallHelp"
        ))
        notes.addWidget(label("Sin hallazgos ≠ equipo limpio", "WarningText"))
        center.addWidget(panel(notes), 2)
        column.addLayout(center)
        log_title = QHBoxLayout()
        log_title.addWidget(label("REGISTRO DE ACTIVIDAD", "Eyebrow", wrap=False))
        log_title.addStretch()
        self.coverage_detail_button = QPushButton("Ver omisiones")
        self.coverage_detail_button.setEnabled(False)
        self.coverage_detail_button.clicked.connect(self.show_coverage_details)
        log_title.addWidget(self.coverage_detail_button)
        self.console_toggle = QPushButton("Ocultar registro")
        self.console_toggle.clicked.connect(self.toggle_console)
        log_title.addWidget(self.console_toggle)
        self.pause_button = QPushButton("Pausar")
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.setObjectName("Danger")
        self.pause_button.clicked.connect(self.toggle_pause)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.pause_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        log_title.addWidget(self.pause_button)
        log_title.addWidget(self.cancel_button)
        column.addLayout(log_title)
        self.console = QPlainTextEdit()
        self.console.setObjectName("EventConsole")
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(800)
        self.console.setMinimumHeight(150)
        self.console.setMaximumHeight(245)
        self.console.setFont(QFont("Consolas", 10))
        column.addWidget(self.console)
        column.addStretch(1)
        scan_scroll = QScrollArea()
        scan_scroll.setWidgetResizable(True)
        scan_scroll.setFrameShape(QFrame.Shape.NoFrame)
        scan_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        scan_scroll.setWidget(page)
        self.pages.removeWidget(self.pages.widget(1))
        self.pages.insertWidget(1, scan_scroll)

    def _setup_findings(self) -> None:
        """Provide filterable persisted findings with contextual evidence detail."""
        page, column = vertical_page()
        column.addWidget(label("EVIDENCIAS / HALLAZGOS", "Eyebrow"))
        column.addWidget(label("Resultados explicados", "Title"))
        self.results_caption = label("Selecciona una sesión para ver sus resultados")
        column.addWidget(self.results_caption)
        filters = QHBoxLayout()
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Todas", "critical", "high", "medium", "low", "info"])
        self.type_filter = QComboBox()
        self.type_filter.addItem("Todos")
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Buscar ruta, tipo, motor o evidencia…")
        filters.addWidget(self.severity_filter)
        filters.addWidget(self.type_filter)
        filters.addWidget(self.search_box, 1)
        column.addLayout(filters)
        report_bar = QHBoxLayout()
        self.html_button = QPushButton("Exportar HTML")
        self.csv_button = QPushButton("Exportar CSV")
        self.html_button.clicked.connect(lambda: self.export_report("html"))
        self.csv_button.clicked.connect(lambda: self.export_report("csv"))
        report_bar.addStretch()
        report_bar.addWidget(self.html_button)
        report_bar.addWidget(self.csv_button)
        column.addLayout(report_bar)
        self.model = FindingsModel()
        self.proxy = FindingFilter()
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(37)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.proxy.setDynamicSortFilter(True)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self.table.setColumnWidth(0, 112)
        self.table.setColumnWidth(1, 340)
        self.table.setColumnWidth(2, 170)
        self.table.setColumnWidth(3, 110)
        self.table.setColumnWidth(4, 250)
        self.table.setMinimumHeight(230)
        self.severity_filter.currentTextChanged.connect(self._update_filter)
        self.type_filter.currentTextChanged.connect(self._update_filter)
        self.search_box.textChanged.connect(self._update_filter)
        self.table.selectionModel().selectionChanged.connect(self._selected_finding)
        detail_layout = QVBoxLayout()
        detail_layout.addWidget(label("DETALLES Y RAZONES", "Eyebrow"))
        self.detail_title = label("Selecciona un hallazgo", "SectionHeading")
        detail_layout.addWidget(self.detail_title)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMinimumHeight(180)
        self.detail.setPlaceholderText("Las evidencias técnicas aparecerán aquí.")
        detail_layout.addWidget(self.detail, 1)
        actions = QHBoxLayout()
        self.quarantine_button = QPushButton("Poner en cuarentena")
        self.quarantine_button.clicked.connect(self.request_quarantine)
        self.ignore_button = QPushButton("Ignorar hash")
        self.ignore_button.clicked.connect(self.request_ignore)
        self.process_button = QPushButton("Finalizar proceso")
        self.process_button.clicked.connect(self.request_process_termination)
        self.autorun_button = QPushButton("Desactivar inicio HKCU")
        self.autorun_button.clicked.connect(self.request_disable_autorun)
        for button in (self.quarantine_button, self.ignore_button,
                       self.process_button, self.autorun_button):
            button.setEnabled(False)
            actions.addWidget(button)
        detail_layout.addLayout(actions)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(panel(detail_layout))
        splitter.setSizes([420, 280])
        column.addWidget(splitter, 1)
        self.pages.removeWidget(self.pages.widget(2))
        self.pages.insertWidget(2, page)

    def _setup_investigation(self) -> None:
        """Show evidence-based associations without fictional causal timelines."""
        page, column = vertical_page()
        column.addWidget(label("ANÁLISIS DE INCIDENTES", "Eyebrow"))
        column.addWidget(label("¿Qué puede explicar los hallazgos?", "Title"))
        column.addWidget(label(
            "Relaciona ejecutables y mecanismos de persistencia respaldados por los motores. "
            "Un vínculo por ruta no demuestra el punto de entrada ni un robo de datos."))
        self.investigation_text = QPlainTextEdit()
        self.investigation_text.setReadOnly(True)
        self.investigation_text.setPlainText(
            "Aún no hay un análisis investigable. Completa un análisis y se mostrarán "
            "las relaciones encontradas, prioridades de revisión y limitaciones.")
        column.addWidget(self.investigation_text, 1)
        column.addWidget(label(
            "Fase 5: tras aplicar una acción, ejecuta un análisis nuevo para verificar resultados. "
            "No se concluye que el equipo esté limpio únicamente por retirar un hallazgo."))
        self.pages.removeWidget(self.pages.widget(3))
        self.pages.insertWidget(3, page)

    def _setup_history(self) -> None:
        """Allow users to inspect previous persisted sessions read-only."""
        page, column = vertical_page()
        column.addWidget(label("HISTORIAL LOCAL", "Eyebrow"))
        column.addWidget(label("Análisis anteriores", "Title"))
        column.addWidget(label("La base de datos se mantiene en tu equipo. Doble clic para revisar hallazgos."))
        self.history_table = QTableWidget(0, 7)
        self.history_table.setHorizontalHeaderLabels([
            "Inicio", "Duración", "Estado", "Archivos", "Hallazgos", "Errores", "ID",
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.doubleClicked.connect(self.open_historical_scan)
        column.addWidget(self.history_table, 1)
        buttons = QHBoxLayout()
        reload_button = QPushButton("Actualizar historial")
        reload_button.clicked.connect(self.refresh_history)
        buttons.addWidget(reload_button)
        timing_button = QPushButton("Ver rendimiento de sesión")
        timing_button.clicked.connect(self.show_historical_performance)
        buttons.addWidget(timing_button)
        buttons.addStretch()
        column.addLayout(buttons)
        column.addWidget(label("Puedes exportar informes HTML/CSV desde Hallazgos tras abrir una sesión."))
        self.pages.removeWidget(self.pages.widget(4))
        self.pages.insertWidget(4, page)

    def _setup_settings(self) -> None:
        """Keep provider keys ephemeral; do not persist them to disk."""
        page, column = vertical_page()
        column.addWidget(label("CONFIGURACIÓN LOCAL", "Eyebrow"))
        column.addWidget(label("Reputación y privacidad", "Title"))
        column.addWidget(label(
            "Solo se consulta un proveedor cuando el asistente autoriza los hashes en línea. "
            "Sin autorización, no se realizan consultas externas."))
        for field_name, title, help_text in (
            ("vt_input", "VirusTotal v3 · API Key", "Solo SHA-256 · se respeta el control de solicitudes del núcleo."),
            ("mb_input", "MalwareBazaar · Auth-Key", "Solo SHA-256 · puede requerir clave según el proveedor."),
        ):
            sub = QVBoxLayout()
            sub.addWidget(label(title, "SectionHeading"))
            input_box = QLineEdit()
            input_box.setEchoMode(QLineEdit.EchoMode.Password)
            input_box.setPlaceholderText("Introduce la clave solo para esta sesión")
            setattr(self, field_name, input_box)
            sub.addWidget(input_box)
            sub.addWidget(label(help_text))
            column.addWidget(panel(sub))
        save = QPushButton("Aplicar claves en memoria")
        save.clicked.connect(self.save_keys)
        column.addWidget(save, alignment=Qt.AlignmentFlag.AlignLeft)
        column.addWidget(label(
            "Las claves se conservan solo durante la ejecución de esta aplicación. "
            "También puedes utilizar ONEGUARD_VT_API_KEY / ONEGUARD_MB_API_KEY "
            "desde variables de entorno. No se guardan en SQLite ni en el README."))
        column.addStretch()
        self.pages.removeWidget(self.pages.widget(5))
        self.pages.insertWidget(5, page)

    def save_keys(self) -> None:
        """Keep API credentials in memory only, not in settings or output logs."""
        self.vt_key = self.vt_input.text().strip()
        self.mb_key = self.mb_input.text().strip()
        self.vt_input.clear()
        self.mb_input.clear()
        QMessageBox.information(self, "Configuración", "Claves aplicadas en memoria para esta ejecución.")

    def open_wizard(self) -> None:
        """Open the standard opt-in scan wizard."""
        self._open_with_profile("quick")

    def _open_with_profile(self, profile: str) -> None:
        """Preselect one scan type while still requiring all user permissions."""
        if self.controller.running:
            QMessageBox.information(self, "Escaneo activo", "Cancela o termina el análisis actual antes de iniciar otro.")
            return
        wizard = ConsentWizard(self)
        profile_buttons = {
            "quick": wizard.quick, "full": wizard.full, "custom": wizard.custom,
        }
        profile_buttons.get(profile, wizard.quick).setChecked(True)
        if wizard.exec() != ConsentWizard.DialogCode.Accepted or not wizard.plan:
            return
        self._prepare_live_scan()
        self._show_scan_scope(wizard.plan)
        try:
            self.controller.start(
                wizard.plan, vt_key=self.vt_key or self.config.vt_api_key,
                mb_key=self.mb_key or self.config.mb_api_key,
            )
        except RuntimeError as exc:
            QMessageBox.warning(self, "No se pudo iniciar", str(exc))
            return
        self._switch_page(1)

    def toggle_console(self) -> None:
        """Expand or collapse the activity log without losing scan events."""
        visible = not self.console.isVisible()
        self.console.setVisible(visible)
        self.console_toggle.setText(
            "Ocultar registro" if visible else "Mostrar registro"
        )

    def _show_scan_scope(self, plan: ScanPlan) -> None:
        """Present the authorized scope, not unverified detector availability."""
        names = {
            "quick": "Rápido", "full": "Completo", "custom": "Personalizado",
        }
        scope = names.get(plan.profile, "Seleccionado")
        self.coverage_files.setText(
            f"Archivos · {scope} · {len(plan.roots)} ubicaciones"
        )
        self.coverage_processes.setText(
            "Procesos y red · autorizados" if plan.processes else
            "Procesos y red · no autorizados"
        )
        self.coverage_persistence.setText(
            "Persistencia · autorizada" if plan.persistence else
            "Persistencia · no autorizada"
        )
        self.coverage_online.setText(
            "Reputación · consulta de hashes autorizada" if plan.online else
            "Reputación · solo local"
        )

    def _prepare_live_scan(self) -> None:
        """Reset only session-specific UI data, never erase stored results."""
        self._completion_seen = False
        self._is_paused = False
        self._seen_warnings = 0
        self._coverage_groups.clear()
        self._coverage_titles.clear()
        self._current_error_count = 0
        self._found = 0
        self._last_fetch_count = 0
        self._view_mode = "live"
        self._display_session_id = None
        self.session_id = None
        self._show_rows([])
        self.results_caption.setText("Análisis en preparación · todavía no hay resultados.")
        self.scanned_tile.set_count(0)
        self.threats_tile.set_count(0)
        self.partial_tile.set_count(0)
        self.coverage_detail_button.setEnabled(False)
        self.error_tile.set_count(0)
        self.global_progress.setRange(0, 0)
        self.phase_progress.setRange(0, 100)
        self.phase_progress.setValue(0)
        self.global_label.setText("Descubriendo objetivos · tiempo restante no estimable")
        self.scan_clock.reset()
        self._latest_performance = None
        self.engine_perf_button.setEnabled(False)
        self.eta_label.setText("Tiempo restante · recopilando mediciones")
        self.resources_label.setText("Recursos · recopilando datos")
        self.pending_label.setText("Objetivos pendientes · sin inventario completo")
        self._last_clock_refresh = 0.0
        self.elapsed_label.setText("Transcurrido  00:00")
        self.rate_label.setText("Ritmo observado  — archivos/s")
        self._phase_started_at = monotonic()
        self._phase_finished_at = None
        self.phase_time_label.setText("Fase en curso  00:00")
        self.phase_label.setText("Trabajo identificado · 0 / 0 (total dinámico)")
        self.scan_phase.setText("Preparando motores de detección")
        self.failure_hint.setVisible(False)
        self.failure_hint.clear()
        self.console.setVisible(True)
        self.console_toggle.setText("Ocultar registro")
        self.scan_status.setText("Preparando análisis…")
        self.console.clear()
        self.pause_button.setEnabled(False)
        self.pause_button.setText("Pausar")
        self.cancel_button.setEnabled(True)
        self.new_scan_button.setEnabled(False)
        self.sidebar_status.setText("Análisis en curso")
        self._log("INFO", "Consentimiento recibido. Análisis de solo lectura iniciado; la respuesta es opcional.")

    def toggle_pause(self) -> None:
        """Cooperatively pause or resume the producer, not force-kill workers."""
        if not self.controller.running:
            return
        if self._is_paused:
            self.controller.resume()
            self._is_paused = False
            self.pause_button.setText("Pausar")
        else:
            self.controller.pause()
            self._is_paused = True
            self.pause_button.setText("Reanudar")

    def cancel_scan(self) -> None:
        """Explicitly request cancellation without touching scanned files."""
        if not self.controller.running:
            return
        self.controller.cancel()
        self.cancel_button.setEnabled(False)
        self._log("WARN", "Cancelación solicitada; esperando operaciones activas.")

    def _log(self, severity: str, text: str) -> None:
        """Append a bounded, severity-tinted line using Qt document formatting."""
        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        color = {
            "WARN": COLORS["amber"], "ERROR": COLORS["danger"],
            "FIND": COLORS["danger"], "OK": COLORS["green"],
        }.get(severity, COLORS["muted"])
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.insertText(f"[{datetime.now().strftime('%H:%M:%S')}] {severity:<5}  {text}\n", fmt)
        self.console.setTextCursor(cursor)
        self.console.ensureCursorVisible()

    def _drain_events(self) -> None:
        """Poll at most 250 events per tick, keeping GUI processing bounded."""
        self._drain_action_queue()
        try:
            for _ in range(250):
                try:
                    event = self.controller.bus.get_nowait()
                except Empty:
                    break
                self._apply_event(event)
        except Exception:
            LOG.exception("Error no recuperable al actualizar interfaz")
        if self.session_id and self.controller.running and self._event_counter > 0:
            from time import monotonic
            now = monotonic()
            if now - getattr(self, "_last_refresh_at", 0.0) >= 0.75:
                self._last_refresh_at = now
                self._event_counter = 0
                self._refresh_findings_safely()
        self._update_scan_metrics()

    def _update_scan_metrics(self, *, force: bool = False) -> None:
        """Display observed elapsed time and throughput; never predict an ETA."""
        if not self.controller.running and not self._completion_seen:
            return
        now = monotonic()
        if not force and now - self._last_clock_refresh < 0.75:
            return
        self._last_clock_refresh = now
        observed = self.scan_clock.snapshot()
        self.elapsed_label.setText(
            f"Transcurrido  {format_duration(observed.elapsed_seconds)}"
            + (f" · pausa {format_duration(observed.paused_seconds)}"
               if observed.paused_seconds > 0 else "")
        )
        # Prefer the scanner's measured target throughput once available.
        if self._latest_performance is None:
            self.rate_label.setText(
                f"Ritmo observado  {observed.files_per_second:.1f} archivos/s"
                if observed.active_seconds >= 1.0 else
                "Ritmo observado  calculando…"
            )
        phase_end = self._phase_finished_at if self._phase_finished_at is not None else now
        phase_elapsed = max(0.0, phase_end - self._phase_started_at)
        self.phase_time_label.setText(
            f"Fase en curso  {format_duration(phase_elapsed)}"
        )

    def _render_performance(self, data: dict) -> None:
        """Display observed rates and an explicitly scoped time estimate."""
        self._latest_performance = data
        engines = data.get("engines") or {}
        self.engine_perf_button.setEnabled(bool(engines))
        resources = data.get("process_resources") or {}
        if resources:
            cpu = float(resources.get("cpu_percent", 0.0))
            ram = int(resources.get("rss_bytes", 0)) / (1024 * 1024)
            self.resources_label.setText(
                f"Este proceso · CPU {cpu:.1f}% · memoria RAM {ram:.0f} MiB"
            )
        else:
            self.resources_label.setText("Recursos · no disponibles")
        pending = max(0, int(data.get("remaining_known", 0)))
        discovery = bool(data.get("discovery_complete", False))
        self.pending_label.setText(
            f"Objetivos conocidos pendientes · {pending:,}"
            .replace(",", ".") +
            ("" if discovery else " · inventario en curso")
        )
        speed = float(data.get("throughput_targets_per_second", 0.0))
        self.rate_label.setText(
            f"Ritmo observado  {speed:.1f} objetivos/s" if speed > 0
            else "Ritmo observado  calculando…"
        )
        eta = data.get("eta")
        if data.get("paused"):
            self.eta_label.setText("Tiempo restante · análisis en pausa")
        elif not isinstance(eta, dict):
            self.eta_label.setText(
                "Tiempo restante · recopilando mediciones"
                if not data.get("discovery_complete")
                else "Tiempo restante · sin estimación fiable"
            )
        else:
            low = format_duration(float(eta.get("low_seconds", 0)))
            high = format_duration(float(eta.get("high_seconds", 0)))
            if eta.get("scope") == "known":
                self.eta_label.setText(
                    f"Cola conocida: ~{low}–{high} · aún se descubren objetivos"
                )
            else:
                self.eta_label.setText(
                    f"Tiempo restante orientativo: {low}–{high}"
                )

    def show_engine_performance(self) -> None:
        """Show observed engine measurements for the current session."""
        self._open_engine_metrics(
            (self._latest_performance or {}).get("engines") or {}
        )

    def _open_engine_metrics(self, engines: dict) -> None:
        """Present cumulative measurements without confusing concurrency with wall time."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Rendimiento observado por motor")
        dialog.resize(760, 460)
        layout = QVBoxLayout(dialog)
        layout.addWidget(label(
            "Duraciones acumuladas de invocaciones por motor. "
            "Pueden ejecutarse en paralelo; no son el tiempo total. "
            "Los bytes son tamaños de entrada, no lectura física."
        ))
        details = QPlainTextEdit()
        details.setReadOnly(True)
        rows = []
        for name, item in sorted(
            engines.items(),
            key=lambda value: -float(value[1].get("duration_seconds", 0)),
        ):
            checks = int(item.get("checks", 0))
            elapsed = float(item.get("duration_seconds", 0))
            mean_ms = 1000 * elapsed / checks if checks else 0
            mb = int(item.get("input_size_bytes", 0)) / (1024 * 1024)
            rows.append(
                f"{name} · {checks} comprobaciones · {elapsed:.2f} s acumulados "
                f"· {mean_ms:.1f} ms/comprobación\n"
                f"  Completadas: {item.get('completed', 0)} · "
                f"Omitidas: {item.get('skipped', 0)} · "
                f"Errores: {item.get('errors', 0)} · "
                f"Entrada: {mb:.1f} MiB"
            )
        details.setPlainText("\n\n".join(rows) if rows else
                             "Todavía no hay mediciones de motores.")
        layout.addWidget(details)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def _record_coverage(self, event: ScanEvent) -> None:
        """Count partial checks while avoiding repeated console messages."""
        note = present_event(event)
        group = note.dedupe_key
        count = self._coverage_groups.get(group, 0) + 1
        self._coverage_groups[group] = count
        self._coverage_titles[group] = note.title
        self._seen_warnings += 1
        self.partial_tile.set_count(self._seen_warnings)
        self.coverage_detail_button.setEnabled(True)
        if count == 1:
            self._log("WARN", f"{note.title}. {note.description}")

    def show_coverage_details(self) -> None:
        """Show affected paths and reasons stored on this device."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Cobertura parcial · detalle de omisiones")
        dialog.resize(850, 480)
        layout = QVBoxLayout(dialog)
        layout.addWidget(label(
            "Una omisión no equivale a una infección. "
            "Solo se muestran evidencias guardadas localmente."
        ))
        detail = QPlainTextEdit()
        detail.setReadOnly(True)
        lines = [
            f"{title} — {self._coverage_groups[key]} incidencia(s)"
            for key, title in self._coverage_titles.items()
        ]
        if self.session_id:
            try:
                store = SQLiteStore(self.config.database_path)
                with store.connection() as conn:
                    rows = conn.execute(
                        """SELECT target_path, engine, detail
                           FROM scan_coverage WHERE session_id=?
                           ORDER BY target_path LIMIT 500""",
                        (self.session_id,),
                    ).fetchall()
                    total = conn.execute(
                        "SELECT COUNT(*) FROM scan_coverage WHERE session_id=?",
                        (self.session_id,),
                    ).fetchone()[0]
                lines.extend(
                    f"{row['engine']} · {row['target_path']}\n   {row['detail']}"
                    for row in rows
                )
                if total > len(rows):
                    lines.append(f"Hay {total - len(rows)} registros adicionales.")
            except (OSError, sqlite3.Error) as exc:
                lines.append(f"Historial no disponible: {type(exc).__name__}")
        detail.setPlainText("\n\n".join(lines))
        layout.addWidget(detail)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def _apply_event(self, event: ScanEvent) -> None:
        """Apply one immutable core event on the GUI thread only."""
        payload = event.payload
        kind = event.kind
        if kind == "started":
            self.session_id = payload["session_id"]
            self.scan_status.setText("Analizando (sin estimación global fiable)")
            self.pause_button.setEnabled(True)
            self._log("INFO", "Sesión " + self.session_id[:12] + " iniciada")
        elif kind == "phase":
            self._phase_started_at = monotonic()
            self.scan_phase.setText(payload["name"])
            self._log("INFO", payload["name"])
        elif kind == "warning":
            note = present_event(event)
            if note.category == "coverage":
                self._record_coverage(event)
            else:
                self._log(note.level, f"{note.title}. {note.description}")
        elif kind == "current_target":
            self.current_target.setText(
                "ÚLTIMO OBJETIVO ENVIADO A LA COLA   " + payload.get("path", "")
            )
        elif kind == "finding":
            self._found += 1
            self.threats_tile.set_count(self._found)
            self._event_counter += 1
            severity = str(payload.get("severity", "info")).lower()
            level = ("FIND" if severity in ("critical", "high") else
                     "WARN" if severity in ("medium", "low") else "INFO")
            self._log(level, f"{severity.upper()} · {payload.get('type')} · {payload.get('target')}")
        elif kind == "skipped":
            self._record_coverage(event)
        elif kind == "error":
            self._current_error_count += 1
            self.error_tile.set_count(self._current_error_count)
            message = str(payload.get("message", "Error no especificado"))
            if self.session_id is None:
                self.failure_hint.setText(explain_scan_error(message))
                self.failure_hint.setVisible(True)
            self._log("ERROR", message)
        elif kind == "performance":
            self._render_performance(payload)
        elif kind == "progress":
            done = int(payload.get("scanned", 0)) + int(payload.get("system_scanned", 0))
            known = int(payload.get("discovered", 0)) + int(payload.get("system_scanned", 0))
            self.scanned_tile.set_count(int(payload.get("scanned", 0)))
            self.scan_clock.set_processed(int(payload.get("scanned", 0)))
            self.phase_label.setText(
                f"Trabajo conocido · {done:,} / {known:,} (puede aumentar)"
                .replace(",", ".")
            )
            self.phase_progress.setRange(0, 100)
            # This is only a known-work indicator, not a global percentage.
            self.phase_progress.setValue(min(99, round(done / known * 100)) if known else 0)
        elif kind == "paused":
            self.scan_clock.pause()
            self.scan_status.setText("Pausado (trabajos en curso pueden finalizar)")
            self._log("WARN", "Pausa cooperativa solicitada")
        elif kind == "resumed":
            self.scan_clock.resume()
            self.scan_status.setText("Analizando")
            self._log("INFO", "Análisis reanudado")
        elif kind == "cancelling":
            self.scan_status.setText("Cancelando operaciones")
        elif kind == "complete":
            self._complete(payload)
        elif kind == "investigation":
            self._render_investigation(payload)

    def _complete(self, payload: dict) -> None:
        """Finalize UI controls and show real core status, even when cancelled."""
        self._completion_seen = True
        # The final summary is authoritative if intermediate progress messages
        # were dropped to keep the bounded event queue responsive.
        final_scanned = int(payload.get("scanned", 0))
        self.scanned_tile.set_count(final_scanned)
        self.scan_clock.set_processed(final_scanned)
        self.error_tile.set_count(int(payload.get("errors", self._current_error_count)))
        # Bounded queues may discard intermediate skip events; use final totals.
        self._seen_warnings = max(
            self._seen_warnings, int(payload.get("omitted_checks", 0))
        )
        self.partial_tile.set_count(self._seen_warnings)
        summary = self.controller.last_summary
        if summary is not None:
            self.threats_tile.set_count(len(summary.findings))
        self.scan_clock.finish()
        self._phase_finished_at = monotonic()
        self._update_scan_metrics(force=True)
        if isinstance(payload.get("performance"), dict):
            self._render_performance(payload["performance"])
        self.eta_label.setText(
            "Tiempo restante · análisis finalizado"
            if payload.get("status") == "completed" else
            "Tiempo restante · análisis interrumpido"
        )
        self._display_session_id = self.session_id
        status = str(payload.get("status", "failed"))
        self.global_progress.setRange(0, 100)
        self.global_progress.setValue(100 if status == "completed" else 0)
        self.global_label.setText(
            "Análisis terminado · comprobar archivos omitidos y advertencias"
            if status == "completed" else
            "Análisis interrumpido · cobertura incompleta; revisar registro"
        )
        self.phase_progress.setValue(100 if status == "completed" else self.phase_progress.value())
        if status == "failed" and not self.failure_hint.text():
            self.failure_hint.setText(explain_scan_error(""))
            self.failure_hint.setVisible(True)
        elif status == "completed":
            self.failure_hint.setVisible(False)
        self.scan_status.setText({
            "completed": "Análisis terminado · revisar cobertura y evidencias",
            "cancelled": "Análisis cancelado · resultados parciales",
            "failed": "Análisis fallido · resultados no concluyentes",
        }.get(status, "Estado desconocido"))
        self.sidebar_status.setText({
            "completed": "Análisis finalizado\nRevisar evidencias",
            "cancelled": "Cancelado\nCobertura parcial",
            "failed": "Falló\nNo concluyente",
        }.get(status, "Estado desconocido"))
        self.pause_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.new_scan_button.setEnabled(True)
        self._log("OK" if status == "completed" else "WARN", self.scan_status.text())
        for group, count in self._coverage_groups.items():
            if count > 1:
                self._log(
                    "WARN", f"{self._coverage_titles[group]} · {count} omisiones. "
                    "Consulta el detalle para revisar los objetivos."
                )
        self._refresh_findings_safely()
        self.refresh_history()
        if self.session_id and self._last_fetch_count == 0:
            self.results_caption.setText(
                f"Sesión {self.session_id[:12]} · sin hallazgos visibles. "
                "Revisa cobertura, advertencias y errores; no equivale a equipo limpio."
            )
        # Never redirect failed initialization to an empty results table.
        if self.session_id and status in ("completed", "cancelled"):
            self._switch_page(2)
        else:
            self._switch_page(1)

    def _refresh_findings_safely(self) -> None:
        """Fetch a bounded SQLite page; report lock problems without freezing UI."""
        if not self.session_id or self._view_mode != "live":
            return
        try:
            rows = self.repository.findings(self.session_id)
        except sqlite3.Error as exc:
            self._log("WARN", f"No se pudieron refrescar los hallazgos: {type(exc).__name__}")
            return
        if len(rows) != self._last_fetch_count:
            self._last_fetch_count = len(rows)
            self._show_rows(rows)

    def _show_rows(self, rows: list[FindingRow]) -> None:
        """Replace table data and preserve available threat type filters."""
        self.model.set_rows(rows)
        self._active_finding = None
        for button in (self.quarantine_button, self.ignore_button,
                       self.process_button, self.autorun_button):
            button.setEnabled(False)
        old = self.type_filter.currentText()
        unique_types = sorted({record.threat_type for record in rows})
        self.type_filter.blockSignals(True)
        self.type_filter.clear()
        self.type_filter.addItems(["Todos", *unique_types])
        index = self.type_filter.findText(old)
        self.type_filter.setCurrentIndex(index if index >= 0 else 0)
        self.type_filter.blockSignals(False)
        self._update_filter()
        actionable = [r for r in rows if not r.suppressed and r.score >= 20]
        severe = sum(r.severity in {"critical", "high"} for r in actionable)
        self.results_caption.setText(
            f"{len(rows)} hallazgos visibles · {severe} altos/críticos · "
            f"{len(actionable)} requieren revisión. "
            "Sin hallazgos no equivale a un equipo limpio."
        )

    def _update_filter(self, *_args) -> None:
        """Apply active filters to the bounded in-memory table model."""
        self.proxy.update_filters(
            self.severity_filter.currentText(), self.type_filter.currentText(),
            self.search_box.text().strip(),
        )

    def _selected_finding(self, *_args) -> None:
        """Read evidence of exactly the selected record, never touch its file."""
        indices = self.table.selectionModel().selectedRows()
        if not indices:
            return
        record = self.proxy.data(indices[0], Qt.ItemDataRole.UserRole)
        if not isinstance(record, FindingRow):
            return
        self._active_finding = record
        self.quarantine_button.setEnabled(bool(record.sha256) and not record.suppressed and not self._action_busy)
        self.ignore_button.setEnabled(bool(record.sha256) and not record.suppressed and not self._action_busy)
        self.process_button.setEnabled(record.target.startswith("process_") and not self._action_busy)
        self.autorun_button.setEnabled("persistence" in record.engines and not self._action_busy)
        self.detail_title.setText(f"{record.threat_type}   ·   {record.severity.upper()}")
        try:
            signals = self.repository.evidence(record.id)
        except sqlite3.Error as exc:
            self.detail.setPlainText(f"Error al leer evidencias: {type(exc).__name__}")
            return
        output = [
            f"OBJETIVO: {record.target}",
            f"RIESGO: {record.score}/100 · CONFIANZA HEURÍSTICA: {record.confidence}/100",
            f"MOTORES: {', '.join(record.engines)}",
            f"SHA-256: {record.sha256 or 'No disponible'}",
            f"ESTADO: {'Excepción autorizada' if record.suppressed else 'Requiere revisión'}",
            "", "MOTIVO:", record.reason, "", "EVIDENCIA TÉCNICA:",
        ]
        for signal in signals:
            output.extend([
                f"• {signal['engine']} [{signal['rule_id'] or 'sin regla'}]",
                f"  {signal['reason']}",
                f"  Datos: {json.dumps(signal['details'], ensure_ascii=False, default=str)[:2400]}",
            ])
        output.extend([
            "", "RECOMENDACIÓN:",
            "No ejecutar el objeto. Verificar origen y firma, corroborar con Defender "
            "y preservar evidencias antes de decidir cualquier reparación.",
            *guidance_for(record.threat_type, record.severity),
            "Las acciones requieren confirmación. No se permite actuar sobre objetos protegidos.",
        ])
        self.detail.setPlainText("\n".join(output))

    def _render_investigation(self, report: dict) -> None:
        """Render only actual correlations and explicit evidence limitations."""
        links = report.get("links", [])
        lines = ["INVESTIGACIÓN DE INCIDENTES · BASADA EN EVIDENCIAS", ""]
        if not links:
            lines.extend(["No hay vínculos directos entre múltiples objetivos.",
                          "Esto no demuestra ausencia de malware o persistencia.", ""])
        else:
            lines.append(f"RELACIONES IDENTIFICADAS: {len(links)}")
            for link in links[:100]:
                lines.extend([
                    f"• {link.get('executable_path', '')}",
                    f"  {link.get('left_target', '')}  ↔  {link.get('right_target', '')}",
                    f"  {link.get('relationship', '')}", "",
                ])
        lines.append("PRIORIDADES DE INVESTIGACIÓN:")
        for item in report.get("investigation_priorities", []):
            lines.append("• " + str(item))
        lines.extend(["", "LIMITACIONES:"])
        for item in report.get("limitations", []):
            lines.append("• " + str(item))
        self.investigation_text.setPlainText("\n".join(lines))

    def refresh_history(self) -> None:
        """Reload newest sessions, with read-only bounded queries."""
        if not hasattr(self, "history_table"):
            return
        try:
            sessions = self.repository.sessions()
        except (sqlite3.Error, OSError):
            return
        self.history_table.setRowCount(len(sessions))
        if sessions:
            latest = sessions[0]
            state = {
                "completed": "Finalizado (revisar cobertura)",
                "cancelled": "Cancelado · cobertura parcial",
                "failed": "Falló · diagnóstico no concluyente",
                "running": "Interrumpido o todavía en curso",
            }.get(latest.status, latest.status)
            self.home_status.setText(f"Último análisis: {state}")
            self.home_last_scan.setText(
                f"{latest.started[:19].replace('T', ' ')} · "
                f"{latest.scanned:,} archivos · {latest.finding_files} objetivos con hallazgos · "
                f"{latest.errors} errores".replace(",", ".")
            )
        else:
            self.home_status.setText("Todavía no se ha evaluado este equipo.")
            self.home_last_scan.setText(
                "Inicia un análisis; no se ha confirmado la seguridad del sistema."
            )
        for row_index, record in enumerate(sessions):
            try:
                duration = (format_duration(
                    (datetime.fromisoformat(record.finished)
                     - datetime.fromisoformat(record.started)).total_seconds()
                ) if record.finished else "En curso")
            except ValueError:
                duration = "No disponible"
            items = (
                record.started[:19].replace("T", " "), duration, record.status,
                str(record.scanned), str(record.finding_files),
                str(record.errors), record.id,
            )
            for column, value in enumerate(items):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.history_table.setItem(row_index, column, item)

    def show_historical_performance(self) -> None:
        """Inspect saved engine performance without re-running any scan."""
        index = self.history_table.currentRow()
        record = self.history_table.item(index, 6) if index >= 0 else None
        if record is None:
            QMessageBox.information(
                self, "Rendimiento", "Selecciona primero un análisis del historial."
            )
            return
        try:
            metrics = SQLiteStore(
                self.config.database_path
            ).get_engine_metrics(record.text())
        except (sqlite3.Error, OSError):
            QMessageBox.warning(
                self, "Rendimiento", "No se pudo consultar la medición almacenada."
            )
            return
        if not metrics:
            QMessageBox.information(
                self, "Rendimiento", "Esta sesión no tiene métricas por motor."
            )
            return
        self._open_engine_metrics({
            str(item["engine"]): item for item in metrics
        })

    def open_historical_scan(self, index: QModelIndex) -> None:
        """Inspect one previous session without re-running any detection."""
        item = self.history_table.item(index.row(), 6)
        if not item:
            return
        session_id = item.text()
        try:
            rows = self.repository.findings(session_id)
        except sqlite3.Error as exc:
            QMessageBox.warning(self, "Historial", f"No se pudo leer: {type(exc).__name__}")
            return
        self._view_mode = "historical"
        self._display_session_id = session_id
        self._show_rows(rows)
        self.results_caption.setText(f"Historial · {session_id[:12]} · {len(rows)} hallazgos visibles")
        self._switch_page(2)

    def _setup_quarantine(self) -> None:
        """Display durable quarantine and reversible user autorun records."""
        page, column = vertical_page()
        column.addWidget(label("RESPUESTA CONTROLADA", "Eyebrow"))
        column.addWidget(label("Cuarentena y recuperación", "Title"))
        column.addWidget(label(
            "La cuarentena solo admite archivos comprobados en el mismo volumen, "
            "fuera de rutas protegidas. Recuperar un archivo puede reactivar malware."))
        self.quarantine_table = QTableWidget(0, 5)
        self.quarantine_table.setHorizontalHeaderLabels([
            "ID", "Archivo original", "SHA-256", "Tamaño", "Estado",
        ])
        self.quarantine_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.quarantine_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.quarantine_table.horizontalHeader().setStretchLastSection(True)
        column.addWidget(self.quarantine_table, 1)
        buttons = QHBoxLayout()
        for title, handler in (("Restaurar seleccionado", self.request_restore),
                               ("Eliminar de cuarentena", self.request_delete),
                               ("Actualizar", self.refresh_quarantine)):
            button = QPushButton(title)
            button.clicked.connect(handler)
            buttons.addWidget(button)
        column.addLayout(buttons)
        column.addWidget(label("ENTRADAS RUN/ RUNONCE HKCU DESACTIVADAS", "Eyebrow"))
        self.autorun_table = QTableWidget(0, 4)
        self.autorun_table.setHorizontalHeaderLabels(["ID", "Registro", "Valor", "Estado"])
        self.autorun_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.autorun_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.autorun_table.horizontalHeader().setStretchLastSection(True)
        column.addWidget(self.autorun_table, 1)
        restore_autorun = QPushButton("Restaurar entrada HKCU seleccionada")
        restore_autorun.clicked.connect(self.request_restore_autorun)
        column.addWidget(restore_autorun, alignment=Qt.AlignmentFlag.AlignLeft)
        self.pages.removeWidget(self.pages.widget(6))
        self.pages.insertWidget(6, page)

    def refresh_quarantine(self) -> None:
        """Read metadata only; never load suspicious file content into Qt."""
        if not hasattr(self, "quarantine_table"):
            return
        try:
            items = self.repository.quarantine_items()
            autoruns = self.repository.disabled_autoruns()
        except (sqlite3.Error, OSError) as exc:
            self._log("WARN", f"No se pudo consultar la cuarentena: {type(exc).__name__}")
            return
        self.quarantine_table.setRowCount(len(items))
        for i, record in enumerate(items):
            for j, value in enumerate((record["id"], record["original_path"],
                                      record["sha256"], str(record["size"]), record["status"])):
                self.quarantine_table.setItem(i, j, QTableWidgetItem(str(value)))
        self.autorun_table.setRowCount(len(autoruns))
        for i, record in enumerate(autoruns):
            for j, value in enumerate((record["id"], record["key_path"],
                                      record["value_name"], record["status"])):
                self.autorun_table.setItem(i, j, QTableWidgetItem(str(value)))

    def _confirm_phrase(self, phrase: str, explanation: str, *, destructive: bool = False) -> bool:
        """Require two distinct UI approvals for any destructive operation."""
        if self._action_busy or self.controller.running:
            QMessageBox.warning(self, "No disponible", "Termina el escaneo o la acción actual primero.")
            return False
        result = QMessageBox.warning(
            self, "Confirmar acción", explanation + "\n\n¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return False
        answer, ok = QInputDialog.getText(self, "Confirmación explícita", f"Escribe exactamente: {phrase}")
        return ok and answer == phrase

    def _run_action(self, label_text: str, operation) -> None:
        """Execute filesystem/registry/report operations off the Qt main thread."""
        if self._action_busy or self.controller.running:
            return
        self._action_busy = True
        for button in (self.quarantine_button, self.ignore_button,
                       self.process_button, self.autorun_button):
            button.setEnabled(False)
        def job():
            try:
                operation()
            except Exception as exc:
                self._action_queue.put((False, f"{label_text}: {type(exc).__name__}: {exc}"))
            else:
                self._action_queue.put((True, f"{label_text}: completado"))
        threading.Thread(target=job, name="oneguard-response", daemon=False).start()

    def _drain_action_queue(self) -> None:
        """Apply worker results from the main thread and refresh durable status."""
        try:
            while True:
                success, description = self._action_queue.get_nowait()
                self._action_busy = False
                self._log("OK" if success else "ERROR", description)
                QMessageBox.information(self, "Respuesta completada", description) if success else \
                    QMessageBox.warning(self, "Acción no aplicada", description)
                self.refresh_quarantine()
                display = self._display_session_id
                if display:
                    try:
                        self._show_rows(self.repository.findings(display))
                    except (sqlite3.Error, OSError):
                        pass
        except Empty:
            pass

    def request_quarantine(self) -> None:
        """Offer quarantine only for a selected hash-bearing real file finding."""
        record = self._active_finding
        if not record or not record.sha256:
            return
        if not self._confirm_phrase("CUARENTENA", f"Mover a cuarentena el archivo:\n{record.target}\n"
                                    "Se verificará el hash y se bloquearán rutas protegidas."):
            return
        self._run_action("Cuarentena", lambda: QuarantineService(
            SQLiteStore(self.config.database_path)).quarantine(record.id, confirmation="CUARENTENA"))

    def request_ignore(self) -> None:
        """Suppress only a confirmed SHA-256 and keep original evidence for review."""
        record = self._active_finding
        if not record or not record.sha256:
            return
        if not self._confirm_phrase("IGNORAR HASH", f"Marcar como excepción este SHA-256:\n{record.sha256}"):
            return
        reason, ok = QInputDialog.getText(self, "Motivo de excepción", "¿Por qué confías en el archivo?")
        if not ok or not reason.strip():
            return
        self._run_action("Excepción de hash", lambda: SQLiteStore(
            self.config.database_path).add_whitelist_entry(record.id, reason, confirmation="IGNORAR HASH"))

    def request_process_termination(self) -> None:
        """Confirm termination of the exact process instance observed by the engine."""
        record = self._active_finding
        if not record or not record.target.startswith("process_"):
            return
        if not self._confirm_phrase("FINALIZAR PROCESO", f"Terminar proceso identificado en:\n{record.target}"):
            return
        self._run_action("Finalizar proceso", lambda: ProcessResponse(
            SQLiteStore(self.config.database_path)).terminate_finding(
                record.id, confirmation="FINALIZAR PROCESO"))

    def request_disable_autorun(self) -> None:
        """Confirm narrow reversible removal of a verified HKCU Run entry."""
        record = self._active_finding
        if not record or "persistence" not in record.engines:
            return
        if not self._confirm_phrase("DESACTIVAR INICIO", f"Deshabilitar un autorun HKCU investigado:\n{record.target}"):
            return
        self._run_action("Desactivar HKCU Run", lambda: PersistenceResponse(
            SQLiteStore(self.config.database_path)).disable_hkcu_run(
                record.id, confirmation="DESACTIVAR INICIO"))

    def _selected_id(self, table: QTableWidget) -> str | None:
        """Read only the selected record identifier, never interpret a file path."""
        index = table.currentRow()
        item = table.item(index, 0) if index >= 0 else None
        return item.text() if item else None

    def request_restore(self) -> None:
        """Restore the selected isolated item after explicit confirmation."""
        item_id = self._selected_id(self.quarantine_table)
        if item_id and self._confirm_phrase("RESTAURAR", "Restaurar el archivo puede reactivar malware. ¿Fue un falso positivo?"):
            self._run_action("Restaurar archivo", lambda: QuarantineService(
                SQLiteStore(self.config.database_path)).restore(item_id, confirmation="RESTAURAR"))

    def request_delete(self) -> None:
        """Double-confirm a permanent deletion restricted to the vault."""
        item_id = self._selected_id(self.quarantine_table)
        if item_id and self._confirm_phrase("ELIMINAR DEFINITIVAMENTE",
                                            "Eliminar permanentemente el objeto seleccionado de cuarentena.",
                                            destructive=True):
            self._run_action("Eliminar objeto aislado", lambda: QuarantineService(
                SQLiteStore(self.config.database_path)).delete(
                    item_id, confirmation="ELIMINAR DEFINITIVAMENTE"))

    def request_restore_autorun(self) -> None:
        """Restore a disabled user startup entry without overwriting any new entry."""
        item_id = self._selected_id(self.autorun_table)
        if item_id and self._confirm_phrase("RESTAURAR INICIO", "Esto puede permitir que el programa vuelva a iniciarse con Windows."):
            self._run_action("Restaurar Run HKCU", lambda: PersistenceResponse(
                SQLiteStore(self.config.database_path)).restore_hkcu_run(
                    item_id, confirmation="RESTAURAR INICIO"))

    def export_report(self, kind: str) -> None:
        """Generate a local report for the session currently displayed."""
        session_id = self._display_session_id
        if not session_id or self._action_busy or self.controller.running:
            QMessageBox.warning(self, "Exportar", "Abre una sesión terminada y espera a finalizar otras operaciones.")
            return
        extension = "html" if kind == "html" else "csv"
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Guardar informe local", f"OneGuard-{session_id[:12]}.{extension}",
            "Informe HTML (*.html)" if kind == "html" else "Tabla CSV (*.csv)",
        )
        if not file_name:
            return
        destination = Path(file_name)
        if destination.suffix.casefold() != f".{extension}":
            destination = destination.with_suffix(f".{extension}")
        if destination.exists():
            QMessageBox.warning(self, "Exportar", "El informe ya existe y no se sobrescribirá.")
            return
        self._run_action(f"Exportar {extension.upper()}", lambda: (
            ReportService(SQLiteStore(self.config.database_path)).export_html(session_id, destination)
            if kind == "html" else
            ReportService(SQLiteStore(self.config.database_path)).export_csv(session_id, destination)
        ))

    def closeEvent(self, event) -> None:  # noqa: N802
        """Prevent silently killing an active scan or detaching worker threads."""
        if self.controller.running:
            response = QMessageBox.question(
                self, "Análisis activo", "Hay un análisis en curso. ¿Solicitar cancelación?\n"
                "Espera a que terminen los trabajos activos antes de cerrar.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if response == QMessageBox.StandardButton.Yes:
                self.controller.cancel()
                self._log("WARN", "Cancelación solicitada antes de cerrar")
            event.ignore()
        elif self._action_busy:
            QMessageBox.warning(self, "Acción en curso", "Finaliza la operación de respuesta antes de cerrar.")
            event.ignore()
        else:
            event.accept()
