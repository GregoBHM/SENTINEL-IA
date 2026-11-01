"""Three-stage, opt-in permission wizard for initiating read-only scans."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup, QCheckBox, QDialog, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QListWidget, QMessageBox, QPushButton, QRadioButton,
    QStackedWidget, QVBoxLayout, QWidget,
)

from ui.profiles import ScanPlan, ScanSelection, build_plan


def _paragraph(text: str) -> QLabel:
    """Create an accessible line-wrapped explanatory label."""
    label = QLabel(text)
    label.setWordWrap(True)
    label.setObjectName("Muted")
    return label


class ConsentWizard(QDialog):
    """Explain collection, gather granular consent, then validate scan scope."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sentinel OneGuard · Configurar análisis")
        self.setMinimumSize(720, 600)
        self.setModal(True)
        self.plan: ScanPlan | None = None
        self.steps = QStackedWidget()
        self.steps.addWidget(self._introduction())
        self.steps.addWidget(self._permissions())
        self.steps.addWidget(self._scope())
        self.back = QPushButton("Anterior")
        self.forward = QPushButton("Continuar")
        self.forward.setObjectName("Primary")
        self.back.clicked.connect(self._previous)
        self.forward.clicked.connect(self._next)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 26, 30, 26)
        layout.setSpacing(18)
        self.step_label = QLabel("PASO 1 DE 3   /   QUÉ SE ANALIZARÁ")
        self.step_label.setObjectName("Eyebrow")
        layout.addWidget(self.step_label)
        layout.addWidget(self.steps, 1)
        actions = QHBoxLayout()
        actions.addStretch()
        actions.addWidget(self.back)
        actions.addWidget(self.forward)
        layout.addLayout(actions)
        self._refresh()

    def _introduction(self) -> QWidget:
        """Describe collection, privacy and exclusions before consent."""
        page = QWidget()
        column = QVBoxLayout(page)
        column.setSpacing(18)
        title = QLabel("Analizar sin alterar tu equipo")
        title.setObjectName("Title")
        column.addWidget(title)
        column.addWidget(_paragraph(
            "OneGuard examina archivos y, solo si lo autorizas, procesos activos y "
            "mecanismos de inicio automático. Busca indicios de malware y explica "
            "cada hallazgo; no ejecuta muestras ni intenta eliminar amenazas."))
        for title_text, description in (
            ("01   ARCHIVOS", "Lectura de contenido, metadatos y hashes SHA-256."),
            ("02   PROCESOS", "Ruta de ejecutables, estado y conexiones resumidas; no lee contraseñas."),
            ("03   PERSISTENCIA", "Entradas de inicio, servicios y tareas programadas; sin modificarlos."),
            ("04   REPUTACIÓN", "Opcional: enviar únicamente SHA-256 a proveedores externos."),
        ):
            card = QFrame()
            card.setObjectName("WizardPanel")
            inside = QVBoxLayout(card)
            heading = QLabel(title_text)
            heading.setObjectName("SectionHeading")
            inside.addWidget(heading)
            inside.addWidget(_paragraph(description))
            column.addWidget(card)
        column.addWidget(_paragraph(
            "Aviso: resultados incompletos, sin hallazgos o un archivo firmado no "
            "demuestran que Windows esté limpio. La mitigación llegará en la Fase 5."))
        column.addStretch()
        return page

    def _permissions(self) -> QWidget:
        """Collect separate opt-in permissions with no prechecked online transfer."""
        page = QWidget()
        column = QVBoxLayout(page)
        column.setSpacing(11)
        title = QLabel("Elige qué puede leer OneGuard")
        title.setObjectName("Title")
        column.addWidget(title)
        column.addWidget(_paragraph("Confirma cada permiso. Puedes cancelar en cualquier momento."))
        self.files = QCheckBox("Autorizo leer archivos de las ubicaciones elegidas (obligatorio)")
        self.processes = QCheckBox("Autorizo inspeccionar procesos y datos generales de red")
        self.persistence = QCheckBox("Autorizo revisar registro, servicios, Startup y tareas")
        self.online = QCheckBox("Autorizo consultar hashes SHA-256 en línea (opcional)")
        for checkbox in (self.files, self.processes, self.persistence, self.online):
            column.addWidget(checkbox)
            checkbox.toggled.connect(self._refresh)
        column.addSpacing(20)
        column.addWidget(_paragraph(
            "Privacidad: no se enviarán archivos, nombres de cuentas, contraseñas, "
            "cookies ni rutas completas a servicios de reputación. Las claves API "
            "se introducirán en Ajustes y permanecerán solo en memoria."))
        column.addWidget(_paragraph(
            "El análisis del sistema puede encontrar zonas bloqueadas o resultados "
            "parciales. Este prototipo no equivale a un antivirus certificado."))
        column.addStretch()
        return page

    def _scope(self) -> QWidget:
        """Choose quick, full or custom file coverage and optional paths."""
        page = QWidget()
        column = QVBoxLayout(page)
        title = QLabel("Selecciona el alcance")
        title.setObjectName("Title")
        column.addWidget(title)
        self.quick = QRadioButton("Rápido · Descargas, escritorio y ubicaciones comunes")
        self.full = QRadioButton("Completo · Unidades locales fijas")
        self.custom = QRadioButton("Personalizado · Solo archivos y carpetas seleccionados")
        self.quick.setChecked(True)
        self.profile_group = QButtonGroup(page)
        for option in (self.quick, self.full, self.custom):
            self.profile_group.addButton(option)
            column.addWidget(option)
            option.toggled.connect(self._refresh)
        column.addSpacing(12)
        column.addWidget(_paragraph("Rutas personalizadas (solo se usan en modo Personalizado):"))
        self.path_list = QListWidget()
        self.path_list.setMinimumHeight(150)
        column.addWidget(self.path_list, 1)
        add_row = QHBoxLayout()
        self.add_folder = QPushButton("Añadir carpeta")
        self.add_file = QPushButton("Añadir archivo")
        self.remove_path = QPushButton("Quitar seleccionado")
        self.add_folder.clicked.connect(self._choose_folder)
        self.add_file.clicked.connect(self._choose_file)
        self.remove_path.clicked.connect(self._remove_path)
        for button in (self.add_folder, self.add_file, self.remove_path):
            add_row.addWidget(button)
        add_row.addStretch()
        column.addLayout(add_row)
        column.addWidget(_paragraph(
            "El análisis completo puede tardar y encontrar archivos inaccesibles. "
            "El progreso global será indeterminado mientras se descubren archivos."))
        return page

    def _choose_folder(self) -> None:
        """Add an explicitly selected folder; never silently inspect it now."""
        directory = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta")
        if directory:
            self._add_path(directory)

    def _choose_file(self) -> None:
        """Add an explicitly selected file for analysis."""
        name, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo")
        if name:
            self._add_path(name)

    def _add_path(self, path: str) -> None:
        """Avoid duplicate items in the visible custom selection."""
        if not self.path_list.findItems(path, Qt.MatchFlag.MatchExactly):
            self.path_list.addItem(path)
        self._refresh()

    def _remove_path(self) -> None:
        """Remove a selection before any work starts."""
        for item in self.path_list.selectedItems():
            self.path_list.takeItem(self.path_list.row(item))
        self._refresh()

    def _selection(self) -> ScanSelection:
        """Read current checkboxes into a UI-independent immutable value."""
        profile = "custom" if self.custom.isChecked() else "full" if self.full.isChecked() else "quick"
        return ScanSelection(
            profile=profile, read_files=self.files.isChecked(),
            inspect_processes=self.processes.isChecked(),
            inspect_persistence=self.persistence.isChecked(),
            online_hashes=self.online.isChecked(),
            custom_paths=tuple(Path(self.path_list.item(i).text())
                               for i in range(self.path_list.count())),
        )

    def _previous(self) -> None:
        """Navigate to the previous step."""
        self.steps.setCurrentIndex(max(0, self.steps.currentIndex() - 1))
        self._refresh()

    def _next(self) -> None:
        """Proceed only with permissions and a validated scan plan."""
        step = self.steps.currentIndex()
        if step < 2:
            self.steps.setCurrentIndex(step + 1)
            self._refresh()
            return
        try:
            self.plan = build_plan(self._selection())
        except ValueError as exc:
            QMessageBox.warning(self, "Revisa el alcance", str(exc))
            return
        self.accept()

    def _refresh(self) -> None:
        """Apply real step and permission constraints to navigation actions."""
        step = self.steps.currentIndex()
        self.step_label.setText((
            "PASO 1 DE 3   /   INFORMACIÓN",
            "PASO 2 DE 3   /   CONSENTIMIENTO",
            "PASO 3 DE 3   /   ALCANCE",
        )[step])
        self.back.setEnabled(step > 0)
        self.forward.setText("Iniciar análisis" if step == 2 else "Continuar")
        self.forward.setEnabled(step != 1 or self.files.isChecked())
        for control in (getattr(self, "add_folder", None), getattr(self, "add_file", None),
                        getattr(self, "remove_path", None), getattr(self, "path_list", None)):
            if control is not None:
                control.setEnabled(self.custom.isChecked())
