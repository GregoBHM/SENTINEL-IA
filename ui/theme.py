"""OneGuard design tokens and compact PySide6 dark theme."""
from __future__ import annotations

COLORS = {
    "base": "#0B111A", "surface": "#111B27", "raised": "#182534",
    "line": "#263647", "muted": "#93A6B8", "text": "#E9F1F7",
    "accent": "#34CFD0", "blue": "#56A9E6", "danger": "#F17978",
    "amber": "#E8B45C", "green": "#63D2A4",
}

STYLESHEET = """
/* Text widgets must not paint an opaque rectangle over the panel surface. */
QWidget { color: #E9F1F7; font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px; }
QMainWindow, QDialog, QWidget#RootSurface, QWidget#PageSurface, QStackedWidget { background: #0B111A; }
QLabel { background: transparent; border: none; padding: 0; }
QScrollArea { background: #0B111A; border: none; }
QFrame#Sidebar { background: #101925; border-right: 1px solid #263647; }
QFrame#Panel, QFrame#Metric, QFrame#WizardPanel, QFrame#Insight { background: #141F2D; border: 1px solid #263647; border-radius: 13px; }
QFrame#EngineDeck {
    background: #111F2F;
    border: 1px solid #315266;
    border-radius: 14px;
}
QTableWidget#EngineTable {
    background: #0D1926;
    border: 1px solid #253D50;
    border-radius: 8px;
    selection-background-color: #19394D;
}
QTableWidget#EngineTable::item {
    padding: 5px 7px;
}
QFrame#Hero { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #173448, stop:0.5 #123041, stop:1 #172331); border: 1px solid #2A5062; border-radius: 17px; }
QLabel#Title { font-size: 29px; font-weight: 700; letter-spacing: 0px; }
QLabel#Heading { font-size: 21px; font-weight: 700; }
QLabel#SectionHeading { font-size: 15px; font-weight: 650; }
QLabel#Muted { color: #93A6B8; }
QLabel#Eyebrow { color: #54D2D1; font-size: 10px; font-weight: 700; letter-spacing: 0.4px; }
QLabel#MetricNumber { font-size: 29px; font-weight: 750; }
QLabel#DangerText { color: #F17978; }
QLabel#WarningText { color: #E8B45C; }
QLabel#SuccessText { color: #63D2A4; }
QLabel#Brand { font-size: 17px; font-weight: 800; }
QLabel#FailureHint { color: #F5BC77; font-size: 12px; }
QLabel#SmallHelp { color: #93A6B8; font-size: 12px; }
QFrame#Metric { min-height: 74px; }
QPlainTextEdit#EventConsole { font-family: 'Consolas', monospace; font-size: 12px; }
QPushButton { background: #1B2A3A; color: #DDEBF1; border: 1px solid #2D4256; padding: 10px 14px; border-radius: 8px; font-weight: 600; }
QPushButton:hover { background: #263B4F; border-color: #42647B; }
QPushButton:pressed { background: #203244; }
QPushButton:disabled { color: #718395; background: #182331; border-color: #283544; }
QPushButton#Primary { background: #39CED0; color: #08202A; border: 1px solid #39CED0; }
QPushButton#Primary:hover { background: #6DE0DF; }
QPushButton#Nav { border: 0; border-left: 3px solid transparent; border-radius: 7px; padding: 11px 13px; text-align: left; background: transparent; color: #9CB1C3; font-weight: 600; }
QPushButton#Nav:hover { color: #E5F4FB; background: #1A2A38; }
QPushButton#Nav[active="true"] { background: #1B3240; border-left-color: #34CFD0; color: #F0FBFF; }
QPushButton#Danger { color: #FFAAA4; border-color: #713E49; background: #2B202C; }
QPushButton#Danger:hover { background: #49303B; }
QCheckBox { spacing: 12px; padding: 7px 4px; }
QCheckBox::indicator { width: 17px; height: 17px; }
QCheckBox::indicator:unchecked { border: 1px solid #62768A; background: #172533; border-radius: 4px; }
QCheckBox::indicator:checked { border: 1px solid #3BCFD0; background: #3BCFD0; border-radius: 4px; }
QRadioButton { spacing: 10px; padding: 7px 5px; }
QRadioButton::indicator { width: 17px; height: 17px; }
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QListWidget { background: #101B27; border: 1px solid #304357; color: #E9F1F7; border-radius: 8px; padding: 9px; selection-background-color: #276378; }
QComboBox QAbstractItemView { background: #172536; selection-background-color: #1D4A5E; }
QProgressBar { border-radius: 5px; border: 0; background: #253746; min-height: 9px; max-height: 9px; color: transparent; }
QProgressBar::chunk { border-radius: 5px; background: #35CDD2; }
QTableView, QTableWidget { background: #111B28; border: 1px solid #273B4A; border-radius: 9px; gridline-color: #223141; alternate-background-color: #152331; selection-background-color: #1F4A5B; selection-color: white; }
QHeaderView::section { background: #1A2A3B; color: #96ADBF; border: 0; border-bottom: 1px solid #355066; padding: 11px 9px; font-weight: 650; }
QTableView::item, QTableWidget::item { padding: 7px; }
QScrollBar:vertical { background: #101925; width: 9px; }
QScrollBar::handle:vertical { background: #345067; min-height: 25px; border-radius: 4px; }
QScrollBar:horizontal { background: #101925; height: 9px; }
QScrollBar::handle:horizontal { background: #345067; border-radius: 4px; }
QSplitter::handle { background: #263647; width: 2px; }
QToolTip { background: #22394B; color: #FFFFFF; border: 1px solid #4C6980; padding: 6px; }
"""


def severity_color(severity: str) -> str:
    """Return accessible semantic foreground for one severity tier."""
    return {
        "critical": COLORS["danger"], "high": "#FF9F83",
        "medium": COLORS["amber"], "low": COLORS["blue"],
        "info": COLORS["muted"],
    }.get(severity.lower(), COLORS["muted"])
