"""Explainable incident hypotheses derived from completed static scan evidence.

Associations are path-based, not proof of a causal chain or initial compromise.
Never manufacture timestamps, stolen data or successful exfiltration claims.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from core.models import AggregatedFinding


def normalize_windows_path(value: str) -> str:
    """Normalize case and separators for Windows-style path correlation."""
    return value.strip().strip('"').replace("/", "\\").lower()


@dataclass(frozen=True, slots=True)
class IncidentLink:
    """Explain a shared executable referenced by two separate findings."""

    executable_path: str
    left_target: str
    right_target: str
    relationship: str


@dataclass(frozen=True, slots=True)
class IncidentReport:
    """Evidence-based associations and recovery guidance without certainty claims."""

    links: tuple[IncidentLink, ...]
    investigation_priorities: tuple[str, ...]
    limitations: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """Serialize the investigation summary without hidden/private metadata."""
        return {
            "links": [vars_ for vars_ in (
                {"executable_path": x.executable_path, "left_target": x.left_target,
                 "right_target": x.right_target, "relationship": x.relationship}
                for x in self.links
            )],
            "investigation_priorities": list(self.investigation_priorities),
            "limitations": list(self.limitations),
        }


class IncidentInvestigator:
    """Connect process/persistence references to existing on-disk file findings."""

    def investigate(self, findings: list[AggregatedFinding]) -> IncidentReport:
        """Build candidate links without assigning an unsupported point of entry."""
        by_executable: dict[str, list[tuple[str, str]]] = {}
        for finding in findings:
            source_paths = set()
            for evidence in finding.evidence:
                raw = evidence.details.get("executable_path")
                if isinstance(raw, str) and raw:
                    source_paths.add(normalize_windows_path(raw))
            if finding.target and not finding.target.startswith(("HKCU\\", "HKLM\\")):
                if Path(finding.target).suffix.lower() in {".exe", ".dll", ".sys", ".scr"}:
                    source_paths.add(normalize_windows_path(finding.target))
            for path in source_paths:
                by_executable.setdefault(path, []).append((finding.target, finding.threat_type))
        links: list[IncidentLink] = []
        priorities = []
        for path, references in sorted(by_executable.items()):
            distinct_targets = sorted(set(item[0] for item in references))
            if len(distinct_targets) < 2:
                continue
            for other in distinct_targets[1:]:
                links.append(IncidentLink(path, distinct_targets[0], other,
                    "Ambos hallazgos hacen referencia al mismo ejecutable; relación causal no confirmada"))
            priorities.append(f"Verificar origen, firma, hash y persistencia de {path}")
        if not priorities and findings:
            priorities.append("Revisar las evidencias independientes antes de inferir una causa inicial")
        return IncidentReport(
            links=tuple(links[:500]),
            investigation_priorities=tuple(priorities[:100]),
            limitations=(
                "Sin telemetría histórica no puede determinarse con certeza el archivo inicial.",
                "No se confirma robo de cuentas, comunicación C2 ni limpieza completa a partir de heurísticas.",
                "Una revisión profunda requiere registros temporales, estado de Defender y artefactos del sistema.",
            ),
        )
