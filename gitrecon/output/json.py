"""
Gestion de l'export JSON des résultats GitRecon.

Ce module transforme les modèles internes de GitRecon en structures
sérialisables et écrit les rapports JSON dans le dossier ``reports``.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from gitrecon.models.analysis import RepositoryAnalysis
from gitrecon.models.repository import RepositoryInfo
from gitrecon.models.security import (
    SecurityAnalysis,
    SecurityFinding,
    WorkflowInfo,
    WorkflowPermission,
)

REPORTS_DIRECTORY = Path("reports")


def serialize_repository(
    repository: RepositoryInfo,
) -> dict[str, Any]:
    """
    Sérialise les informations générales d'un dépôt.
    """

    return {
        "name": repository.name,
        "full_name": repository.full_name,
        "owner": repository.owner,
        "description": repository.description,
        "private": repository.private,
        "fork": repository.fork,
        "archived": repository.archived,
        "default_branch": repository.default_branch,
        "language": repository.language,
        "stars": repository.stars,
        "forks": repository.forks,
        "open_issues": repository.open_issues,
        "created_at": repository.created_at,
        "updated_at": repository.updated_at,
        "pushed_at": repository.pushed_at,
    }


def serialize_analysis(
    analysis: RepositoryAnalysis,
) -> dict[str, Any]:
    """
    Sérialise l'analyse générale du dépôt.
    """

    return {
        "languages": [
            {
                "name": language.name,
                "bytes": language.bytes,
                "percentage": language.percentage,
            }
            for language in analysis.languages
        ],
        "contributors_count": analysis.contributors_count,
        "branches_count": analysis.branches_count,
        "releases_count": analysis.releases_count,
        "warnings": list(analysis.warnings),
    }


def serialize_permission(
    permission: WorkflowPermission,
) -> dict[str, Any]:
    """
    Sérialise une permission GitHub Actions.
    """

    return {
        "scope": permission.scope,
        "access": permission.access,
        "level": permission.level.value,
        "job": permission.job,
    }


def serialize_finding(
    finding: SecurityFinding,
) -> dict[str, Any]:
    """
    Sérialise un finding de sécurité.
    """

    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "workflow": finding.workflow,
        "path": finding.path,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
    }


def serialize_workflow(
    workflow: WorkflowInfo,
) -> dict[str, Any]:
    """
    Sérialise un workflow GitHub Actions.
    """

    return {
        "name": workflow.name,
        "path": workflow.path,
        "state": workflow.state,
        "content_available": workflow.content_available,
        "actions": list(workflow.actions),
        "uses": list(workflow.uses),
        "permissions": [
            serialize_permission(permission) for permission in workflow.permissions
        ],
        "findings": [serialize_finding(finding) for finding in workflow.findings],
    }


def serialize_workflow_detection(
    detection,
) -> dict[str, Any]:
    """
    Sérialise un résultat de détection de workflows.
    """

    return {
        "detected": detection.detected,
        "workflows": [
            {
                "name": workflow.name,
                "path": workflow.path,
            }
            for workflow in detection.workflows
        ],
    }


def serialize_security(
    security: SecurityAnalysis,
) -> dict[str, Any]:
    """
    Sérialise l'analyse de sécurité du dépôt.
    """

    return {
        "security_policy": asdict(security.security_policy),
        "license": asdict(security.license),
        "code_of_conduct": asdict(security.code_of_conduct),
        "contributing_guide": asdict(security.contributing_guide),
        "dependabot": asdict(security.dependabot),
        "github_actions": {
            "present": security.github_actions.present,
            "workflows_count": (security.github_actions.workflows_count),
            "workflows": [
                serialize_workflow(workflow)
                for workflow in security.github_actions.workflows
            ],
        },
        "automation": {
            "codeql": serialize_workflow_detection(security.automation.codeql),
            "zizmor": serialize_workflow_detection(security.automation.zizmor),
            "dependency_review": serialize_workflow_detection(
                security.automation.dependency_review
            ),
            "dependency_tools": serialize_workflow_detection(
                security.automation.dependency_tools
            ),
            "tests": serialize_workflow_detection(security.automation.tests),
            "releases": serialize_workflow_detection(security.automation.releases),
        },
        "workflow_security": {
            "total": security.workflow_security.total,
            "critical": security.workflow_security.critical,
            "high": security.workflow_security.high,
            "medium": security.workflow_security.medium,
            "low": security.workflow_security.low,
            "info": security.workflow_security.info,
            "findings": [
                serialize_finding(finding)
                for finding in security.workflow_security.findings
            ],
        },
        "warnings": list(security.warnings),
    }


def build_json_report(
    repository: RepositoryInfo,
    analysis: RepositoryAnalysis,
    security: SecurityAnalysis,
) -> dict[str, Any]:
    """
    Construit le rapport JSON complet.
    """

    return {
        "repository": serialize_repository(repository),
        "analysis": serialize_analysis(analysis),
        "security": serialize_security(security),
    }


def render_json_report(
    repository: RepositoryInfo,
    analysis: RepositoryAnalysis,
    security: SecurityAnalysis,
    *,
    indent: int = 2,
) -> str:
    """
    Génère la représentation JSON du rapport.
    """

    report = build_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
    )

    return json.dumps(
        report,
        indent=indent,
        ensure_ascii=False,
    )


def build_default_filename(
    repository: RepositoryInfo,
) -> str:
    """
    Construit le nom de fichier JSON utilisé par défaut.

    Exemple :

        pallets/flask

    devient :

        pallets-flask.json
    """

    owner = repository.owner.strip()
    name = repository.name.strip()

    return f"{owner}-{name}.json"


def normalize_output_filename(
    filename: str | Path,
) -> str:
    """
    Normalise le nom du fichier de sortie.

    Le rapport reste toujours enregistré dans le dossier ``reports``.
    Les éventuels composants de chemin fournis par l'utilisateur sont
    supprimés afin d'éviter de sortir du dossier d'export.
    """

    output_name = Path(filename).name

    if not output_name:
        raise ValueError("Le nom du fichier JSON ne peut pas être vide.")

    output_path = Path(output_name)

    if output_path.suffix.lower() != ".json":
        output_path = output_path.with_suffix(".json")

    return output_path.name


def get_report_path(
    repository: RepositoryInfo,
    filename: str | Path | None = None,
) -> Path:
    """
    Construit le chemin final du rapport JSON.
    """

    if filename is None:
        output_name = build_default_filename(repository)
    else:
        output_name = normalize_output_filename(filename)

    return REPORTS_DIRECTORY / output_name


def write_json_report(
    repository: RepositoryInfo,
    analysis: RepositoryAnalysis,
    security: SecurityAnalysis,
    filename: str | Path | None = None,
    *,
    indent: int = 2,
) -> Path:
    """
    Écrit le rapport JSON dans le dossier ``reports``.

    Le dossier est créé automatiquement lorsqu'il n'existe pas.

    Args:
        repository:
            Informations générales du dépôt.

        analysis:
            Analyse générale du dépôt.

        security:
            Analyse de sécurité du dépôt.

        filename:
            Nom optionnel du fichier JSON.

        indent:
            Niveau d'indentation du JSON.

    Returns:
        Chemin du fichier créé.
    """

    REPORTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = get_report_path(
        repository=repository,
        filename=filename,
    )

    content = render_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
        indent=indent,
    )

    output_path.write_text(
        content + "\n",
        encoding="utf-8",
    )

    return output_path
