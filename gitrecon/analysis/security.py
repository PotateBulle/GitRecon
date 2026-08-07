"""
Logique d'analyse des informations de sécurité d'un dépôt GitHub.

Ce module transforme les données brutes collectées depuis l'API GitHub
en structures normalisées utilisables par GitRecon.

Il réalise également une première classification heuristique des
workflows GitHub Actions à partir de leur nom et de leur chemin.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from gitrecon.models.security import (
    GitHubActionsStatus,
    SecurityAnalysis,
    SecurityAutomationAnalysis,
    SecurityFileStatus,
    WorkflowDetection,
    WorkflowInfo,
)


def build_file_status(
    result: tuple[bool, str | None],
) -> SecurityFileStatus:
    """
    Construit l'état normalisé d'un fichier de sécurité.
    """

    present, path = result

    return SecurityFileStatus(
        present=present,
        path=path,
    )


def normalize_workflow(
    workflow: dict[str, Any],
) -> WorkflowInfo:
    """
    Transforme un workflow brut GitHub en modèle interne.

    Args:
        workflow:
            Dictionnaire retourné par l'API GitHub.

    Returns:
        Workflow normalisé.
    """

    name = workflow.get("name")
    path = workflow.get("path")
    state = workflow.get("state")

    return WorkflowInfo(
        name=name if isinstance(name, str) else "Workflow sans nom",
        path=path if isinstance(path, str) else None,
        state=state if isinstance(state, str) else None,
    )


def build_github_actions_status(
    workflows: list[dict[str, Any]],
) -> GitHubActionsStatus:
    """
    Construit l'état normalisé de GitHub Actions.
    """

    normalized_workflows = [normalize_workflow(workflow) for workflow in workflows]

    return GitHubActionsStatus(
        present=bool(normalized_workflows),
        workflows_count=len(normalized_workflows),
        workflows=normalized_workflows,
    )


def workflow_matches(
    workflow: WorkflowInfo,
    keywords: Iterable[str],
) -> bool:
    """
    Vérifie si un workflow correspond à une série de mots-clés.

    La recherche est effectuée dans le nom et le chemin du workflow.

    Args:
        workflow:
            Workflow à analyser.

        keywords:
            Termes associés à une catégorie donnée.

    Returns:
        ``True`` lorsqu'au moins un mot-clé est détecté.
    """

    searchable_content = " ".join(
        value
        for value in (
            workflow.name,
            workflow.path or "",
        )
        if value
    ).lower()

    return any(keyword.lower() in searchable_content for keyword in keywords)


def detect_workflows(
    workflows: list[WorkflowInfo],
    keywords: tuple[str, ...],
) -> WorkflowDetection:
    """
    Recherche les workflows correspondant à une catégorie.

    Args:
        workflows:
            Liste des workflows normalisés.

        keywords:
            Mots-clés utilisés pour la classification.

    Returns:
        Résultat de la détection.
    """

    matches = [
        workflow for workflow in workflows if workflow_matches(workflow, keywords)
    ]

    return WorkflowDetection(
        detected=bool(matches),
        workflows=matches,
    )


def build_security_automation_analysis(
    workflows: list[WorkflowInfo],
) -> SecurityAutomationAnalysis:
    """
    Analyse les workflows GitHub Actions afin d'identifier plusieurs
    catégories liées à la sécurité et au cycle de développement.

    La détection repose actuellement sur le nom et le chemin des
    workflows. Elle constitue donc une heuristique et non une preuve
    de l'utilisation effective d'une action particulière.

    Args:
        workflows:
            Workflows GitHub Actions normalisés.

    Returns:
        Analyse des automatisations détectées.
    """

    codeql = detect_workflows(
        workflows,
        (
            "codeql",
            "code ql",
        ),
    )

    zizmor = detect_workflows(
        workflows,
        ("zizmor",),
    )

    dependency_review = detect_workflows(
        workflows,
        (
            "dependency review",
            "dependency-review",
            "dependency_review",
        ),
    )

    dependency_tools = detect_workflows(
        workflows,
        (
            "dependency",
            "dependencies",
            "dependabot",
        ),
    )

    tests = detect_workflows(
        workflows,
        (
            "test",
            "tests",
            "testing",
            "ci",
            "continuous integration",
            "pytest",
        ),
    )

    releases = detect_workflows(
        workflows,
        (
            "release",
            "publish",
            "publication",
            "deploy",
            "deployment",
        ),
    )

    return SecurityAutomationAnalysis(
        codeql=codeql,
        zizmor=zizmor,
        dependency_review=dependency_review,
        dependency_tools=dependency_tools,
        tests=tests,
        releases=releases,
    )


def build_security_analysis(
    security_policy: tuple[bool, str | None],
    license_file: tuple[bool, str | None],
    code_of_conduct: tuple[bool, str | None],
    contributing_guide: tuple[bool, str | None],
    dependabot: tuple[bool, str | None],
    workflows: list[dict[str, Any]],
    warnings: list[str] | None = None,
) -> SecurityAnalysis:
    """
    Construit l'analyse de sécurité complète d'un dépôt GitHub.
    """

    github_actions = build_github_actions_status(workflows)

    automation = build_security_automation_analysis(github_actions.workflows)

    return SecurityAnalysis(
        security_policy=build_file_status(security_policy),
        license=build_file_status(license_file),
        code_of_conduct=build_file_status(code_of_conduct),
        contributing_guide=build_file_status(contributing_guide),
        dependabot=build_file_status(dependabot),
        github_actions=github_actions,
        automation=automation,
        warnings=warnings or [],
    )
