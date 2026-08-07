"""
Gestion de l'affichage des résultats dans le terminal.

Ce module contient exclusivement la logique de présentation des données.
Il ne réalise aucun appel réseau et ne contient aucune logique métier.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from gitrecon.models.analysis import RepositoryAnalysis
from gitrecon.models.repository import RepositoryInfo
from gitrecon.models.security import (
    FindingSeverity,
    SecurityAnalysis,
    SecurityFileStatus,
    SecurityFinding,
    WorkflowDetection,
    WorkflowInfo,
)

console = Console()


def create_information_table() -> Table:
    """
    Crée une table Rich générique utilisée par GitRecon.

    Returns:
        Table configurée pour l'affichage des informations.
    """

    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    table.add_column(
        "Champ",
        style="bold",
        no_wrap=True,
    )

    table.add_column("Valeur")

    return table


def format_optional_count(value: int | None) -> str:
    """
    Formate une valeur numérique susceptible d'être indisponible.

    Args:
        value:
            Valeur numérique ou ``None``.

    Returns:
        Valeur formatée pour l'affichage.
    """

    if value is None:
        return "Indisponible"

    return f"{value:,}"


def format_security_file_status(
    status: SecurityFileStatus,
) -> str:
    """
    Formate l'état d'un fichier de sécurité ou de gouvernance.

    Args:
        status:
            État du fichier.

    Returns:
        Représentation Rich de l'état du fichier.
    """

    if not status.present:
        return "[red]Missing[/red]"

    if status.path:
        return f"[green]Present[/green] ({status.path})"

    return "[green]Present[/green]"


def format_detection(
    detection: WorkflowDetection,
) -> str:
    """
    Formate le résultat d'une détection de workflow.

    Args:
        detection:
            Résultat de détection.

    Returns:
        État lisible accompagné du nombre de workflows associés.
    """

    if not detection.detected:
        return "[red]Not detected[/red]"

    count = len(detection.workflows)

    return f"[green]Detected[/green] ({count})"


def format_severity(
    severity: FindingSeverity,
) -> str:
    """
    Formate un niveau de sévérité avec une couleur adaptée.

    Args:
        severity:
            Niveau de sévérité du finding.

    Returns:
        Représentation Rich du niveau de sévérité.
    """

    if severity == FindingSeverity.CRITICAL:
        return "[bold red]CRITICAL[/bold red]"

    if severity == FindingSeverity.HIGH:
        return "[red]HIGH[/red]"

    if severity == FindingSeverity.MEDIUM:
        return "[yellow]MEDIUM[/yellow]"

    if severity == FindingSeverity.LOW:
        return "[cyan]LOW[/cyan]"

    return "[dim]INFO[/dim]"


def display_repository(
    repository: RepositoryInfo,
    analysis: RepositoryAnalysis,
    security: SecurityAnalysis,
) -> None:
    """
    Affiche le rapport complet généré par GitRecon.

    Args:
        repository:
            Informations générales du dépôt.

        analysis:
            Analyse générale du dépôt.

        security:
            Analyse de sécurité du dépôt.
    """

    console.print()
    console.rule("[bold]GitRecon — Repository Intelligence")

    display_repository_information(repository)
    display_statistics(repository, analysis)
    display_languages(analysis)
    display_activity(repository)
    display_security(security)
    display_workflow_security(security)
    display_warnings(analysis, security)

    console.print()


def display_repository_information(
    repository: RepositoryInfo,
) -> None:
    """
    Affiche les informations générales du dépôt.
    """

    console.print("\n[bold cyan]Repository[/bold cyan]")

    table = create_information_table()

    visibility = "Private" if repository.private else "Public"

    table.add_row(
        "Repository",
        repository.full_name,
    )

    table.add_row(
        "Description",
        repository.description or "Aucune description",
    )

    table.add_row(
        "Visibility",
        visibility,
    )

    table.add_row(
        "Default branch",
        repository.default_branch,
    )

    table.add_row(
        "Primary language",
        repository.language or "Non déterminé",
    )

    table.add_row(
        "Archived",
        "Yes" if repository.archived else "No",
    )

    table.add_row(
        "Fork",
        "Yes" if repository.fork else "No",
    )

    console.print(table)


def display_statistics(
    repository: RepositoryInfo,
    analysis: RepositoryAnalysis,
) -> None:
    """
    Affiche les principales statistiques du dépôt.
    """

    console.print("\n[bold cyan]Statistics[/bold cyan]")

    table = create_information_table()

    table.add_row(
        "Stars",
        f"{repository.stars:,}",
    )

    table.add_row(
        "Forks",
        f"{repository.forks:,}",
    )

    table.add_row(
        "Open issues",
        f"{repository.open_issues:,}",
    )

    table.add_row(
        "Contributors",
        format_optional_count(analysis.contributors_count),
    )

    table.add_row(
        "Branches",
        format_optional_count(analysis.branches_count),
    )

    table.add_row(
        "Releases",
        format_optional_count(analysis.releases_count),
    )

    console.print(table)


def display_languages(
    analysis: RepositoryAnalysis,
) -> None:
    """
    Affiche la répartition des langages détectés.
    """

    console.print("\n[bold cyan]Languages[/bold cyan]")

    if not analysis.languages:
        console.print("  Aucun langage détecté.")
        return

    table = create_information_table()

    for language in analysis.languages:
        table.add_row(
            language.name,
            f"{language.percentage:.2f} %",
        )

    console.print(table)


def display_activity(
    repository: RepositoryInfo,
) -> None:
    """
    Affiche les principales informations temporelles du dépôt.
    """

    console.print("\n[bold cyan]Activity[/bold cyan]")

    table = create_information_table()

    table.add_row(
        "Created",
        repository.created_at,
    )

    table.add_row(
        "Updated",
        repository.updated_at,
    )

    if repository.pushed_at:
        table.add_row(
            "Last push",
            repository.pushed_at,
        )

    console.print(table)


def display_security(
    security: SecurityAnalysis,
) -> None:
    """
    Affiche les indicateurs de sécurité et de gouvernance.
    """

    console.print("\n[bold cyan]Security[/bold cyan]")

    table = create_information_table()

    table.add_row(
        "Security policy",
        format_security_file_status(security.security_policy),
    )

    table.add_row(
        "License",
        format_security_file_status(security.license),
    )

    table.add_row(
        "Code of Conduct",
        format_security_file_status(security.code_of_conduct),
    )

    table.add_row(
        "Contributing guide",
        format_security_file_status(security.contributing_guide),
    )

    table.add_row(
        "Dependabot config",
        format_security_file_status(security.dependabot),
    )

    if security.github_actions.present:
        actions_status = (
            f"[green]Present[/green] "
            f"({security.github_actions.workflows_count} workflows)"
        )
    else:
        actions_status = "[red]Missing[/red]"

    table.add_row(
        "GitHub Actions",
        actions_status,
    )

    console.print(table)

    display_security_automation(security)
    display_github_actions_workflows(security)


def display_security_automation(
    security: SecurityAnalysis,
) -> None:
    """
    Affiche les automatisations liées à la sécurité.
    """

    if not security.github_actions.present:
        return

    console.print("\n[bold cyan]Security Automation[/bold cyan]")

    table = create_information_table()

    table.add_row(
        "CodeQL",
        format_detection(security.automation.codeql),
    )

    table.add_row(
        "zizmor",
        format_detection(security.automation.zizmor),
    )

    table.add_row(
        "Dependency Review",
        format_detection(security.automation.dependency_review),
    )

    table.add_row(
        "Dependency tooling",
        format_detection(security.automation.dependency_tools),
    )

    table.add_row(
        "Tests / CI",
        format_detection(security.automation.tests),
    )

    table.add_row(
        "Release / Publish",
        format_detection(security.automation.releases),
    )

    console.print(table)


def display_workflow_actions(
    workflow: WorkflowInfo,
) -> None:
    """
    Affiche les actions détectées dans un workflow GitHub Actions.
    """

    if not workflow.content_available:
        console.print("      [yellow]Contenu YAML non disponible[/yellow]")
        return

    if not workflow.actions:
        console.print("      [dim]Aucune action externe détectée[/dim]")
        return

    for action in workflow.actions:
        console.print(f"      [dim]→ {action}[/dim]")


def display_github_actions_workflows(
    security: SecurityAnalysis,
) -> None:
    """
    Affiche les workflows GitHub Actions et leurs actions détectées.
    """

    if not security.github_actions.workflows:
        return

    console.print("\n[bold]GitHub Actions workflows[/bold]")

    for workflow in security.github_actions.workflows:
        console.print(f"  [green]✓[/green] {workflow.name}")

        if workflow.path:
            console.print(f"      [dim]{workflow.path}[/dim]")

        display_workflow_actions(workflow)


def display_workflow_security(
    security: SecurityAnalysis,
) -> None:
    """
    Affiche le résumé et les findings de sécurité des workflows.
    """

    workflow_security = security.workflow_security

    console.print("\n[bold cyan]Workflow Security[/bold cyan]")

    summary_table = create_information_table()

    summary_table.add_row(
        "Findings",
        str(workflow_security.total),
    )

    summary_table.add_row(
        "Critical",
        str(workflow_security.critical),
    )

    summary_table.add_row(
        "High",
        str(workflow_security.high),
    )

    summary_table.add_row(
        "Medium",
        str(workflow_security.medium),
    )

    summary_table.add_row(
        "Low",
        str(workflow_security.low),
    )

    summary_table.add_row(
        "Info",
        str(workflow_security.info),
    )

    console.print(summary_table)

    if not workflow_security.findings:
        console.print("\n  [green]Aucun finding de sécurité détecté.[/green]")
        return

    console.print("\n[bold]Security Findings[/bold]")

    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4,
    }

    findings = sorted(
        workflow_security.findings,
        key=lambda finding: (
            severity_order[finding.severity],
            finding.rule_id,
            finding.workflow or "",
        ),
    )

    for finding in findings:
        display_security_finding(finding)


def display_security_finding(
    finding: SecurityFinding,
) -> None:
    """
    Affiche le détail d'un finding de sécurité.
    """

    console.print()

    console.print(
        f"  {format_severity(finding.severity)} [bold]{finding.rule_id}[/bold]"
    )

    console.print(f"  [bold]{finding.title}[/bold]")

    table = create_information_table()

    if finding.workflow:
        table.add_row(
            "Workflow",
            finding.workflow,
        )

    if finding.path:
        table.add_row(
            "Path",
            finding.path,
        )

    if finding.evidence:
        table.add_row(
            "Evidence",
            finding.evidence,
        )

    table.add_row(
        "Description",
        finding.description,
    )

    if finding.recommendation:
        table.add_row(
            "Recommendation",
            finding.recommendation,
        )

    console.print(table)


def display_warnings(
    analysis: RepositoryAnalysis,
    security: SecurityAnalysis,
) -> None:
    """
    Affiche les avertissements générés pendant le scan.
    """

    warnings = [
        *analysis.warnings,
        *security.warnings,
    ]

    if not warnings:
        return

    console.print("\n[bold yellow]Warnings[/bold yellow]")

    for warning in warnings:
        console.print(f"  [yellow]⚠[/yellow] {warning}")
