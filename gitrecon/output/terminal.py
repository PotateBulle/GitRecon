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
    SecurityAnalysis,
    SecurityFileStatus,
    WorkflowDetection,
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
    Formate l'état d'un fichier lié à la sécurité ou à la gouvernance.

    Args:
        status:
            État du fichier à afficher.

    Returns:
        Chaîne Rich représentant la présence ou l'absence du fichier.
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
            Résultat de détection à présenter.

    Returns:
        État de la détection accompagné du nombre de workflows
        correspondants lorsqu'au moins un élément a été trouvé.
    """

    if not detection.detected:
        return "[red]Not detected[/red]"

    count = len(detection.workflows)

    return f"[green]Detected[/green] ({count})"


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
            Résultats de l'analyse générale.

        security:
            Résultats de l'analyse de sécurité.
    """

    console.print()
    console.rule("[bold]GitRecon — Repository Intelligence")

    display_repository_information(repository)
    display_statistics(repository, analysis)
    display_languages(analysis)
    display_activity(repository)
    display_security(security)
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

    Args:
        security:
            Analyse de sécurité normalisée du dépôt.
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
    Affiche les automatisations de sécurité détectées.

    La détection repose actuellement sur les noms et chemins des
    workflows GitHub Actions.
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


def display_github_actions_workflows(
    security: SecurityAnalysis,
) -> None:
    """
    Affiche la liste complète des workflows GitHub Actions.

    Args:
        security:
            Analyse de sécurité contenant les workflows normalisés.
    """

    if not security.github_actions.workflows:
        return

    console.print("\n[bold]GitHub Actions workflows[/bold]")

    for workflow in security.github_actions.workflows:
        console.print(f"  [green]✓[/green] {workflow.name}")


def display_warnings(
    analysis: RepositoryAnalysis,
    security: SecurityAnalysis,
) -> None:
    """
    Affiche les avertissements générés pendant le scan.

    Les avertissements de l'analyse générale et de l'analyse de sécurité
    sont regroupés afin d'éviter plusieurs sections distinctes.
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
