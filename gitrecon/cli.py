"""
Interface en ligne de commande de GitRecon.

Ce module définit les commandes exposées à l'utilisateur et orchestre
la collecte, l'analyse et l'affichage des informations d'un dépôt GitHub.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import typer

from gitrecon.analysis.repository import build_repository_analysis
from gitrecon.analysis.security import build_security_analysis
from gitrecon.github.client import GitHubAPIError, GitHubClient
from gitrecon.github.repositories import (
    get_branches,
    get_contributors,
    get_languages,
    get_releases,
    get_repository,
)
from gitrecon.github.security import (
    get_code_of_conduct,
    get_contributing_guide,
    get_dependabot_configuration,
    get_github_actions_workflow_contents,
    get_github_actions_workflows,
    get_license_file,
    get_security_policy,
)
from gitrecon.models.analysis import RepositoryAnalysis
from gitrecon.models.repository import RepositoryInfo
from gitrecon.models.security import SecurityAnalysis
from gitrecon.output.json import write_json_report
from gitrecon.output.terminal import (
    console,
    display_repository,
)

app = typer.Typer(
    name="gitrecon",
    help=("GitRecon collecte et analyse les informations publiques d'un dépôt GitHub."),
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """
    Interface principale de GitRecon.
    """


def parse_repository_target(
    target: str,
) -> tuple[str, str]:
    """
    Analyse une cible GitHub et retourne le propriétaire et le dépôt.

    Formats acceptés :

        owner/repository
        https://github.com/owner/repository
        https://github.com/owner/repository.git
    """

    normalized_target = target.strip()

    if not normalized_target:
        raise ValueError("La cible du dépôt ne peut pas être vide.")

    # URL GitHub
    if normalized_target.startswith(
        (
            "http://",
            "https://",
        )
    ):
        parsed = urlparse(normalized_target)

        if parsed.hostname not in {
            "github.com",
            "www.github.com",
        }:
            raise ValueError("L'URL doit pointer vers github.com.")

        parts = [part for part in parsed.path.split("/") if part]

    # owner/repository
    else:
        parts = [part for part in normalized_target.split("/") if part]

    if len(parts) != 2:
        raise ValueError(
            "La cible doit utiliser le format owner/repository "
            "ou une URL GitHub complète."
        )

    owner, repository = parts

    repository = repository.removesuffix(".git")

    owner = owner.strip()
    repository = repository.strip()

    if not owner or not repository:
        raise ValueError("Le propriétaire et le dépôt doivent être renseignés.")

    return owner, repository


def collect_repository_data(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[
    RepositoryInfo,
    RepositoryAnalysis,
    SecurityAnalysis,
]:
    """
    Collecte et analyse les informations nécessaires au rapport.
    """

    warnings: list[str] = []

    # Dépôt
    repository_data = get_repository(
        client,
        owner,
        repository,
    )

    repository_info = RepositoryInfo.from_github(repository_data)

    # Langages
    languages = get_languages(
        client,
        owner,
        repository,
    )

    # Contributeurs
    contributors: list[dict] | None

    try:
        contributors = get_contributors(
            client,
            owner,
            repository,
        )

    except GitHubAPIError as exc:
        message = str(exc).lower()

        if exc.status_code == 403 and "contributor list is too large" in message:
            contributors = None

            warnings.append(
                "La liste des contributeurs est trop volumineuse "
                "pour être retournée par l'API GitHub."
            )

        else:
            raise

    # Branches
    branches = get_branches(
        client,
        owner,
        repository,
    )

    # Releases
    releases = get_releases(
        client,
        owner,
        repository,
    )

    analysis = build_repository_analysis(
        languages=languages,
        contributors=contributors,
        branches=branches,
        releases=releases,
        warnings=warnings,
    )

    # Sécurité
    security_policy = get_security_policy(
        client,
        owner,
        repository,
    )

    license_file = get_license_file(
        client,
        owner,
        repository,
    )

    code_of_conduct = get_code_of_conduct(
        client,
        owner,
        repository,
    )

    contributing_guide = get_contributing_guide(
        client,
        owner,
        repository,
    )

    dependabot = get_dependabot_configuration(
        client,
        owner,
        repository,
    )

    # GitHub Actions
    workflows = get_github_actions_workflows(
        client,
        owner,
        repository,
    )

    workflow_contents = get_github_actions_workflow_contents(
        client,
        owner,
        repository,
        workflows,
    )

    security = build_security_analysis(
        security_policy=security_policy,
        license_file=license_file,
        code_of_conduct=code_of_conduct,
        contributing_guide=contributing_guide,
        dependabot=dependabot,
        workflows=workflows,
        workflow_contents=workflow_contents,
    )

    return (
        repository_info,
        analysis,
        security,
    )


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            help=("Dépôt GitHub à analyser : owner/repository ou URL GitHub complète."),
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help=("Exporte le rapport au format JSON dans le dossier reports."),
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "Nom du fichier JSON à créer dans reports. "
                "Cette option nécessite --json."
            ),
        ),
    ] = None,
) -> None:
    """
    Analyse un dépôt GitHub.

    Sans option particulière, GitRecon affiche le rapport dans le terminal.

    Avec ``--json``, GitRecon crée automatiquement le dossier ``reports``
    et y sauvegarde le rapport JSON.
    """

    if output is not None and not json_output:
        raise typer.BadParameter(
            "--output nécessite l'option --json.",
            param_hint="--output",
        )

    try:
        owner, repository = parse_repository_target(target)

    except ValueError as exc:
        console.print(f"[bold red]Erreur :[/bold red] {exc}")

        raise typer.Exit(code=2) from exc

    client = GitHubClient()

    try:
        (
            repository_info,
            analysis,
            security,
        ) = collect_repository_data(
            client=client,
            owner=owner,
            repository=repository,
        )

        # Export JSON
        if json_output:
            try:
                output_path = write_json_report(
                    repository=repository_info,
                    analysis=analysis,
                    security=security,
                    filename=output,
                )

            except (OSError, ValueError) as exc:
                console.print("\n[bold red]Erreur export JSON[/bold red]")

                console.print(str(exc))

                raise typer.Exit(code=1) from exc

            console.print(f"\n[green]Rapport JSON créé :[/green] {output_path}")

            return

        # Affichage
        display_repository(
            repository=repository_info,
            analysis=analysis,
            security=security,
        )

    except GitHubAPIError as exc:
        console.print("\n[bold red]Erreur GitHub API[/bold red]")

        console.print(str(exc))

        raise typer.Exit(code=1) from exc

    except KeyError as exc:
        console.print("\n[bold red]Erreur de données[/bold red]")

        console.print(
            f"Une information attendue est absente de la réponse GitHub : {exc}"
        )

        raise typer.Exit(code=1) from exc

    finally:
        client.close()


if __name__ == "__main__":
    app()
