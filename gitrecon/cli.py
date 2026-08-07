"""
Interface en ligne de commande de GitRecon.

Ce module constitue le point d'entrée principal de l'application.
Il interprète les commandes saisies par l'utilisateur et coordonne
les différents composants nécessaires à leur exécution.
"""

from __future__ import annotations

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
    get_github_actions_workflows,
    get_license_file,
    get_security_policy,
)
from gitrecon.models.repository import RepositoryInfo
from gitrecon.output.terminal import console, display_repository

app = typer.Typer(
    name="gitrecon",
    help="GitHub Repository Intelligence & Security Scanner.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """
    GitRecon — GitHub Repository Intelligence & Security Scanner.
    """


def parse_repository_target(target: str) -> tuple[str, str]:
    """
    Extrait le propriétaire et le nom d'un dépôt GitHub.

    Les formats suivants sont acceptés :

        owner/repository

        https://github.com/owner/repository

        https://github.com/owner/repository.git

    Args:
        target:
            Cible GitHub fournie par l'utilisateur.

    Returns:
        Tuple contenant respectivement le propriétaire et le nom
        du dépôt.

    Raises:
        typer.BadParameter:
            Lorsque la cible fournie n'est pas correctement formée.
    """

    cleaned_target = target.strip()

    # Une cible commençant par HTTP ou HTTPS est interprétée comme
    # une URL GitHub complète.
    if cleaned_target.startswith(("http://", "https://")):
        parsed_url = urlparse(cleaned_target)

        if parsed_url.hostname not in {
            "github.com",
            "www.github.com",
        }:
            raise typer.BadParameter("L'URL fournie doit pointer vers github.com.")

        path_parts = [part for part in parsed_url.path.strip("/").split("/") if part]

        if len(path_parts) < 2:
            raise typer.BadParameter("L'URL GitHub ne contient pas de dépôt valide.")

        owner = path_parts[0]
        repository = path_parts[1]

    else:
        # Lorsque la cible n'est pas une URL, GitRecon attend le
        # format simple owner/repository.
        path_parts = [part for part in cleaned_target.strip("/").split("/") if part]

        if len(path_parts) != 2:
            raise typer.BadParameter(
                "Le dépôt doit être indiqué sous la forme "
                "owner/repository ou avec son URL GitHub complète."
            )

        owner, repository = path_parts

    # Les URL de clonage Git peuvent se terminer par ".git".
    # Cette extension ne fait pas partie du véritable nom du dépôt.
    repository = repository.removesuffix(".git")

    if not owner or not repository:
        raise typer.BadParameter(
            "Le propriétaire et le nom du dépôt sont obligatoires."
        )

    return owner, repository


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help=(
            "Dépôt GitHub à analyser. Formats acceptés : "
            "owner/repository ou URL GitHub complète."
        ),
        metavar="REPOSITORY",
    ),
) -> None:
    """
    Analyse un dépôt GitHub et affiche les informations collectées.

    GitRecon récupère les métadonnées générales du dépôt ainsi que
    différents indicateurs relatifs à son activité, sa gouvernance,
    sa sécurité et ses automatisations GitHub Actions.
    """

    owner, repository_name = parse_repository_target(target)

    client = GitHubClient()

    try:
        # ------------------------------------------------------------------
        # Métadonnées générales du dépôt
        # ------------------------------------------------------------------

        repository_data = get_repository(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        languages_data = get_languages(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        # Cette liste contient les limitations non bloquantes rencontrées
        # pendant la collecte générale.
        warnings: list[str] = []

        # ------------------------------------------------------------------
        # Contributeurs
        # ------------------------------------------------------------------

        try:
            contributors_data = get_contributors(
                client=client,
                owner=owner,
                repository=repository_name,
            )

        except GitHubAPIError as exc:
            error_message = str(exc).lower()

            # GitHub peut refuser d'énumérer les contributeurs de certains
            # très grands dépôts lorsque leur historique est trop important.
            if "contributor list is too large" in error_message:
                contributors_data = None

                warnings.append(
                    "GitHub ne permet pas d'énumérer les contributeurs "
                    "de ce dépôt, car son historique est trop volumineux."
                )

            else:
                raise

        # ------------------------------------------------------------------
        # Branches et releases
        # ------------------------------------------------------------------

        branches_data = get_branches(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        releases_data = get_releases(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        # ------------------------------------------------------------------
        # Informations de sécurité et de gouvernance
        # ------------------------------------------------------------------

        security_policy_data = get_security_policy(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        license_data = get_license_file(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        code_of_conduct_data = get_code_of_conduct(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        contributing_guide_data = get_contributing_guide(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        dependabot_data = get_dependabot_configuration(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        workflows_data = get_github_actions_workflows(
            client=client,
            owner=owner,
            repository=repository_name,
        )

        # ------------------------------------------------------------------
        # Normalisation des données
        # ------------------------------------------------------------------

        repository = RepositoryInfo.from_github(repository_data)

        analysis = build_repository_analysis(
            languages=languages_data,
            contributors=contributors_data,
            branches=branches_data,
            releases=releases_data,
            warnings=warnings,
        )

        security_analysis = build_security_analysis(
            security_policy=security_policy_data,
            license_file=license_data,
            code_of_conduct=code_of_conduct_data,
            contributing_guide=contributing_guide_data,
            dependabot=dependabot_data,
            workflows=workflows_data,
        )

        # ------------------------------------------------------------------
        # Affichage du rapport
        # ------------------------------------------------------------------

        display_repository(
            repository=repository,
            analysis=analysis,
            security=security_analysis,
        )

    except GitHubAPIError as exc:
        console.print(f"[bold red]Erreur GitHub :[/bold red] {exc}")

        raise typer.Exit(code=1) from exc

    except KeyError as exc:
        console.print(
            "[bold red]Erreur :[/bold red] "
            f"donnée GitHub manquante ou inattendue : {exc}"
        )

        raise typer.Exit(code=1) from exc

    finally:
        # Les connexions HTTP sont toujours fermées, même lorsque
        # l'analyse se termine prématurément à cause d'une erreur.
        client.close()


if __name__ == "__main__":
    app()
