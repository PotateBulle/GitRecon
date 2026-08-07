"""
Fonctions permettant de collecter les informations de sécurité
et de gouvernance d'un dépôt GitHub.

Ce module interroge l'API REST GitHub afin de détecter la présence
de fichiers et configurations couramment utilisés pour documenter
la sécurité, les contributions et l'automatisation d'un projet.

La logique d'interprétation des résultats n'est volontairement pas
implémentée ici. Ce module se limite à la collecte des informations
fournies par GitHub.
"""

from __future__ import annotations

from typing import Any

from gitrecon.github.client import GitHubAPIError, GitHubClient


def repository_file_exists(
    client: GitHubClient,
    owner: str,
    repository: str,
    paths: tuple[str, ...],
) -> tuple[bool, str | None]:
    """
    Vérifie si au moins un fichier donné existe dans un dépôt GitHub.

    Plusieurs emplacements peuvent être testés pour une même ressource.
    Cette approche est utile pour certains fichiers communautaires que
    GitHub accepte dans différents répertoires, comme ``SECURITY.md``.

    Args:
        client:
            Client utilisé pour communiquer avec l'API GitHub.

        owner:
            Propriétaire du dépôt.

        repository:
            Nom du dépôt.

        paths:
            Emplacements à tester dans l'ordre.

    Returns:
        Tuple contenant :

        - ``True`` et le chemin trouvé lorsque le fichier existe ;
        - ``False`` et ``None`` lorsqu'aucun emplacement ne correspond.

    Raises:
        GitHubAPIError:
            Lorsqu'une erreur autre qu'une absence de fichier survient.
    """

    for path in paths:
        endpoint = f"/repos/{owner}/{repository}/contents/{path}"

        try:
            client.get(endpoint)

            return True, path

        except GitHubAPIError as exc:
            error_message = str(exc).lower()

            # Une réponse HTTP 404 indique simplement que le fichier
            # recherché n'existe pas à cet emplacement.
            #
            # Cette absence n'est pas considérée comme une erreur
            # bloquante pour GitRecon.
            if "erreur http 404" in error_message:
                continue

            # Toute autre erreur doit être propagée afin de ne pas
            # masquer un problème d'authentification, de permissions
            # ou de communication avec GitHub.
            raise

    return False, None


def get_security_policy(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[bool, str | None]:
    """
    Recherche une politique de sécurité dans le dépôt.

    GitHub reconnaît notamment ``SECURITY.md`` lorsqu'il est placé
    à la racine, dans ``.github`` ou dans ``docs``.

    Returns:
        Indique si une politique de sécurité a été trouvée ainsi que
        son emplacement éventuel.
    """

    return repository_file_exists(
        client=client,
        owner=owner,
        repository=repository,
        paths=(
            "SECURITY.md",
            ".github/SECURITY.md",
            "docs/SECURITY.md",
        ),
    )


def get_license_file(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[bool, str | None]:
    """
    Recherche un fichier de licence dans le dépôt.

    Plusieurs noms couramment utilisés sont vérifiés afin de ne pas
    dépendre d'une seule convention de nommage.

    Returns:
        Indique si un fichier de licence a été trouvé ainsi que son
        emplacement éventuel.
    """

    return repository_file_exists(
        client=client,
        owner=owner,
        repository=repository,
        paths=(
            "LICENSE",
            "LICENSE.md",
            "LICENSE.txt",
            "COPYING",
            "COPYING.md",
            "COPYING.txt",
        ),
    )


def get_code_of_conduct(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[bool, str | None]:
    """
    Recherche un code de conduite dans le dépôt.

    Returns:
        Indique si un code de conduite a été trouvé ainsi que son
        emplacement éventuel.
    """

    return repository_file_exists(
        client=client,
        owner=owner,
        repository=repository,
        paths=(
            "CODE_OF_CONDUCT.md",
            ".github/CODE_OF_CONDUCT.md",
            "docs/CODE_OF_CONDUCT.md",
            "CODE_OF_CONDUCT.txt",
        ),
    )


def get_contributing_guide(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[bool, str | None]:
    """
    Recherche un guide de contribution dans le dépôt.

    Returns:
        Indique si un fichier de contribution a été trouvé ainsi que
        son emplacement éventuel.
    """

    return repository_file_exists(
        client=client,
        owner=owner,
        repository=repository,
        paths=(
            "CONTRIBUTING.md",
            ".github/CONTRIBUTING.md",
            "docs/CONTRIBUTING.md",
            "CONTRIBUTING.txt",
        ),
    )


def get_dependabot_configuration(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[bool, str | None]:
    """
    Recherche une configuration Dependabot.

    Dependabot utilise généralement le fichier :

        .github/dependabot.yml

    ou :

        .github/dependabot.yaml

    Returns:
        Indique si une configuration Dependabot a été trouvée ainsi
        que son emplacement.
    """

    return repository_file_exists(
        client=client,
        owner=owner,
        repository=repository,
        paths=(
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
        ),
    )


def get_github_actions_workflows(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> list[dict[str, Any]]:
    """
    Récupère les workflows GitHub Actions configurés dans le dépôt.

    L'endpoint GitHub retourne les workflows disponibles ainsi qu'un
    compteur total. GitRecon conserve ici uniquement la liste des
    workflows afin de laisser la logique d'analyse à un autre module.

    Args:
        client:
            Client utilisé pour communiquer avec GitHub.

        owner:
            Propriétaire du dépôt.

        repository:
            Nom du dépôt.

    Returns:
        Liste des workflows GitHub Actions.

    Raises:
        GitHubAPIError:
            Lorsqu'une erreur inattendue survient pendant la requête.
    """

    endpoint = f"/repos/{owner}/{repository}/actions/workflows"

    try:
        data = client.get(
            endpoint,
            params={
                "per_page": 100,
            },
        )

    except GitHubAPIError as exc:
        error_message = str(exc).lower()

        # Certains dépôts ou tokens peuvent ne pas permettre l'accès
        # aux informations GitHub Actions. Dans ce cas, la requête ne
        # doit pas nécessairement empêcher l'analyse des autres éléments.
        if "erreur http 404" in error_message:
            return []

        raise

    workflows = data.get("workflows", [])

    if not isinstance(workflows, list):
        return []

    return workflows
