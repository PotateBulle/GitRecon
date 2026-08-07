"""
Collecte des informations de sécurité et de gouvernance d'un dépôt GitHub.

Ce module interroge l'API REST GitHub afin de détecter la présence
de fichiers communautaires, de configurations liées à la sécurité
et de workflows GitHub Actions.

La logique d'interprétation des données reste volontairement séparée
et se trouve dans ``gitrecon.analysis.security``.
"""

from __future__ import annotations

import base64
from typing import Any

from gitrecon.github.client import GitHubAPIError, GitHubClient


def repository_file_exists(
    client: GitHubClient,
    owner: str,
    repository: str,
    paths: tuple[str, ...],
) -> tuple[bool, str | None]:
    """
    Vérifie si au moins un des fichiers fournis existe dans le dépôt.

    Plusieurs emplacements peuvent être testés pour une même ressource.
    La fonction s'arrête dès qu'un fichier correspondant est trouvé.

    Args:
        client:
            Client utilisé pour communiquer avec l'API GitHub.

        owner:
            Propriétaire du dépôt.

        repository:
            Nom du dépôt.

        paths:
            Chemins à vérifier dans l'ordre.

    Returns:
        Tuple contenant :

        - ``True`` et le chemin trouvé lorsque le fichier existe ;
        - ``False`` et ``None`` lorsqu'aucun fichier n'est trouvé.

    Raises:
        GitHubAPIError:
            Lorsqu'une erreur autre qu'un HTTP 404 survient.
    """

    for path in paths:
        endpoint = f"/repos/{owner}/{repository}/contents/{path}"

        try:
            client.get(endpoint)

            return True, path

        except GitHubAPIError as exc:
            error_message = str(exc).lower()

            # Une réponse HTTP 404 indique simplement que le fichier
            # n'existe pas à cet emplacement.
            if "erreur http 404" in error_message:
                continue

            raise

    return False, None


def get_security_policy(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[bool, str | None]:
    """
    Recherche un fichier SECURITY.md.

    GitHub reconnaît notamment les emplacements suivants :

    - SECURITY.md ;
    - .github/SECURITY.md ;
    - docs/SECURITY.md.
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
            "CONTRIBUTING.rst",
            ".github/CONTRIBUTING.rst",
            "docs/CONTRIBUTING.rst",
        ),
    )


def get_dependabot_configuration(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> tuple[bool, str | None]:
    """
    Recherche une configuration Dependabot.

    Dependabot utilise normalement l'un des fichiers suivants :

    - .github/dependabot.yml ;
    - .github/dependabot.yaml.
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
    Récupère les workflows GitHub Actions du dépôt.

    Args:
        client:
            Client GitHub.

        owner:
            Propriétaire du dépôt.

        repository:
            Nom du dépôt.

    Returns:
        Liste brute des workflows GitHub Actions.

    Raises:
        GitHubAPIError:
            Lorsqu'une erreur inattendue survient.
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

        # GitHub peut retourner 404 lorsqu'Actions n'est pas disponible
        # ou lorsque le dépôt ne possède aucun workflow accessible.
        if "erreur http 404" in error_message:
            return []

        raise

    if not isinstance(data, dict):
        return []

    workflows = data.get("workflows", [])

    if not isinstance(workflows, list):
        return []

    return workflows


def get_repository_file_content(
    client: GitHubClient,
    owner: str,
    repository: str,
    path: str,
) -> str | None:
    """
    Récupère le contenu textuel d'un fichier présent dans le dépôt.

    L'API Contents de GitHub retourne généralement le contenu d'un fichier
    encodé en Base64. Cette fonction effectue automatiquement le décodage.

    Args:
        client:
            Client GitHub.

        owner:
            Propriétaire du dépôt.

        repository:
            Nom du dépôt.

        path:
            Chemin du fichier dans le dépôt.

    Returns:
        Contenu textuel du fichier ou ``None`` lorsqu'il ne peut pas être
        récupéré ou interprété.

    Raises:
        GitHubAPIError:
            Lorsqu'une erreur inattendue survient.
    """

    endpoint = f"/repos/{owner}/{repository}/contents/{path}"

    try:
        data = client.get(endpoint)

    except GitHubAPIError as exc:
        error_message = str(exc).lower()

        if "erreur http 404" in error_message:
            return None

        raise

    if not isinstance(data, dict):
        return None

    content = data.get("content")
    encoding = data.get("encoding")

    if not isinstance(content, str):
        return None

    # Lorsque GitHub retourne explicitement du Base64, le contenu doit
    # être décodé avant toute analyse.
    if encoding == "base64":
        try:
            decoded_content = base64.b64decode(
                content,
                validate=False,
            )

        except (ValueError, TypeError):
            return None

        return decoded_content.decode(
            "utf-8",
            errors="replace",
        )

    # Certains endpoints ou comportements futurs pourraient retourner
    # directement une chaîne non encodée.
    return content


def get_github_actions_workflow_contents(
    client: GitHubClient,
    owner: str,
    repository: str,
    workflows: list[dict[str, Any]],
) -> dict[str, str]:
    """
    Récupère le contenu YAML de chaque workflow GitHub Actions.

    Args:
        client:
            Client GitHub.

        owner:
            Propriétaire du dépôt.

        repository:
            Nom du dépôt.

        workflows:
            Liste brute des workflows retournée par GitHub.

    Returns:
        Dictionnaire associant le chemin d'un workflow à son contenu YAML.
    """

    contents: dict[str, str] = {}

    for workflow in workflows:
        path = workflow.get("path")

        if not isinstance(path, str):
            continue

        content = get_repository_file_content(
            client=client,
            owner=owner,
            repository=repository,
            path=path,
        )

        if content is None:
            continue

        contents[path] = content

    return contents
