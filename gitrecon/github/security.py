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
import binascii
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
            if exc.status_code == 404:
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
        if exc.status_code == 404:
            return []

        raise

    if not isinstance(data, dict):
        return []

    workflows = data.get(
        "workflows",
        [],
    )

    if not isinstance(workflows, list):
        return []

    return [workflow for workflow in workflows if isinstance(workflow, dict)]


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
        if exc.status_code == 404:
            return None

        raise

    if not isinstance(data, dict):
        return None

    content = data.get("content")
    encoding = data.get("encoding")

    if not isinstance(content, str):
        return None

    # Base64
    if encoding == "base64":
        normalized_content = "".join(content.split())

        if not normalized_content:
            return ""

        try:
            decoded_content = base64.b64decode(
                normalized_content,
                validate=True,
            )

        except (
            binascii.Error,
            ValueError,
            TypeError,
        ):
            return None

        return decoded_content.decode(
            "utf-8",
            errors="replace",
        )

    # Contenu texte direct
    return content


def is_repository_workflow_path(
    path: str,
) -> bool:
    """
    Vérifie qu'un chemin correspond à un workflow YAML du dépôt.

    Seuls les fichiers stockés sous ``.github/workflows/`` avec une
    extension ``.yml`` ou ``.yaml`` sont acceptés.

    Les chemins contenant un segment ``..`` sont rejetés.
    """

    normalized_path = path.strip()

    if not normalized_path:
        return False

    if not normalized_path.startswith(".github/workflows/"):
        return False

    if not normalized_path.lower().endswith(
        (
            ".yml",
            ".yaml",
        )
    ):
        return False

    path_parts = normalized_path.split("/")

    return ".." not in path_parts


def get_github_actions_workflow_contents(
    client: GitHubClient,
    owner: str,
    repository: str,
    workflows: list[dict[str, Any]],
) -> dict[str, str]:
    """
    Récupère le contenu YAML des workflows GitHub Actions du dépôt.

    Seuls les chemins correspondant à de vrais fichiers YAML présents
    sous ``.github/workflows/`` sont récupérés.

    Les workflows internes ou dynamiques exposés par GitHub sont ignorés.

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
        if not isinstance(workflow, dict):
            continue

        path = workflow.get("path")

        if not isinstance(path, str):
            continue

        normalized_path = path.strip()

        if not is_repository_workflow_path(normalized_path):
            continue

        content = get_repository_file_content(
            client=client,
            owner=owner,
            repository=repository,
            path=normalized_path,
        )

        if content is None:
            continue

        contents[normalized_path] = content
    return contents
