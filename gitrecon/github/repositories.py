"""
Fonctions permettant d'interroger les informations relatives
aux dépôts GitHub.
"""

from __future__ import annotations

from typing import Any

from gitrecon.github.client import GitHubClient


def get_repository(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> dict[str, Any]:
    """
    Récupère les informations générales d'un dépôt GitHub.
    """

    endpoint = f"/repos/{owner}/{repository}"

    return client.get(endpoint)


def get_languages(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> dict[str, int]:
    """
    Récupère les langages détectés dans un dépôt GitHub.
    """

    endpoint = f"/repos/{owner}/{repository}/languages"

    return client.get(endpoint)


def get_contributors(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> list[dict[str, Any]]:
    """
    Récupère l'ensemble des contributeurs accessibles via l'API GitHub.

    Certains dépôts très volumineux peuvent refuser cette opération.
    Cette limitation est gérée au niveau de la commande de scan.
    """

    endpoint = f"/repos/{owner}/{repository}/contributors"

    return client.get_paginated(
        endpoint,
        params={
            "anon": "true",
        },
    )


def get_branches(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> list[dict[str, Any]]:
    """
    Récupère l'ensemble des branches du dépôt.
    """

    endpoint = f"/repos/{owner}/{repository}/branches"

    return client.get_paginated(endpoint)


def get_releases(
    client: GitHubClient,
    owner: str,
    repository: str,
) -> list[dict[str, Any]]:
    """
    Récupère l'ensemble des releases GitHub du dépôt.
    """

    endpoint = f"/repos/{owner}/{repository}/releases"

    return client.get_paginated(endpoint)
