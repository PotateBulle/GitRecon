"""
Modèles représentant les informations utilisées par GitRecon.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class RepositoryInfo:
    """
    Représentation simplifiée d'un dépôt GitHub.

    Ce modèle contient uniquement les informations utiles à GitRecon.
    Il permet d'éviter de faire dépendre directement le reste de
    l'application de la structure complète des réponses de GitHub.
    """

    name: str
    full_name: str
    owner: str
    description: str | None

    private: bool
    fork: bool
    archived: bool

    default_branch: str
    language: str | None

    stars: int
    forks: int
    open_issues: int

    created_at: str
    updated_at: str
    pushed_at: str | None

    @classmethod
    def from_github(
        cls,
        data: dict[str, Any],
    ) -> RepositoryInfo:
        """
        Construit un objet RepositoryInfo depuis une réponse GitHub.

        Args:
            data:
                Données JSON retournées par l'API REST GitHub.

        Returns:
            Instance normalisée de RepositoryInfo.
        """

        return cls(
            name=data["name"],
            full_name=data["full_name"],
            owner=data["owner"]["login"],
            description=data.get("description"),
            private=data["private"],
            fork=data["fork"],
            archived=data["archived"],
            default_branch=data["default_branch"],
            language=data.get("language"),
            stars=data["stargazers_count"],
            forks=data["forks_count"],
            open_issues=data["open_issues_count"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            pushed_at=data.get("pushed_at"),
        )
