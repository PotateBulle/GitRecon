"""
Logique d'analyse des données relatives à un dépôt GitHub.

Ce module transforme les réponses brutes de l'API GitHub en informations
plus facilement exploitables par le reste de GitRecon.
"""

from __future__ import annotations

from typing import Any

from gitrecon.models.analysis import LanguageInfo, RepositoryAnalysis


def calculate_languages(
    languages: dict[str, int],
) -> list[LanguageInfo]:
    """
    Calcule la proportion de chaque langage présent dans le dépôt.

    GitHub retourne un nombre d'octets pour chaque langage détecté.
    Cette fonction convertit ces valeurs en pourcentages afin de rendre
    les résultats plus lisibles pour l'utilisateur.

    Args:
        languages:
            Dictionnaire retourné par l'API GitHub.

    Returns:
        Liste des langages triés par volume de code décroissant.
    """

    total_bytes = sum(languages.values())

    if total_bytes == 0:
        return []

    result: list[LanguageInfo] = []

    for name, byte_count in languages.items():
        percentage = (byte_count / total_bytes) * 100

        result.append(
            LanguageInfo(
                name=name,
                bytes=byte_count,
                percentage=percentage,
            )
        )

    result.sort(
        key=lambda language: language.bytes,
        reverse=True,
    )

    return result


def build_repository_analysis(
    languages: dict[str, int],
    contributors: list[dict[str, Any]] | None,
    branches: list[dict[str, Any]] | None,
    releases: list[dict[str, Any]] | None,
    warnings: list[str] | None = None,
) -> RepositoryAnalysis:
    """
    Construit l'analyse complémentaire d'un dépôt.

    Args:
        languages:
            Langages retournés par GitHub.

        contributors:
            Liste des contributeurs ou ``None`` lorsque cette
            information n'est pas disponible.

        branches:
            Liste des branches ou ``None`` en cas d'indisponibilité.

        releases:
            Liste des releases ou ``None`` en cas d'indisponibilité.

        warnings:
            Avertissements générés pendant la collecte.

    Returns:
        Objet RepositoryAnalysis prêt à être affiché.
    """

    return RepositoryAnalysis(
        languages=calculate_languages(languages),
        contributors_count=(len(contributors) if contributors is not None else None),
        branches_count=(len(branches) if branches is not None else None),
        releases_count=(len(releases) if releases is not None else None),
        warnings=warnings or [],
    )
