"""
Modèles représentant les résultats d'analyse produits par GitRecon.

Ces structures regroupent les informations supplémentaires récupérées
depuis l'API GitHub sans modifier directement le modèle principal
RepositoryInfo.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class LanguageInfo:
    """
    Représente un langage détecté dans le dépôt.
    """

    name: str
    bytes: int
    percentage: float


@dataclass(slots=True)
class RepositoryAnalysis:
    """
    Contient les informations complémentaires collectées
    lors de l'analyse d'un dépôt GitHub.

    Certains champs peuvent être indisponibles lorsque GitHub refuse
    ou ne peut pas fournir une information pour un dépôt particulier.
    """

    languages: list[LanguageInfo] = field(default_factory=list)

    contributors_count: int | None = None
    branches_count: int | None = None
    releases_count: int | None = None

    warnings: list[str] = field(default_factory=list)
