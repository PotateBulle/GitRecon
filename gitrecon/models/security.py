"""
Modèles représentant les informations de sécurité d'un dépôt GitHub.

Ces structures permettent à GitRecon de manipuler des données de sécurité
normalisées sans dépendre directement du format brut retourné par
l'API REST GitHub.

La collecte des données est réalisée dans ``gitrecon.github.security``.
La logique d'interprétation est implémentée dans
``gitrecon.analysis.security``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SecurityFileStatus:
    """
    Représente l'état d'un fichier lié à la sécurité ou à la gouvernance.

    Attributes:
        present:
            Indique si la ressource a été détectée.

        path:
            Emplacement du fichier lorsqu'il a été trouvé.
    """

    present: bool
    path: str | None = None


@dataclass(slots=True)
class WorkflowInfo:
    """
    Représente un workflow GitHub Actions détecté.

    Attributes:
        name:
            Nom du workflow tel qu'il est déclaré sur GitHub.

        path:
            Emplacement du fichier YAML dans le dépôt.

        state:
            État du workflow retourné par GitHub.
    """

    name: str
    path: str | None = None
    state: str | None = None


@dataclass(slots=True)
class WorkflowDetection:
    """
    Représente la détection d'une catégorie particulière de workflows.

    Cette structure est utilisée pour identifier certaines fonctions
    automatisées comme CodeQL, zizmor ou les workflows de tests.

    Attributes:
        detected:
            Indique si au moins un workflow correspondant a été trouvé.

        workflows:
            Liste des workflows correspondant à cette catégorie.
    """

    detected: bool
    workflows: list[WorkflowInfo] = field(default_factory=list)


@dataclass(slots=True)
class GitHubActionsStatus:
    """
    Représente l'état général de GitHub Actions pour un dépôt.

    Attributes:
        present:
            Indique si au moins un workflow GitHub Actions existe.

        workflows_count:
            Nombre total de workflows détectés.

        workflows:
            Liste normalisée des workflows GitHub Actions.
    """

    present: bool
    workflows_count: int = 0
    workflows: list[WorkflowInfo] = field(default_factory=list)


@dataclass(slots=True)
class SecurityAutomationAnalysis:
    """
    Regroupe les automatisations liées à la sécurité et au cycle
    de développement détectées dans GitHub Actions.
    """

    codeql: WorkflowDetection
    zizmor: WorkflowDetection
    dependency_review: WorkflowDetection
    dependency_tools: WorkflowDetection
    tests: WorkflowDetection
    releases: WorkflowDetection


@dataclass(slots=True)
class SecurityAnalysis:
    """
    Regroupe les informations de sécurité et de gouvernance d'un dépôt.

    Aucun score de sécurité n'est calculé à ce stade. Le modèle conserve
    uniquement des indicateurs observables qui pourront être utilisés
    ultérieurement par un moteur de scoring.
    """

    security_policy: SecurityFileStatus
    license: SecurityFileStatus
    code_of_conduct: SecurityFileStatus
    contributing_guide: SecurityFileStatus
    dependabot: SecurityFileStatus

    github_actions: GitHubActionsStatus
    automation: SecurityAutomationAnalysis

    warnings: list[str] = field(default_factory=list)
