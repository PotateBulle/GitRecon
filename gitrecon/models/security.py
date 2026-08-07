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

    Cette structure est notamment utilisée pour :

    - SECURITY.md ;
    - LICENSE ;
    - CODE_OF_CONDUCT.md ;
    - CONTRIBUTING.md ;
    - dependabot.yml.

    Attributes:
        present:
            Indique si la ressource a été détectée.

        path:
            Chemin du fichier lorsqu'il a été trouvé.
            La valeur est ``None`` lorsque le fichier est absent.
    """

    present: bool
    path: str | None = None


@dataclass(slots=True)
class WorkflowInfo:
    """
    Représente un workflow GitHub Actions détecté.

    Un workflow peut être connu par GitHub sans que son fichier YAML
    soit directement accessible dans le dépôt. C'est notamment le cas
    de certaines automatisations gérées dynamiquement par GitHub.

    Attributes:
        name:
            Nom du workflow tel qu'il est exposé par GitHub.

        path:
            Emplacement du workflow lorsqu'un chemin est disponible.

        state:
            État du workflow retourné par l'API GitHub.

        content_available:
            Indique si GitRecon a effectivement pu récupérer le contenu
            YAML du workflow.

            ``True`` signifie que le fichier a été récupéré et analysé.

            ``False`` signifie que seules les métadonnées GitHub sont
            disponibles.

        actions:
            Liste normalisée des actions GitHub externes détectées
            dans les directives ``uses`` du workflow.

        uses:
            Liste complète des valeurs ``uses`` rencontrées dans
            le contenu YAML.
    """

    name: str
    path: str | None = None
    state: str | None = None

    content_available: bool = False

    actions: list[str] = field(default_factory=list)
    uses: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WorkflowDetection:
    """
    Représente la détection d'une catégorie de workflows.

    Une détection peut provenir de l'analyse réelle du contenu YAML
    ou d'une classification fondée sur les métadonnées du workflow.

    Attributes:
        detected:
            Indique si au moins un workflow correspondant a été trouvé.

        workflows:
            Liste des workflows associés à cette détection.
    """

    detected: bool
    workflows: list[WorkflowInfo] = field(default_factory=list)


@dataclass(slots=True)
class GitHubActionsStatus:
    """
    Représente l'état général de GitHub Actions pour un dépôt.

    Attributes:
        present:
            Indique si GitHub expose au moins un workflow.

        workflows_count:
            Nombre total de workflows retournés par GitHub.

        workflows:
            Liste normalisée des workflows disponibles.
    """

    present: bool
    workflows_count: int = 0
    workflows: list[WorkflowInfo] = field(default_factory=list)


@dataclass(slots=True)
class SecurityAutomationAnalysis:
    """
    Regroupe les automatisations liées à la sécurité et au cycle
    de développement détectées dans GitHub Actions.

    Certaines catégories peuvent être confirmées par l'analyse réelle
    des actions présentes dans les fichiers YAML, tandis que d'autres
    utilisent encore des heuristiques basées sur les métadonnées.
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

    Ce modèle contient uniquement des observations normalisées.
    Aucun score de sécurité n'est calculé à ce niveau.

    Attributes:
        security_policy:
            État de la politique de sécurité du dépôt.

        license:
            État du fichier de licence.

        code_of_conduct:
            État du code de conduite.

        contributing_guide:
            État du guide de contribution.

        dependabot:
            État de la configuration Dependabot.

        github_actions:
            Informations générales concernant GitHub Actions.

        automation:
            Résultats des détections effectuées dans les workflows.

        warnings:
            Limitations ou anomalies non bloquantes rencontrées
            pendant la collecte ou l'analyse.
    """

    security_policy: SecurityFileStatus
    license: SecurityFileStatus
    code_of_conduct: SecurityFileStatus
    contributing_guide: SecurityFileStatus
    dependabot: SecurityFileStatus

    github_actions: GitHubActionsStatus
    automation: SecurityAutomationAnalysis

    warnings: list[str] = field(default_factory=list)
