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
from enum import StrEnum


class FindingSeverity(StrEnum):
    """
    Niveaux de sévérité utilisés par les findings GitRecon.

    Les niveaux sont volontairement simples afin de conserver une
    classification lisible avant l'introduction éventuelle d'un
    système de score plus avancé.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class SecurityFinding:
    """
    Représente un constat de sécurité détecté par GitRecon.

    Un finding décrit une configuration ou un comportement observé
    pouvant avoir un impact sur la sécurité du dépôt.

    Attributes:
        rule_id:
            Identifiant stable de la règle ayant généré le finding.

        title:
            Intitulé court du constat.

        description:
            Explication détaillée du problème détecté.

        severity:
            Niveau de sévérité associé au finding.

        workflow:
            Nom du workflow concerné lorsque le finding provient
            d'une analyse GitHub Actions.

        path:
            Chemin du fichier concerné lorsque celui-ci est connu.

        evidence:
            Élément observé ayant permis de générer le finding.

        recommendation:
            Recommandation permettant de réduire le risque.
    """

    rule_id: str
    title: str
    description: str
    severity: FindingSeverity

    workflow: str | None = None
    path: str | None = None
    evidence: str | None = None
    recommendation: str | None = None


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
    """

    present: bool
    path: str | None = None


@dataclass(slots=True)
class WorkflowInfo:
    """
    Représente un workflow GitHub Actions détecté.

    Un workflow peut être connu par GitHub sans que son fichier YAML
    soit directement accessible dans le dépôt.

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

        actions:
            Liste normalisée des actions GitHub externes détectées
            dans les directives ``uses``.

        uses:
            Liste complète des valeurs ``uses`` rencontrées dans
            le contenu YAML.

        findings:
            Findings de sécurité associés directement à ce workflow.
    """

    name: str
    path: str | None = None
    state: str | None = None

    content_available: bool = False

    actions: list[str] = field(default_factory=list)
    uses: list[str] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)


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
    """

    codeql: WorkflowDetection
    zizmor: WorkflowDetection
    dependency_review: WorkflowDetection
    dependency_tools: WorkflowDetection
    tests: WorkflowDetection
    releases: WorkflowDetection


@dataclass(slots=True)
class WorkflowSecurityAnalysis:
    """
    Regroupe les résultats de l'analyse de sécurité des workflows.

    Attributes:
        findings:
            Ensemble des findings générés lors de l'analyse.

        total:
            Nombre total de findings.

        critical:
            Nombre de findings critiques.

        high:
            Nombre de findings de sévérité élevée.

        medium:
            Nombre de findings de sévérité moyenne.

        low:
            Nombre de findings de faible sévérité.

        info:
            Nombre de findings informatifs.
    """

    findings: list[SecurityFinding] = field(default_factory=list)

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


@dataclass(slots=True)
class SecurityAnalysis:
    """
    Regroupe les informations de sécurité et de gouvernance d'un dépôt.

    Ce modèle contient les observations normalisées issues des fichiers
    communautaires, de GitHub Actions et des contrôles de sécurité.

    Attributes:
        security_policy:
            État de la politique de sécurité.

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

        workflow_security:
            Résultats des contrôles de sécurité appliqués aux workflows.

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

    workflow_security: WorkflowSecurityAnalysis = field(
        default_factory=WorkflowSecurityAnalysis
    )

    warnings: list[str] = field(default_factory=list)
