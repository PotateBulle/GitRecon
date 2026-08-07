"""
Analyse des informations de sécurité d'un dépôt GitHub.

Ce module transforme les données brutes collectées via l'API GitHub
en structures normalisées utilisables par GitRecon.

Depuis la V3.2, le contenu YAML des workflows GitHub Actions peut être
analysé afin d'identifier les actions réellement référencées dans les
directives ``uses``.

La V3.2.1 ajoute également une distinction entre les workflows dont
le contenu YAML est réellement disponible et ceux uniquement connus
grâce aux métadonnées retournées par GitHub.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import yaml

from gitrecon.models.security import (
    GitHubActionsStatus,
    SecurityAnalysis,
    SecurityAutomationAnalysis,
    SecurityFileStatus,
    WorkflowDetection,
    WorkflowInfo,
)


def build_file_status(
    result: tuple[bool, str | None],
) -> SecurityFileStatus:
    """
    Construit l'état normalisé d'un fichier de sécurité.

    Args:
        result:
            Tuple contenant :

            - un booléen indiquant si le fichier existe ;
            - son chemin lorsqu'il a été trouvé.

    Returns:
        État normalisé du fichier.
    """

    present, path = result

    return SecurityFileStatus(
        present=present,
        path=path,
    )


def extract_uses_from_yaml(
    content: str,
) -> list[str]:
    """
    Extrait toutes les directives ``uses`` d'un workflow GitHub Actions.

    Le document YAML est parcouru récursivement afin de détecter les
    références présentes dans les jobs, les steps ou d'autres structures.

    Args:
        content:
            Contenu YAML brut du workflow.

    Returns:
        Liste dédupliquée des valeurs ``uses`` rencontrées.

    Notes:
        Une erreur de parsing YAML n'interrompt pas le scan. Dans ce cas,
        une liste vide est retournée.
    """

    try:
        document = yaml.safe_load(content)

    except yaml.YAMLError:
        return []

    if not isinstance(document, dict):
        return []

    uses_values: list[str] = []

    def walk(value: Any) -> None:
        """
        Parcourt récursivement une structure issue du document YAML.
        """

        if isinstance(value, dict):
            for key, item in value.items():
                if key == "uses" and isinstance(item, str):
                    normalized_value = item.strip()

                    if normalized_value and normalized_value not in uses_values:
                        uses_values.append(normalized_value)

                walk(item)

        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)

    return uses_values


def normalize_action_name(value: str) -> str:
    """
    Normalise une directive ``uses`` GitHub Actions.

    La version ou la référence Git située après ``@`` est supprimée.

    Exemple :

        actions/checkout@v4

    devient :

        actions/checkout

    Args:
        value:
            Valeur brute d'une directive ``uses``.

    Returns:
        Nom normalisé de l'action ou du workflow réutilisable.
    """

    return value.split("@", maxsplit=1)[0].strip()


def extract_actions(
    uses: list[str],
) -> list[str]:
    """
    Extrait les actions externes utilisées par un workflow.

    Les actions locales commençant par ``./`` sont conservées dans
    ``WorkflowInfo.uses`` mais ne sont pas considérées comme des
    actions externes.

    Args:
        uses:
            Valeurs ``uses`` extraites du workflow.

    Returns:
        Liste dédupliquée des actions externes normalisées.
    """

    actions: list[str] = []

    for value in uses:
        if value.startswith("./"):
            continue

        action = normalize_action_name(value)

        if action and action not in actions:
            actions.append(action)

    return actions


def normalize_workflow(
    workflow: dict[str, Any],
    content: str | None = None,
) -> WorkflowInfo:
    """
    Transforme un workflow brut GitHub en modèle interne.

    Lorsque le contenu YAML est disponible, les directives ``uses`` sont
    extraites puis normalisées afin d'identifier les actions réellement
    référencées par le workflow.

    Args:
        workflow:
            Métadonnées brutes du workflow retournées par GitHub.

        content:
            Contenu YAML du workflow lorsqu'il a pu être récupéré.

    Returns:
        Workflow normalisé.
    """

    name = workflow.get("name")
    path = workflow.get("path")
    state = workflow.get("state")

    uses: list[str] = []

    if content is not None:
        uses = extract_uses_from_yaml(content)

    actions = extract_actions(uses)

    return WorkflowInfo(
        name=(
            name.strip()
            if isinstance(name, str) and name.strip()
            else "Workflow sans nom"
        ),
        path=path if isinstance(path, str) else None,
        state=state if isinstance(state, str) else None,
        content_available=content is not None,
        actions=actions,
        uses=uses,
    )


def build_github_actions_status(
    workflows: list[dict[str, Any]],
    workflow_contents: dict[str, str] | None = None,
) -> GitHubActionsStatus:
    """
    Construit l'état normalisé de GitHub Actions.

    Args:
        workflows:
            Workflows bruts retournés par l'API GitHub.

        workflow_contents:
            Contenus YAML indexés par chemin de workflow.

    Returns:
        État normalisé de GitHub Actions.
    """

    contents = workflow_contents or {}

    normalized_workflows: list[WorkflowInfo] = []

    for workflow in workflows:
        path = workflow.get("path")

        content = contents.get(path) if isinstance(path, str) else None

        normalized_workflows.append(
            normalize_workflow(
                workflow=workflow,
                content=content,
            )
        )

    return GitHubActionsStatus(
        present=bool(normalized_workflows),
        workflows_count=len(normalized_workflows),
        workflows=normalized_workflows,
    )


def workflow_matches(
    workflow: WorkflowInfo,
    keywords: Iterable[str],
) -> bool:
    """
    Vérifie si un workflow correspond à une série de mots-clés.

    La recherche est effectuée dans le nom et dans le chemin du workflow.

    Args:
        workflow:
            Workflow à analyser.

        keywords:
            Mots-clés associés à une catégorie.

    Returns:
        ``True`` lorsqu'au moins un mot-clé est détecté.
    """

    searchable_content = " ".join(
        (
            workflow.name,
            workflow.path or "",
        )
    ).lower()

    return any(keyword.lower() in searchable_content for keyword in keywords)


def detect_workflows(
    workflows: list[WorkflowInfo],
    keywords: tuple[str, ...],
) -> WorkflowDetection:
    """
    Détecte des workflows à partir de leurs métadonnées.

    Cette fonction est utilisée comme mécanisme heuristique lorsque
    l'analyse du contenu YAML ne suffit pas ou n'est pas disponible.

    Args:
        workflows:
            Workflows à analyser.

        keywords:
            Mots-clés utilisés pour la classification.

    Returns:
        Résultat de la détection.
    """

    matches = [
        workflow
        for workflow in workflows
        if workflow_matches(
            workflow,
            keywords,
        )
    ]

    return WorkflowDetection(
        detected=bool(matches),
        workflows=matches,
    )


def workflow_uses_action(
    workflow: WorkflowInfo,
    action_prefixes: tuple[str, ...],
) -> bool:
    """
    Vérifie si un workflow utilise une action donnée.

    La comparaison est réalisée sur les noms d'actions normalisés,
    sans tenir compte de la version située après ``@``.

    Args:
        workflow:
            Workflow à analyser.

        action_prefixes:
            Actions ou préfixes d'actions recherchés.

    Returns:
        ``True`` lorsqu'une action correspond à l'un des préfixes.
    """

    normalized_prefixes = tuple(prefix.lower() for prefix in action_prefixes)

    return any(
        action.lower().startswith(normalized_prefixes) for action in workflow.actions
    )


def detect_action_usage(
    workflows: list[WorkflowInfo],
    actions: tuple[str, ...],
) -> WorkflowDetection:
    """
    Détecte les workflows utilisant réellement certaines actions.

    Args:
        workflows:
            Workflows à analyser.

        actions:
            Actions ou préfixes recherchés.

    Returns:
        Résultat de la détection.
    """

    matches = [
        workflow
        for workflow in workflows
        if workflow_uses_action(
            workflow,
            actions,
        )
    ]

    return WorkflowDetection(
        detected=bool(matches),
        workflows=matches,
    )


def merge_workflow_detections(
    *detections: WorkflowDetection,
) -> WorkflowDetection:
    """
    Fusionne plusieurs résultats de détection sans créer de doublons.

    Cette fonction permet de combiner plusieurs sources d'information,
    par exemple :

    - analyse réelle du contenu YAML ;
    - métadonnées GitHub ;
    - heuristiques basées sur le nom du workflow.

    Args:
        detections:
            Résultats de détection à fusionner.

    Returns:
        Détection consolidée.
    """

    workflows: list[WorkflowInfo] = []

    for detection in detections:
        for workflow in detection.workflows:
            if workflow not in workflows:
                workflows.append(workflow)

    return WorkflowDetection(
        detected=bool(workflows),
        workflows=workflows,
    )


def build_security_automation_analysis(
    workflows: list[WorkflowInfo],
) -> SecurityAutomationAnalysis:
    """
    Analyse les automatisations GitHub Actions du dépôt.

    Certaines technologies disposent d'une action GitHub identifiable
    directement dans le YAML. D'autres nécessitent encore une analyse
    heuristique basée sur les métadonnées.

    CodeQL est volontairement détecté de deux manières :

    1. utilisation réelle de ``github/codeql-action`` dans le YAML ;
    2. présence d'un workflow explicitement identifié comme CodeQL
       par GitHub lorsque le contenu YAML n'est pas disponible.

    Args:
        workflows:
            Workflows normalisés à analyser.

    Returns:
        Analyse des automatisations détectées.
    """

    # CodeQL
    codeql_from_actions = detect_action_usage(
        workflows,
        ("github/codeql-action/",),
    )

    codeql_from_metadata = detect_workflows(
        workflows,
        (
            "codeql",
            "code ql",
        ),
    )

    codeql = merge_workflow_detections(
        codeql_from_actions,
        codeql_from_metadata,
    )

    # Dependency Review
    dependency_review = detect_action_usage(
        workflows,
        ("actions/dependency-review-action",),
    )

    # zizmor

    # zizmor peut être utilisé sous forme d'action GitHub ou être lancé
    # directement comme outil CLI. On combine donc la détection réelle
    # d'action avec les métadonnées du workflow.
    zizmor_from_actions = detect_action_usage(
        workflows,
        (
            "zizmorcore/zizmor-action",
            "woodruffw/zizmor",
        ),
    )

    zizmor_from_metadata = detect_workflows(
        workflows,
        ("zizmor",),
    )

    zizmor = merge_workflow_detections(
        zizmor_from_actions,
        zizmor_from_metadata,
    )

    # Outils liés aux dépendances
    dependency_tools_from_metadata = detect_workflows(
        workflows,
        (
            "dependency",
            "dependencies",
            "dependabot",
        ),
    )

    dependency_tools = merge_workflow_detections(
        dependency_review,
        dependency_tools_from_metadata,
    )

    # Tests / CI
    tests = detect_workflows(
        workflows,
        (
            "test",
            "tests",
            "testing",
            "pytest",
            "continuous integration",
            "pre-commit",
        ),
    )

    # Release / publication / déploiement
    releases = detect_workflows(
        workflows,
        (
            "release",
            "publish",
            "publication",
            "deploy",
            "deployment",
        ),
    )

    return SecurityAutomationAnalysis(
        codeql=codeql,
        zizmor=zizmor,
        dependency_review=dependency_review,
        dependency_tools=dependency_tools,
        tests=tests,
        releases=releases,
    )


def build_security_analysis(
    security_policy: tuple[bool, str | None],
    license_file: tuple[bool, str | None],
    code_of_conduct: tuple[bool, str | None],
    contributing_guide: tuple[bool, str | None],
    dependabot: tuple[bool, str | None],
    workflows: list[dict[str, Any]],
    workflow_contents: dict[str, str] | None = None,
    warnings: list[str] | None = None,
) -> SecurityAnalysis:
    """
    Construit l'analyse de sécurité complète d'un dépôt GitHub.

    Args:
        security_policy:
            Résultat de la recherche d'un fichier SECURITY.md.

        license_file:
            Résultat de la recherche d'un fichier de licence.

        code_of_conduct:
            Résultat de la recherche d'un code de conduite.

        contributing_guide:
            Résultat de la recherche d'un guide de contribution.

        dependabot:
            Résultat de la recherche d'une configuration Dependabot.

        workflows:
            Liste brute des workflows GitHub Actions.

        workflow_contents:
            Contenus YAML des workflows indexés par chemin.

        warnings:
            Avertissements éventuels rencontrés pendant la collecte.

    Returns:
        Analyse de sécurité normalisée.
    """

    github_actions = build_github_actions_status(
        workflows=workflows,
        workflow_contents=workflow_contents,
    )

    automation = build_security_automation_analysis(github_actions.workflows)

    return SecurityAnalysis(
        security_policy=build_file_status(security_policy),
        license=build_file_status(license_file),
        code_of_conduct=build_file_status(code_of_conduct),
        contributing_guide=build_file_status(contributing_guide),
        dependabot=build_file_status(dependabot),
        github_actions=github_actions,
        automation=automation,
        warnings=warnings or [],
    )
