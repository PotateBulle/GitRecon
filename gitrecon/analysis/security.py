"""
Analyse des informations de sécurité d'un dépôt GitHub.

Ce module transforme les données brutes collectées via l'API GitHub
en structures normalisées utilisables par GitRecon.

Le contenu YAML des workflows GitHub Actions est analysé afin
d'identifier les actions utilisées, les permissions déclarées,
certaines automatisations de sécurité et plusieurs configurations
pouvant nécessiter une attention particulière.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

import yaml

from gitrecon.models.security import (
    FindingSeverity,
    GitHubActionsStatus,
    SecurityAnalysis,
    SecurityAutomationAnalysis,
    SecurityFileStatus,
    SecurityFinding,
    WorkflowDetection,
    WorkflowInfo,
    WorkflowPermission,
    WorkflowPermissionLevel,
    WorkflowSecurityAnalysis,
)

FULL_COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")

FIRST_PARTY_ACTION_OWNERS = {
    "actions",
    "github",
}


def build_file_status(
    result: tuple[bool, str | None],
) -> SecurityFileStatus:
    """
    Construit l'état normalisé d'un fichier de sécurité.
    """

    present, path = result

    return SecurityFileStatus(
        present=present,
        path=path,
    )


def load_workflow_yaml(
    content: str,
) -> dict[str, Any] | None:
    """
    Charge le contenu YAML d'un workflow GitHub Actions.

    Returns:
        Document YAML sous forme de dictionnaire ou ``None`` lorsque
        le contenu ne peut pas être interprété.
    """

    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        return None

    if not isinstance(document, dict):
        return None

    return document


def extract_uses_from_document(
    document: dict[str, Any],
) -> list[str]:
    """
    Extrait toutes les directives ``uses`` d'un document YAML.
    """

    uses_values: list[str] = []

    def walk(value: Any) -> None:
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


def extract_uses_from_yaml(
    content: str,
) -> list[str]:
    """
    Extrait les directives ``uses`` depuis un workflow YAML.
    """

    document = load_workflow_yaml(content)

    if document is None:
        return []

    return extract_uses_from_document(document)


def normalize_action_name(
    value: str,
) -> str:
    """
    Supprime la référence située après ``@``.

    Exemple :

        actions/checkout@v4

    devient :

        actions/checkout
    """

    return value.split("@", maxsplit=1)[0].strip()


def is_local_action(
    value: str,
) -> bool:
    """
    Indique si une référence correspond à une action locale.
    """

    return value.startswith("./")


def is_docker_action(
    value: str,
) -> bool:
    """
    Indique si une référence correspond directement à une image Docker.
    """

    return value.startswith("docker://")


def extract_actions(
    uses: list[str],
) -> list[str]:
    """
    Extrait les actions GitHub externes.
    """

    actions: list[str] = []

    for value in uses:
        if is_local_action(value):
            continue

        if is_docker_action(value):
            continue

        action = normalize_action_name(value)

        if action and action not in actions:
            actions.append(action)

    return actions


def split_action_reference(
    value: str,
) -> tuple[str, str | None]:
    """
    Sépare une référence GitHub Actions de sa version.
    """

    if "@" not in value:
        return value.strip(), None

    resource, reference = value.rsplit("@", maxsplit=1)

    return resource.strip(), reference.strip()


def is_full_commit_sha(
    reference: str,
) -> bool:
    """
    Vérifie si une référence correspond à un SHA Git complet.
    """

    return bool(FULL_COMMIT_SHA_PATTERN.fullmatch(reference))


def get_action_owner(
    resource: str,
) -> str | None:
    """
    Extrait le propriétaire d'une action ou d'un workflow réutilisable.
    """

    parts = resource.split("/")

    if len(parts) < 2:
        return None

    return parts[0].lower()


def normalize_permission_access(
    value: Any,
) -> str | None:
    """
    Normalise la valeur d'une permission GitHub Actions.
    """

    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    if not normalized:
        return None

    return normalized


def extract_permission_block(
    value: Any,
    level: WorkflowPermissionLevel,
    job: str | None = None,
) -> list[WorkflowPermission]:
    """
    Extrait les permissions d'un bloc ``permissions``.

    GitHub accepte notamment :

        permissions: read-all

        permissions: write-all

    ou :

        permissions:
          contents: read
          issues: write
    """

    permissions: list[WorkflowPermission] = []

    if isinstance(value, str):
        access = normalize_permission_access(value)

        if access is None:
            return []

        permissions.append(
            WorkflowPermission(
                scope="*",
                access=access,
                level=level,
                job=job,
            )
        )

        return permissions

    if not isinstance(value, dict):
        return []

    for scope, access_value in value.items():
        if not isinstance(scope, str):
            continue

        access = normalize_permission_access(access_value)

        if access is None:
            continue

        permissions.append(
            WorkflowPermission(
                scope=scope.strip().lower(),
                access=access,
                level=level,
                job=job,
            )
        )

    return permissions


def extract_workflow_permissions(
    document: dict[str, Any],
) -> list[WorkflowPermission]:
    """
    Extrait les permissions globales et celles définies par job.

    Returns:
        Permissions détectées dans le workflow.
    """

    permissions: list[WorkflowPermission] = []

    # Workflow
    if "permissions" in document:
        permissions.extend(
            extract_permission_block(
                value=document["permissions"],
                level=WorkflowPermissionLevel.WORKFLOW,
            )
        )

    # Jobs
    jobs = document.get("jobs")

    if not isinstance(jobs, dict):
        return permissions

    for job_name, job_data in jobs.items():
        if not isinstance(job_name, str):
            continue

        if not isinstance(job_data, dict):
            continue

        if "permissions" not in job_data:
            continue

        permissions.extend(
            extract_permission_block(
                value=job_data["permissions"],
                level=WorkflowPermissionLevel.JOB,
                job=job_name,
            )
        )

    return permissions


def format_permission_evidence(
    permission: WorkflowPermission,
) -> str:
    """
    Construit une preuve lisible pour une permission.
    """

    value = f"{permission.scope}: {permission.access}"

    if permission.level == WorkflowPermissionLevel.JOB and permission.job:
        return f"{value} (job: {permission.job})"

    return value


def build_mutable_reference_findings(
    workflow_name: str,
    workflow_path: str | None,
    uses: list[str],
) -> list[SecurityFinding]:
    """
    Recherche les références basées sur main ou master.
    """

    findings: list[SecurityFinding] = []

    for value in uses:
        if is_local_action(value):
            continue

        if is_docker_action(value):
            continue

        _, reference = split_action_reference(value)

        if reference is None:
            continue

        if reference.lower() not in {
            "main",
            "master",
        }:
            continue

        findings.append(
            SecurityFinding(
                rule_id="GH-ACTIONS-001",
                title="Référence Git mutable utilisée",
                description=(
                    "Le workflow utilise une action ou un workflow "
                    "réutilisable référencé directement sur une branche "
                    "mutable."
                ),
                severity=FindingSeverity.HIGH,
                workflow=workflow_name,
                path=workflow_path,
                evidence=value,
                recommendation=(
                    "Épingler la dépendance sur un SHA de commit complet et vérifié."
                ),
            )
        )

    return findings


def build_unpinned_action_findings(
    workflow_name: str,
    workflow_path: str | None,
    uses: list[str],
) -> list[SecurityFinding]:
    """
    Recherche les actions qui ne sont pas épinglées sur un SHA complet.
    """

    findings: list[SecurityFinding] = []

    for value in uses:
        if is_local_action(value):
            continue

        if is_docker_action(value):
            continue

        _, reference = split_action_reference(value)

        if reference is None:
            continue

        # Branche mutable
        if reference.lower() in {
            "main",
            "master",
        }:
            continue

        if is_full_commit_sha(reference):
            continue

        findings.append(
            SecurityFinding(
                rule_id="GH-ACTIONS-002",
                title="Action non épinglée sur un SHA",
                description=(
                    "La dépendance GitHub Actions utilise une référence "
                    "qui peut évoluer dans le temps."
                ),
                severity=FindingSeverity.MEDIUM,
                workflow=workflow_name,
                path=workflow_path,
                evidence=value,
                recommendation=(
                    "Utiliser le SHA complet d'un commit de confiance "
                    "pour rendre la référence immuable."
                ),
            )
        )

    return findings


def build_third_party_action_findings(
    workflow_name: str,
    workflow_path: str | None,
    uses: list[str],
) -> list[SecurityFinding]:
    """
    Identifie les actions provenant d'un propriétaire tiers.

    Cette détection est informative et représente une dépendance
    supplémentaire dans la chaîne de confiance du workflow.
    """

    findings: list[SecurityFinding] = []

    for value in uses:
        if is_local_action(value):
            continue

        if is_docker_action(value):
            continue

        resource, _ = split_action_reference(value)

        owner = get_action_owner(resource)

        if owner is None:
            continue

        if owner in FIRST_PARTY_ACTION_OWNERS:
            continue

        findings.append(
            SecurityFinding(
                rule_id="GH-ACTIONS-003",
                title="Dépendance GitHub Actions tierce",
                description=(
                    "Le workflow utilise une action ou un workflow "
                    "réutilisable maintenu par un propriétaire tiers."
                ),
                severity=FindingSeverity.INFO,
                workflow=workflow_name,
                path=workflow_path,
                evidence=value,
                recommendation=(
                    "Vérifier la provenance et la maintenance de cette "
                    "dépendance, et privilégier une référence épinglée "
                    "sur un SHA de commit complet."
                ),
            )
        )

    return findings


def contains_write_all(
    permissions: list[WorkflowPermission],
) -> list[WorkflowPermission]:
    """
    Retourne les déclarations ``permissions: write-all`` détectées.
    """

    return [
        permission
        for permission in permissions
        if permission.scope == "*" and permission.access == "write-all"
    ]


def build_write_all_findings(
    workflow_name: str,
    workflow_path: str | None,
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Génère les findings associés à ``permissions: write-all``.
    """

    findings: list[SecurityFinding] = []

    for permission in contains_write_all(permissions):
        if permission.level == WorkflowPermissionLevel.JOB and permission.job:
            evidence = f"permissions: write-all (job: {permission.job})"
        else:
            evidence = "permissions: write-all"

        findings.append(
            SecurityFinding(
                rule_id="GH-ACTIONS-004",
                title="Permissions globales en écriture",
                description=(
                    "Le workflow accorde l'ensemble des permissions "
                    "disponibles en écriture au token GitHub Actions."
                ),
                severity=FindingSeverity.HIGH,
                workflow=workflow_name,
                path=workflow_path,
                evidence=evidence,
                recommendation=(
                    "Définir explicitement uniquement les permissions "
                    "nécessaires au workflow ou au job concerné."
                ),
            )
        )

    return findings


def uses_pull_request_target(
    document: dict[str, Any],
) -> bool:
    """
    Vérifie si le workflow utilise l'événement pull_request_target.

    PyYAML peut interpréter la clé YAML ``on`` comme un booléen dans
    certains cas. Cette représentation est également prise en charge.
    """

    trigger = document.get("on")

    if trigger is None:
        trigger = document.get(True)

    if isinstance(trigger, str):
        return trigger == "pull_request_target"

    if isinstance(trigger, list):
        return "pull_request_target" in trigger

    if isinstance(trigger, dict):
        return "pull_request_target" in trigger

    return False


def build_pull_request_target_finding(
    workflow_name: str,
    workflow_path: str | None,
    document: dict[str, Any],
) -> list[SecurityFinding]:
    """
    Génère un finding lorsque pull_request_target est utilisé.
    """

    if not uses_pull_request_target(document):
        return []

    return [
        SecurityFinding(
            rule_id="GH-ACTIONS-005",
            title="Utilisation de pull_request_target",
            description=(
                "Le workflow utilise l'événement pull_request_target. "
                "Cet événement s'exécute dans le contexte du dépôt cible "
                "et peut disposer de permissions ou de secrets sensibles."
            ),
            severity=FindingSeverity.MEDIUM,
            workflow=workflow_name,
            path=workflow_path,
            evidence="pull_request_target",
            recommendation=(
                "Éviter d'exécuter directement du code non fiable "
                "provenant de la pull request dans ce contexte."
            ),
        )
    ]


def build_permission_finding(
    workflow_name: str,
    workflow_path: str | None,
    permission: WorkflowPermission,
    rule_id: str,
    title: str,
    description: str,
    severity: FindingSeverity,
    recommendation: str,
) -> SecurityFinding:
    """
    Construit un finding associé à une permission GitHub Actions.
    """

    return SecurityFinding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        workflow=workflow_name,
        path=workflow_path,
        evidence=format_permission_evidence(permission),
        recommendation=recommendation,
    )


def build_contents_write_findings(
    workflow_name: str,
    workflow_path: str | None,
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Détecte la permission ``contents: write``.
    """

    findings: list[SecurityFinding] = []

    for permission in permissions:
        if permission.scope != "contents":
            continue

        if permission.access != "write":
            continue

        findings.append(
            build_permission_finding(
                workflow_name=workflow_name,
                workflow_path=workflow_path,
                permission=permission,
                rule_id="GH-ACTIONS-006",
                title="Permission contents en écriture",
                description=(
                    "Le workflow dispose d'un accès en écriture au contenu "
                    "du dépôt. Cette permission peut être légitime pour "
                    "certaines opérations de publication ou d'automatisation."
                ),
                severity=FindingSeverity.MEDIUM,
                recommendation=(
                    "Limiter contents: write aux workflows et aux jobs "
                    "qui doivent réellement modifier le contenu du dépôt."
                ),
            )
        )

    return findings


def build_pull_requests_write_findings(
    workflow_name: str,
    workflow_path: str | None,
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Détecte la permission ``pull-requests: write``.
    """

    findings: list[SecurityFinding] = []

    for permission in permissions:
        if permission.scope != "pull-requests":
            continue

        if permission.access != "write":
            continue

        findings.append(
            build_permission_finding(
                workflow_name=workflow_name,
                workflow_path=workflow_path,
                permission=permission,
                rule_id="GH-ACTIONS-007",
                title="Permission pull-requests en écriture",
                description=(
                    "Le workflow peut modifier certaines informations "
                    "associées aux pull requests."
                ),
                severity=FindingSeverity.LOW,
                recommendation=(
                    "Conserver cette permission uniquement lorsque "
                    "l'automatisation doit réellement modifier des "
                    "pull requests."
                ),
            )
        )

    return findings


def build_issues_write_findings(
    workflow_name: str,
    workflow_path: str | None,
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Détecte la permission ``issues: write``.
    """

    findings: list[SecurityFinding] = []

    for permission in permissions:
        if permission.scope != "issues":
            continue

        if permission.access != "write":
            continue

        findings.append(
            build_permission_finding(
                workflow_name=workflow_name,
                workflow_path=workflow_path,
                permission=permission,
                rule_id="GH-ACTIONS-008",
                title="Permission issues en écriture",
                description=("Le workflow peut modifier les issues du dépôt."),
                severity=FindingSeverity.LOW,
                recommendation=(
                    "Limiter issues: write aux automatisations ayant "
                    "réellement besoin de créer ou modifier des issues."
                ),
            )
        )

    return findings


def build_id_token_write_findings(
    workflow_name: str,
    workflow_path: str | None,
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Détecte la permission ``id-token: write``.
    """

    findings: list[SecurityFinding] = []

    for permission in permissions:
        if permission.scope != "id-token":
            continue

        if permission.access != "write":
            continue

        findings.append(
            build_permission_finding(
                workflow_name=workflow_name,
                workflow_path=workflow_path,
                permission=permission,
                rule_id="GH-ACTIONS-009",
                title="Permission OIDC id-token activée",
                description=(
                    "Le workflow peut demander un jeton OpenID Connect "
                    "GitHub Actions. Cette capacité est couramment utilisée "
                    "pour l'authentification sans secret auprès de services "
                    "externes."
                ),
                severity=FindingSeverity.MEDIUM,
                recommendation=(
                    "Limiter id-token: write aux jobs qui utilisent "
                    "réellement une authentification OIDC et vérifier "
                    "les politiques de confiance du fournisseur cible."
                ),
            )
        )

    return findings


def build_packages_write_findings(
    workflow_name: str,
    workflow_path: str | None,
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Détecte la permission ``packages: write``.
    """

    findings: list[SecurityFinding] = []

    for permission in permissions:
        if permission.scope != "packages":
            continue

        if permission.access != "write":
            continue

        findings.append(
            build_permission_finding(
                workflow_name=workflow_name,
                workflow_path=workflow_path,
                permission=permission,
                rule_id="GH-ACTIONS-010",
                title="Permission packages en écriture",
                description=(
                    "Le workflow peut publier ou modifier des paquets "
                    "associés au dépôt."
                ),
                severity=FindingSeverity.LOW,
                recommendation=(
                    "Limiter packages: write aux jobs chargés de la "
                    "publication ou de la gestion des paquets."
                ),
            )
        )

    return findings


def build_permission_findings(
    workflow_name: str,
    workflow_path: str | None,
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Exécute les règles V3.4 liées aux permissions GitHub Actions.
    """

    findings: list[SecurityFinding] = []

    findings.extend(
        build_contents_write_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            permissions=permissions,
        )
    )

    findings.extend(
        build_pull_requests_write_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            permissions=permissions,
        )
    )

    findings.extend(
        build_issues_write_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            permissions=permissions,
        )
    )

    findings.extend(
        build_id_token_write_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            permissions=permissions,
        )
    )

    findings.extend(
        build_packages_write_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            permissions=permissions,
        )
    )

    return findings


def analyze_workflow_findings(
    workflow_name: str,
    workflow_path: str | None,
    document: dict[str, Any],
    uses: list[str],
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Exécute les règles de sécurité sur un workflow.
    """

    findings: list[SecurityFinding] = []

    # Références
    findings.extend(
        build_mutable_reference_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            uses=uses,
        )
    )

    findings.extend(
        build_unpinned_action_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            uses=uses,
        )
    )

    findings.extend(
        build_third_party_action_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            uses=uses,
        )
    )

    # Permissions
    findings.extend(
        build_write_all_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            permissions=permissions,
        )
    )

    findings.extend(
        build_permission_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            permissions=permissions,
        )
    )

    # Événements
    findings.extend(
        build_pull_request_target_finding(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            document=document,
        )
    )

    return findings


def normalize_workflow(
    workflow: dict[str, Any],
    content: str | None = None,
) -> WorkflowInfo:
    """
    Transforme un workflow brut GitHub en modèle interne.

    Lorsque le contenu YAML est disponible, GitRecon extrait les
    directives ``uses``, les permissions et exécute les contrôles
    de sécurité.
    """

    name = workflow.get("name")
    path = workflow.get("path")
    state = workflow.get("state")

    workflow_name = (
        name.strip() if isinstance(name, str) and name.strip() else "Workflow sans nom"
    )

    workflow_path = path if isinstance(path, str) else None

    uses: list[str] = []
    permissions: list[WorkflowPermission] = []
    findings: list[SecurityFinding] = []

    if content is not None:
        document = load_workflow_yaml(content)

        if document is not None:
            uses = extract_uses_from_document(document)
            permissions = extract_workflow_permissions(document)

            findings = analyze_workflow_findings(
                workflow_name=workflow_name,
                workflow_path=workflow_path,
                document=document,
                uses=uses,
                permissions=permissions,
            )

    actions = extract_actions(uses)

    return WorkflowInfo(
        name=workflow_name,
        path=workflow_path,
        state=state if isinstance(state, str) else None,
        content_available=content is not None,
        actions=actions,
        uses=uses,
        permissions=permissions,
        findings=findings,
    )


def build_github_actions_status(
    workflows: list[dict[str, Any]],
    workflow_contents: dict[str, str] | None = None,
) -> GitHubActionsStatus:
    """
    Construit l'état normalisé de GitHub Actions.
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
    Recherche des mots-clés dans les métadonnées d'un workflow.
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
    Détecte les workflows utilisant certaines actions.
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
    Fusionne plusieurs résultats de détection sans doublons.
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
    Analyse les automatisations GitHub Actions détectées.
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

    # Dépendances
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

    # Tests
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

    # Publication
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


def build_workflow_security_analysis(
    workflows: list[WorkflowInfo],
) -> WorkflowSecurityAnalysis:
    """
    Agrège les findings générés pour l'ensemble des workflows.
    """

    findings: list[SecurityFinding] = []

    for workflow in workflows:
        findings.extend(workflow.findings)

    return WorkflowSecurityAnalysis(
        findings=findings,
        total=len(findings),
        critical=sum(
            finding.severity == FindingSeverity.CRITICAL for finding in findings
        ),
        high=sum(finding.severity == FindingSeverity.HIGH for finding in findings),
        medium=sum(finding.severity == FindingSeverity.MEDIUM for finding in findings),
        low=sum(finding.severity == FindingSeverity.LOW for finding in findings),
        info=sum(finding.severity == FindingSeverity.INFO for finding in findings),
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
    Construit l'analyse de sécurité complète du dépôt.
    """

    github_actions = build_github_actions_status(
        workflows=workflows,
        workflow_contents=workflow_contents,
    )

    automation = build_security_automation_analysis(github_actions.workflows)

    workflow_security = build_workflow_security_analysis(github_actions.workflows)

    return SecurityAnalysis(
        security_policy=build_file_status(security_policy),
        license=build_file_status(license_file),
        code_of_conduct=build_file_status(code_of_conduct),
        contributing_guide=build_file_status(contributing_guide),
        dependabot=build_file_status(dependabot),
        github_actions=github_actions,
        automation=automation,
        workflow_security=workflow_security,
        warnings=warnings or [],
    )
