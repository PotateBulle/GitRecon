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

VALID_PERMISSION_ACCESS = {
    "read",
    "write",
    "none",
    "read-all",
    "write-all",
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

    if not isinstance(content, str):
        return None

    if not content.strip():
        return None

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


def normalize_action_reference(
    value: str,
) -> str:
    """
    Normalise une référence ``uses``.
    """

    return value.strip()


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

    normalized = normalize_action_reference(value)

    return normalized.rsplit("@", maxsplit=1)[0].strip()


def is_local_action(
    value: str,
) -> bool:
    """
    Indique si une référence correspond à une action locale.
    """

    return normalize_action_reference(value).startswith("./")


def is_docker_action(
    value: str,
) -> bool:
    """
    Indique si une référence correspond directement à une image Docker.
    """

    return normalize_action_reference(value).lower().startswith("docker://")


def extract_actions(
    uses: list[str],
) -> list[str]:
    """
    Extrait les actions GitHub externes.
    """

    actions: list[str] = []

    for value in uses:
        if not isinstance(value, str):
            continue

        normalized = normalize_action_reference(value)

        if not normalized:
            continue

        if is_local_action(normalized):
            continue

        if is_docker_action(normalized):
            continue

        action = normalize_action_name(normalized)

        if action and action not in actions:
            actions.append(action)

    return actions


def split_action_reference(
    value: str,
) -> tuple[str, str | None]:
    """
    Sépare une référence GitHub Actions de sa version.
    """

    normalized = normalize_action_reference(value)

    if "@" not in normalized:
        return normalized, None

    resource, reference = normalized.rsplit("@", maxsplit=1)

    resource = resource.strip()
    reference = reference.strip()

    if not reference:
        return resource, None

    return resource, reference


def is_full_commit_sha(
    reference: str,
) -> bool:
    """
    Vérifie si une référence correspond à un SHA Git complet.
    """

    if not isinstance(reference, str):
        return False

    return bool(FULL_COMMIT_SHA_PATTERN.fullmatch(reference.strip()))


def get_action_owner(
    resource: str,
) -> str | None:
    """
    Extrait le propriétaire d'une action ou d'un workflow réutilisable.
    """

    normalized = resource.strip().strip("/")

    if not normalized:
        return None

    parts = normalized.split("/")

    if len(parts) < 2:
        return None

    owner = parts[0].strip().lower()

    if not owner:
        return None

    return owner


def normalize_permission_access(
    value: Any,
) -> str | None:
    """
    Normalise la valeur d'une permission GitHub Actions.
    """

    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    if normalized not in VALID_PERMISSION_ACCESS:
        return None

    return normalized


def extract_permission_block(
    value: Any,
    level: WorkflowPermissionLevel,
    job: str | None = None,
) -> list[WorkflowPermission]:
    """
    Extrait les permissions d'un bloc ``permissions``.
    """

    permissions: list[WorkflowPermission] = []

    if isinstance(value, str):
        access = normalize_permission_access(value)

        if access not in {
            "read-all",
            "write-all",
        }:
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

        normalized_scope = scope.strip().lower()

        if not normalized_scope:
            continue

        access = normalize_permission_access(access_value)

        if access not in {
            "read",
            "write",
            "none",
        }:
            continue

        permissions.append(
            WorkflowPermission(
                scope=normalized_scope,
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

        normalized_job_name = job_name.strip()

        if not normalized_job_name:
            continue

        if not isinstance(job_data, dict):
            continue

        if "permissions" not in job_data:
            continue

        permissions.extend(
            extract_permission_block(
                value=job_data["permissions"],
                level=WorkflowPermissionLevel.JOB,
                job=normalized_job_name,
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


def deduplicate_findings(
    findings: list[SecurityFinding],
) -> list[SecurityFinding]:
    """
    Supprime les findings identiques.

    Deux findings sont considérés comme identiques lorsqu'ils partagent
    la même règle, le même workflow, le même chemin et la même preuve.
    """

    unique_findings: list[SecurityFinding] = []

    seen: set[
        tuple[
            str,
            str | None,
            str | None,
            str | None,
        ]
    ] = set()

    for finding in findings:
        key = (
            finding.rule_id,
            finding.workflow,
            finding.path,
            finding.evidence,
        )

        if key in seen:
            continue

        seen.add(key)
        unique_findings.append(finding)

    return unique_findings


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

        resource, reference = split_action_reference(value)

        if not resource:
            continue

        # Référence absente
        if reference is None:
            findings.append(
                SecurityFinding(
                    rule_id="GH-ACTIONS-002",
                    title="Action non épinglée sur un SHA",
                    description=(
                        "La dépendance GitHub Actions ne contient "
                        "aucune référence explicite et n'est donc pas "
                        "épinglée sur un commit immuable."
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


def get_write_all_permissions(
    permissions: list[WorkflowPermission],
) -> list[WorkflowPermission]:
    """
    Retourne les déclarations ``permissions: write-all``.
    """

    return [
        permission
        for permission in permissions
        if (permission.scope == "*" and permission.access == "write-all")
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

    for permission in get_write_all_permissions(permissions):
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


def get_workflow_trigger(
    document: dict[str, Any],
) -> Any:
    """
    Retourne la configuration de déclenchement du workflow.

    PyYAML peut interpréter la clé YAML ``on`` comme le booléen ``True``.
    """

    if "on" in document:
        return document["on"]

    if True in document:
        return document[True]

    return None


def uses_pull_request_target(
    document: dict[str, Any],
) -> bool:
    """
    Vérifie si le workflow utilise l'événement pull_request_target.
    """

    trigger = get_workflow_trigger(document)

    if isinstance(trigger, str):
        return trigger.strip().lower() == "pull_request_target"

    if isinstance(trigger, list):
        return any(
            isinstance(item, str) and item.strip().lower() == "pull_request_target"
            for item in trigger
        )

    if isinstance(trigger, dict):
        return any(
            isinstance(key, str) and key.strip().lower() == "pull_request_target"
            for key in trigger
        )

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
        if permission.scope != "contents" or permission.access != "write":
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
        if permission.scope != "pull-requests" or permission.access != "write":
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
        if permission.scope != "issues" or permission.access != "write":
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
        if permission.scope != "id-token" or permission.access != "write":
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
        if permission.scope != "packages" or permission.access != "write":
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
    Exécute les règles liées aux permissions GitHub Actions.
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


def permission_grants_write(
    permission: WorkflowPermission,
) -> bool:
    """
    Indique si une permission accorde un accès en écriture.
    """

    return permission.access in {
        "write",
        "write-all",
    }


def get_write_permissions(
    permissions: list[WorkflowPermission],
) -> list[WorkflowPermission]:
    """
    Retourne les permissions accordant un accès en écriture.
    """

    return [
        permission for permission in permissions if permission_grants_write(permission)
    ]


def build_privileged_pull_request_findings(
    workflow_name: str,
    workflow_path: str | None,
    document: dict[str, Any],
    permissions: list[WorkflowPermission],
) -> list[SecurityFinding]:
    """
    Détecte la combinaison pull_request_target et permissions d'écriture.

    Cette combinaison augmente le niveau de confiance nécessaire pour
    le workflow car pull_request_target s'exécute dans le contexte
    privilégié du dépôt cible.
    """

    if not uses_pull_request_target(document):
        return []

    write_permissions = get_write_permissions(permissions)

    if not write_permissions:
        return []

    evidence_values = [
        format_permission_evidence(permission) for permission in write_permissions
    ]

    evidence = "pull_request_target + " + ", ".join(evidence_values)

    return [
        SecurityFinding(
            rule_id="GH-ACTIONS-011",
            title=("pull_request_target avec permissions d'écriture"),
            description=(
                "Le workflow combine pull_request_target avec une ou "
                "plusieurs permissions d'écriture. Cette configuration "
                "peut augmenter l'impact d'une exécution non fiable dans "
                "le contexte privilégié du dépôt cible."
            ),
            severity=FindingSeverity.HIGH,
            workflow=workflow_name,
            path=workflow_path,
            evidence=evidence,
            recommendation=(
                "Réduire les permissions au minimum nécessaire et éviter "
                "d'exécuter du code provenant directement d'une pull "
                "request non fiable dans ce contexte."
            ),
        )
    ]


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

    # Contexte privilégié
    findings.extend(
        build_privileged_pull_request_findings(
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            document=document,
            permissions=permissions,
        )
    )

    return deduplicate_findings(findings)


def normalize_workflow(
    workflow: dict[str, Any],
    content: str | None = None,
) -> WorkflowInfo:
    """
    Transforme un workflow brut GitHub en modèle interne.
    """

    name = workflow.get("name")
    path = workflow.get("path")
    state = workflow.get("state")

    workflow_name = (
        name.strip() if isinstance(name, str) and name.strip() else "Workflow sans nom"
    )

    workflow_path = path.strip() if isinstance(path, str) and path.strip() else None

    workflow_state = state.strip() if isinstance(state, str) and state.strip() else None

    uses: list[str] = []
    permissions: list[WorkflowPermission] = []
    findings: list[SecurityFinding] = []

    content_available = isinstance(content, str) and bool(content.strip())

    if content_available:
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
        state=workflow_state,
        content_available=content_available,
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
        if not isinstance(workflow, dict):
            continue

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

    return any(
        keyword.lower() in searchable_content
        for keyword in keywords
        if isinstance(keyword, str) and keyword
    )


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

    normalized_prefixes = tuple(
        prefix.lower()
        for prefix in action_prefixes
        if isinstance(prefix, str) and prefix
    )

    if not normalized_prefixes:
        return False

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

    seen: set[tuple[str, str | None]] = set()

    for detection in detections:
        for workflow in detection.workflows:
            key = (
                workflow.name,
                workflow.path,
            )

            if key in seen:
                continue

            seen.add(key)
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

    findings = deduplicate_findings(findings)

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
