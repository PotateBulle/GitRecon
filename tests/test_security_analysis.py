"""
Tests du moteur d'analyse de sécurité GitHub Actions.

Ces tests vérifient le parsing des workflows, l'extraction des actions,
les permissions GitHub Actions, les règles de sécurité GitRecon et
plusieurs cas limites destinés à renforcer la robustesse du moteur.
"""

from __future__ import annotations

from gitrecon.analysis.security import (
    extract_actions,
    extract_uses_from_yaml,
    extract_workflow_permissions,
    is_full_commit_sha,
    load_workflow_yaml,
    normalize_workflow,
    split_action_reference,
)
from gitrecon.models.security import (
    FindingSeverity,
    WorkflowInfo,
    WorkflowPermissionLevel,
)


def build_workflow(
    content: str,
    name: str = "Security Test",
    path: str = ".github/workflows/security-test.yml",
) -> WorkflowInfo:
    """
    Construit un workflow normalisé utilisé dans les tests.
    """

    workflow = {
        "name": name,
        "path": path,
        "state": "active",
    }

    return normalize_workflow(
        workflow=workflow,
        content=content,
    )


def get_rule_ids(
    workflow: WorkflowInfo,
) -> list[str]:
    """
    Retourne les identifiants des findings d'un workflow.
    """

    return [
        finding.rule_id
        for finding in workflow.findings
    ]


def get_findings_by_rule(
    workflow: WorkflowInfo,
    rule_id: str,
):
    """
    Retourne les findings correspondant à une règle.
    """

    return [
        finding
        for finding in workflow.findings
        if finding.rule_id == rule_id
    ]


# YAML


def test_load_valid_workflow_yaml() -> None:
    content = """
name: Test

jobs:
  test:
    runs-on: ubuntu-latest
"""

    document = load_workflow_yaml(content)

    assert document is not None
    assert document["name"] == "Test"
    assert "jobs" in document


def test_invalid_yaml_returns_none() -> None:
    content = """
name: Test

jobs:
  test:
    - invalid:
      yaml:
     broken
"""

    document = load_workflow_yaml(content)

    assert document is None


def test_empty_yaml_returns_none() -> None:
    assert load_workflow_yaml("") is None


def test_yaml_list_root_returns_none() -> None:
    content = """
- one
- two
- three
"""

    assert load_workflow_yaml(content) is None


# uses


def test_extract_uses_from_yaml() -> None:
    content = """
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
"""

    uses = extract_uses_from_yaml(content)

    assert uses == [
        "actions/checkout@v4",
        "astral-sh/setup-uv@v6",
    ]


def test_extract_uses_removes_duplicates() -> None:
    content = """
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
"""

    uses = extract_uses_from_yaml(content)

    assert uses == [
        "actions/checkout@v4",
    ]


def test_extract_actions_ignores_local_actions() -> None:
    uses = [
        "./.github/actions/local",
        "actions/checkout@v4",
    ]

    actions = extract_actions(uses)

    assert actions == [
        "actions/checkout",
    ]


def test_extract_actions_ignores_docker_references() -> None:
    uses = [
        "docker://alpine:latest",
        "actions/checkout@v4",
    ]

    actions = extract_actions(uses)

    assert actions == [
        "actions/checkout",
    ]


# Références


def test_split_action_reference() -> None:
    resource, reference = split_action_reference(
        "actions/checkout@v4"
    )

    assert resource == "actions/checkout"
    assert reference == "v4"


def test_split_action_reference_without_version() -> None:
    resource, reference = split_action_reference(
        "actions/checkout"
    )

    assert resource == "actions/checkout"
    assert reference is None


def test_full_commit_sha_detection() -> None:
    reference = "1234567890abcdef1234567890abcdef12345678"

    assert is_full_commit_sha(reference)


def test_short_sha_is_not_considered_pinned() -> None:
    reference = "1234567890abcdef"

    assert not is_full_commit_sha(reference)


def test_tag_is_not_considered_sha() -> None:
    assert not is_full_commit_sha("v4")


def test_uppercase_sha_is_considered_pinned() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: actions/checkout@ABCDEF1234567890ABCDEF1234567890ABCDEF12
"""
    )

    assert "GH-ACTIONS-002" not in get_rule_ids(workflow)


# Permissions


def test_extract_workflow_level_permissions() -> None:
    content = """
permissions:
  contents: read
  issues: write

jobs:
  test:
    runs-on: ubuntu-latest
"""

    document = load_workflow_yaml(content)

    assert document is not None

    permissions = extract_workflow_permissions(document)

    assert len(permissions) == 2

    assert permissions[0].scope == "contents"
    assert permissions[0].access == "read"
    assert (
        permissions[0].level
        == WorkflowPermissionLevel.WORKFLOW
    )

    assert permissions[1].scope == "issues"
    assert permissions[1].access == "write"


def test_extract_job_level_permissions() -> None:
    content = """
jobs:
  publish:
    permissions:
      contents: write
      id-token: write
"""

    document = load_workflow_yaml(content)

    assert document is not None

    permissions = extract_workflow_permissions(document)

    assert len(permissions) == 2

    for permission in permissions:
        assert (
            permission.level
            == WorkflowPermissionLevel.JOB
        )
        assert permission.job == "publish"


def test_extract_write_all_permission() -> None:
    content = """
permissions: write-all

jobs:
  test:
    runs-on: ubuntu-latest
"""

    document = load_workflow_yaml(content)

    assert document is not None

    permissions = extract_workflow_permissions(document)

    assert len(permissions) == 1

    permission = permissions[0]

    assert permission.scope == "*"
    assert permission.access == "write-all"
    assert (
        permission.level
        == WorkflowPermissionLevel.WORKFLOW
    )


def test_permissions_can_exist_at_workflow_and_job_level() -> None:
    content = """
permissions:
  contents: read

jobs:
  publish:
    permissions:
      contents: write
"""

    document = load_workflow_yaml(content)

    assert document is not None

    permissions = extract_workflow_permissions(document)

    assert len(permissions) == 2

    assert (
        permissions[0].level
        == WorkflowPermissionLevel.WORKFLOW
    )

    assert (
        permissions[1].level
        == WorkflowPermissionLevel.JOB
    )


def test_invalid_permission_access_is_ignored() -> None:
    workflow = build_workflow(
        """
permissions:
  contents: execute
"""
    )

    assert workflow.permissions == []


def test_invalid_scalar_permission_is_ignored() -> None:
    workflow = build_workflow(
        """
permissions: admin
"""
    )

    assert workflow.permissions == []


# GH-ACTIONS-001


def test_detect_main_branch_reference() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: example/action@main
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-001",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.HIGH
    )
    assert findings[0].evidence == "example/action@main"


def test_detect_master_branch_reference() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: example/action@master
"""
    )

    assert "GH-ACTIONS-001" in get_rule_ids(workflow)


# GH-ACTIONS-002


def test_detect_unpinned_action_tag() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-002",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.MEDIUM
    )


def test_full_sha_does_not_trigger_unpinned_rule() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
"""
    )

    assert "GH-ACTIONS-002" not in get_rule_ids(workflow)


def test_main_does_not_trigger_duplicate_unpinned_rule() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: example/action@main
"""
    )

    rule_ids = get_rule_ids(workflow)

    assert "GH-ACTIONS-001" in rule_ids
    assert "GH-ACTIONS-002" not in rule_ids


def test_action_without_reference_triggers_unpinned_rule() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: vendor/action
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-002",
    )

    assert len(findings) == 1
    assert findings[0].evidence == "vendor/action"


def test_action_without_reference_can_be_third_party() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: vendor/action
"""
    )

    rule_ids = get_rule_ids(workflow)

    assert "GH-ACTIONS-002" in rule_ids
    assert "GH-ACTIONS-003" in rule_ids


# GH-ACTIONS-003


def test_detect_third_party_action_as_info() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: astral-sh/setup-uv@1234567890abcdef1234567890abcdef12345678
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-003",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.INFO
    )


def test_github_first_party_action_is_not_third_party() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
"""
    )

    assert "GH-ACTIONS-003" not in get_rule_ids(workflow)


# GH-ACTIONS-004


def test_detect_workflow_write_all() -> None:
    workflow = build_workflow(
        """
permissions: write-all

jobs:
  test:
    runs-on: ubuntu-latest
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-004",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.HIGH
    )


def test_detect_job_write_all() -> None:
    workflow = build_workflow(
        """
jobs:
  release:
    permissions: write-all
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-004",
    )

    assert len(findings) == 1
    assert "job: release" in findings[0].evidence


# GH-ACTIONS-005


def test_detect_pull_request_target() -> None:
    workflow = build_workflow(
        """
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-005",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.MEDIUM
    )


def test_push_event_does_not_trigger_pull_request_target() -> None:
    workflow = build_workflow(
        """
on:
  push:

jobs:
  test:
    runs-on: ubuntu-latest
"""
    )

    assert "GH-ACTIONS-005" not in get_rule_ids(workflow)


# GH-ACTIONS-006


def test_detect_contents_write() -> None:
    workflow = build_workflow(
        """
permissions:
  contents: write

jobs:
  test:
    runs-on: ubuntu-latest
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-006",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.MEDIUM
    )


def test_contents_read_does_not_trigger_rule() -> None:
    workflow = build_workflow(
        """
permissions:
  contents: read
"""
    )

    assert "GH-ACTIONS-006" not in get_rule_ids(workflow)


# GH-ACTIONS-007


def test_detect_pull_requests_write() -> None:
    workflow = build_workflow(
        """
permissions:
  pull-requests: write
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-007",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.LOW
    )


# GH-ACTIONS-008


def test_detect_issues_write() -> None:
    workflow = build_workflow(
        """
permissions:
  issues: write
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-008",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.LOW
    )


# GH-ACTIONS-009


def test_detect_id_token_write() -> None:
    workflow = build_workflow(
        """
permissions:
  id-token: write
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-009",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.MEDIUM
    )


# GH-ACTIONS-010


def test_detect_packages_write() -> None:
    workflow = build_workflow(
        """
permissions:
  packages: write
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-010",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.LOW
    )


# GH-ACTIONS-011


def test_pull_request_target_with_write_permission_is_high() -> None:
    workflow = build_workflow(
        """
on:
  pull_request_target:

permissions:
  contents: write
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-011",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.HIGH
    )


def test_pull_request_target_without_write_permission_does_not_trigger_011() -> None:
    workflow = build_workflow(
        """
on:
  pull_request_target:

permissions:
  contents: read
"""
    )

    assert "GH-ACTIONS-011" not in get_rule_ids(workflow)


def test_pull_request_target_with_job_write_permission_triggers_011() -> None:
    workflow = build_workflow(
        """
on:
  pull_request_target:

jobs:
  publish:
    permissions:
      packages: write
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-011",
    )

    assert len(findings) == 1
    assert "packages: write" in findings[0].evidence


def test_pull_request_target_with_write_all_triggers_011() -> None:
    workflow = build_workflow(
        """
on:
  pull_request_target:

permissions: write-all
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-011",
    )

    assert len(findings) == 1
    assert (
        findings[0].severity
        == FindingSeverity.HIGH
    )


# Robustesse


def test_read_only_permissions_generate_no_permission_findings() -> None:
    workflow = build_workflow(
        """
permissions:
  contents: read
  issues: read
  pull-requests: read
  packages: read
"""
    )

    permission_rules = {
        "GH-ACTIONS-004",
        "GH-ACTIONS-006",
        "GH-ACTIONS-007",
        "GH-ACTIONS-008",
        "GH-ACTIONS-009",
        "GH-ACTIONS-010",
        "GH-ACTIONS-011",
    }

    assert not (
        permission_rules
        & set(get_rule_ids(workflow))
    )


def test_local_action_generates_no_reference_findings() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: ./.github/actions/local
"""
    )

    rule_ids = set(get_rule_ids(workflow))

    assert "GH-ACTIONS-001" not in rule_ids
    assert "GH-ACTIONS-002" not in rule_ids
    assert "GH-ACTIONS-003" not in rule_ids


def test_docker_reference_generates_no_action_findings() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: docker://alpine:latest
"""
    )

    rule_ids = set(get_rule_ids(workflow))

    assert "GH-ACTIONS-001" not in rule_ids
    assert "GH-ACTIONS-002" not in rule_ids
    assert "GH-ACTIONS-003" not in rule_ids


def test_workflow_without_content_does_not_crash() -> None:
    workflow = normalize_workflow(
        workflow={
            "name": "Unavailable",
            "path": ".github/workflows/unavailable.yml",
            "state": "active",
        },
        content=None,
    )

    assert workflow.content_available is False
    assert workflow.actions == []
    assert workflow.permissions == []
    assert workflow.findings == []


def test_invalid_job_structure_does_not_crash() -> None:
    workflow = build_workflow(
        """
jobs:
  test: invalid
"""
    )

    assert workflow.permissions == []


def test_empty_job_name_does_not_crash() -> None:
    workflow = build_workflow(
        """
jobs:
  "":
    permissions:
      contents: write
"""
    )

    assert workflow.permissions == []
    assert workflow.findings == []


def test_duplicate_uses_do_not_create_duplicate_findings() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
"""
    )

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-002",
    )

    assert len(findings) == 1


def test_whitespace_in_action_reference_is_normalized() -> None:
    workflow = build_workflow(
        """
jobs:
  test:
    steps:
      - uses: "  actions/checkout@v4  "
"""
    )

    assert workflow.uses == [
        "actions/checkout@v4",
    ]

    findings = get_findings_by_rule(
        workflow,
        "GH-ACTIONS-002",
    )

    assert len(findings) == 1


def test_malformed_permissions_type_does_not_crash() -> None:
    workflow = build_workflow(
        """
permissions:
  - contents
  - issues
"""
    )

    assert workflow.permissions == []


def test_malformed_jobs_list_does_not_crash() -> None:
    workflow = build_workflow(
        """
jobs:
  - test
  - publish
"""
    )

    assert workflow.permissions == []


def test_complete_security_scenario() -> None:
    workflow = build_workflow(
        """
on:
  pull_request_target:

permissions:
  contents: write
  issues: write

jobs:
  publish:
    permissions:
      id-token: write
      packages: write

    steps:
      - uses: actions/checkout@v4
      - uses: example/action@main
      - uses: vendor/tool@1234567890abcdef1234567890abcdef12345678
"""
    )

    rule_ids = set(get_rule_ids(workflow))

    assert "GH-ACTIONS-001" in rule_ids
    assert "GH-ACTIONS-002" in rule_ids
    assert "GH-ACTIONS-003" in rule_ids
    assert "GH-ACTIONS-005" in rule_ids
    assert "GH-ACTIONS-006" in rule_ids
    assert "GH-ACTIONS-008" in rule_ids
    assert "GH-ACTIONS-009" in rule_ids
    assert "GH-ACTIONS-010" in rule_ids
    assert "GH-ACTIONS-011" in rule_ids