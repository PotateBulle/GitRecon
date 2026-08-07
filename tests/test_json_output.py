"""
Tests de l'export JSON GitRecon.

Ces tests vérifient la sérialisation des modèles internes,
la génération du rapport JSON et l'écriture des fichiers
dans le dossier ``reports``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gitrecon.models.analysis import (
    LanguageInfo,
    RepositoryAnalysis,
)
from gitrecon.models.repository import RepositoryInfo
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
from gitrecon.output.json import (
    build_default_filename,
    build_json_report,
    get_report_path,
    normalize_output_filename,
    render_json_report,
    serialize_finding,
    serialize_permission,
    serialize_repository,
    serialize_security,
    serialize_workflow,
    write_json_report,
)


def build_repository() -> RepositoryInfo:
    """
    Construit un dépôt utilisé dans les tests.
    """

    return RepositoryInfo(
        name="flask",
        full_name="pallets/flask",
        owner="pallets",
        description="Test repository",
        private=False,
        fork=False,
        archived=False,
        default_branch="main",
        language="Python",
        stars=100,
        forks=20,
        open_issues=3,
        created_at="2020-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        pushed_at="2026-01-02T00:00:00Z",
    )


def build_analysis() -> RepositoryAnalysis:
    """
    Construit une analyse générale utilisée dans les tests.
    """

    return RepositoryAnalysis(
        languages=[
            LanguageInfo(
                name="Python",
                bytes=1000,
                percentage=100.0,
            )
        ],
        contributors_count=10,
        branches_count=2,
        releases_count=4,
        warnings=[],
    )


def build_workflow() -> WorkflowInfo:
    """
    Construit un workflow utilisé dans les tests.
    """

    permission = WorkflowPermission(
        scope="contents",
        access="write",
        level=WorkflowPermissionLevel.JOB,
        job="release",
    )

    finding = SecurityFinding(
        rule_id="GH-ACTIONS-006",
        title="Permission contents en écriture",
        description="Test finding",
        severity=FindingSeverity.MEDIUM,
        workflow="Publish",
        path=".github/workflows/publish.yml",
        evidence="contents: write (job: release)",
        recommendation="Limiter les permissions.",
    )

    return WorkflowInfo(
        name="Publish",
        path=".github/workflows/publish.yml",
        state="active",
        content_available=True,
        actions=[
            "actions/checkout",
        ],
        uses=[("actions/checkout@1234567890abcdef1234567890abcdef12345678")],
        permissions=[
            permission,
        ],
        findings=[
            finding,
        ],
    )


def build_security() -> SecurityAnalysis:
    """
    Construit une analyse de sécurité utilisée dans les tests.
    """

    workflow = build_workflow()

    empty_detection = WorkflowDetection(
        detected=False,
        workflows=[],
    )

    release_detection = WorkflowDetection(
        detected=True,
        workflows=[
            workflow,
        ],
    )

    automation = SecurityAutomationAnalysis(
        codeql=empty_detection,
        zizmor=empty_detection,
        dependency_review=empty_detection,
        dependency_tools=empty_detection,
        tests=empty_detection,
        releases=release_detection,
    )

    workflow_security = WorkflowSecurityAnalysis(
        findings=list(workflow.findings),
        total=1,
        critical=0,
        high=0,
        medium=1,
        low=0,
        info=0,
    )

    return SecurityAnalysis(
        security_policy=SecurityFileStatus(
            present=False,
            path=None,
        ),
        license=SecurityFileStatus(
            present=True,
            path="LICENSE",
        ),
        code_of_conduct=SecurityFileStatus(
            present=False,
            path=None,
        ),
        contributing_guide=SecurityFileStatus(
            present=False,
            path=None,
        ),
        dependabot=SecurityFileStatus(
            present=False,
            path=None,
        ),
        github_actions=GitHubActionsStatus(
            present=True,
            workflows_count=1,
            workflows=[
                workflow,
            ],
        ),
        automation=automation,
        workflow_security=workflow_security,
        warnings=[],
    )


def test_serialize_repository() -> None:
    repository = build_repository()

    result = serialize_repository(repository)

    assert result["name"] == "flask"
    assert result["full_name"] == "pallets/flask"
    assert result["owner"] == "pallets"
    assert result["stars"] == 100
    assert result["private"] is False


def test_serialize_permission() -> None:
    permission = WorkflowPermission(
        scope="contents",
        access="write",
        level=WorkflowPermissionLevel.JOB,
        job="release",
    )

    result = serialize_permission(permission)

    assert result == {
        "scope": "contents",
        "access": "write",
        "level": "job",
        "job": "release",
    }


def test_serialize_finding() -> None:
    finding = SecurityFinding(
        rule_id="GH-ACTIONS-006",
        title="Permission contents en écriture",
        description="Test",
        severity=FindingSeverity.MEDIUM,
        workflow="Publish",
        path=".github/workflows/publish.yml",
        evidence="contents: write",
        recommendation="Limiter les permissions.",
    )

    result = serialize_finding(finding)

    assert result["rule_id"] == "GH-ACTIONS-006"
    assert result["severity"] == "MEDIUM"
    assert result["workflow"] == "Publish"
    assert result["evidence"] == "contents: write"


def test_serialize_workflow() -> None:
    workflow = build_workflow()

    result = serialize_workflow(workflow)

    assert result["name"] == "Publish"
    assert result["content_available"] is True
    assert result["actions"] == [
        "actions/checkout",
    ]

    assert result["permissions"][0]["scope"] == "contents"
    assert result["findings"][0]["rule_id"] == "GH-ACTIONS-006"


def test_serialize_security() -> None:
    security = build_security()

    result = serialize_security(security)

    assert result["license"]["present"] is True
    assert result["license"]["path"] == "LICENSE"

    assert result["github_actions"]["present"] is True
    assert result["github_actions"]["workflows_count"] == 1

    assert result["workflow_security"]["total"] == 1
    assert result["workflow_security"]["medium"] == 1

    assert result["automation"]["releases"]["detected"] is True


def test_build_json_report() -> None:
    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    report = build_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
    )

    assert set(report) == {
        "repository",
        "analysis",
        "security",
    }

    assert report["repository"]["full_name"] == "pallets/flask"
    assert report["analysis"]["contributors_count"] == 10
    assert report["security"]["workflow_security"]["total"] == 1


def test_render_json_report_returns_valid_json() -> None:
    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    content = render_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
    )

    parsed = json.loads(content)

    assert parsed["repository"]["name"] == "flask"
    assert parsed["security"]["workflow_security"]["medium"] == 1


def test_render_json_report_preserves_unicode() -> None:
    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    security.workflow_security.findings[0].title = "Permission en écriture détectée"

    content = render_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
    )

    assert "écriture" in content
    assert "\\u00e9" not in content


def test_build_default_filename() -> None:
    repository = build_repository()

    filename = build_default_filename(repository)

    assert filename == "pallets-flask.json"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "report",
            "report.json",
        ),
        (
            "report.json",
            "report.json",
        ),
        (
            "REPORT.JSON",
            "REPORT.JSON",
        ),
        (
            "directory/report.json",
            "report.json",
        ),
        (
            "../../escape.json",
            "escape.json",
        ),
    ],
)
def test_normalize_output_filename(
    value: str,
    expected: str,
) -> None:
    assert normalize_output_filename(value) == expected


def test_get_report_path_uses_default_filename() -> None:
    repository = build_repository()

    path = get_report_path(
        repository=repository,
    )

    assert path == Path("reports/pallets-flask.json")


def test_get_report_path_with_custom_filename() -> None:
    repository = build_repository()

    path = get_report_path(
        repository=repository,
        filename="audit",
    )

    assert path == Path("reports/audit.json")


def test_get_report_path_confines_output_to_reports() -> None:
    repository = build_repository()

    path = get_report_path(
        repository=repository,
        filename="../../escape.json",
    )

    assert path == Path("reports/escape.json")


def test_write_json_report_creates_reports_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    path = write_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
    )

    assert path == Path("reports/pallets-flask.json")

    assert path.exists()
    assert path.is_file()


def test_write_json_report_creates_valid_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    path = write_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
    )

    content = path.read_text(encoding="utf-8")

    parsed = json.loads(content)

    assert parsed["repository"]["full_name"] == "pallets/flask"
    assert parsed["analysis"]["branches_count"] == 2


def test_write_json_report_uses_custom_filename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    path = write_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
        filename="flask-audit",
    )

    assert path == Path("reports/flask-audit.json")

    assert path.exists()


def test_write_json_report_confines_custom_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    path = write_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
        filename="../../outside.json",
    )

    assert path == Path("reports/outside.json")

    assert path.exists()

    assert not (tmp_path.parent / "outside.json").exists()


def test_write_json_report_ends_with_newline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    repository = build_repository()
    analysis = build_analysis()
    security = build_security()

    path = write_json_report(
        repository=repository,
        analysis=analysis,
        security=security,
    )

    content = path.read_text(encoding="utf-8")

    assert content.endswith("\n")
