"""
Tests de robustesse de la collecte GitHub et du client HTTP.
"""

from __future__ import annotations

import base64

import httpx
import pytest

from gitrecon.github.client import (
    GitHubAPIError,
    GitHubClient,
)
from gitrecon.github.security import (
    get_github_actions_workflow_contents,
    get_repository_file_content,
    repository_file_exists,
)


class FakeGitHubClient:
    """
    Client minimal utilisé pour tester la collecte sans accès réseau.
    """

    def __init__(
        self,
        responses: dict[str, object],
    ) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(
        self,
        endpoint: str,
        params=None,
    ):
        self.calls.append(endpoint)

        response = self.responses[endpoint]

        if isinstance(response, Exception):
            raise response

        return response


def test_github_api_error_exposes_status_code() -> None:
    request = httpx.Request(
        "GET",
        "https://api.github.com/repos/owner/repository",
    )

    response = httpx.Response(
        404,
        request=request,
        json={
            "message": "Not Found",
        },
    )

    client = GitHubClient.__new__(GitHubClient)

    with pytest.raises(GitHubAPIError) as exc_info:
        client._handle_response(response)

    error = exc_info.value

    assert error.status_code == 404
    assert error.url == "https://api.github.com/repos/owner/repository"
    assert "Not Found" in str(error)


def test_repository_file_exists_uses_status_code_for_404() -> None:
    first_endpoint = "/repos/owner/repository/contents/SECURITY.md"

    second_endpoint = "/repos/owner/repository/contents/.github/SECURITY.md"

    client = FakeGitHubClient(
        {
            first_endpoint: GitHubAPIError(
                "Not Found",
                status_code=404,
            ),
            second_endpoint: {
                "name": "SECURITY.md",
            },
        }
    )

    result = repository_file_exists(
        client=client,
        owner="owner",
        repository="repository",
        paths=(
            "SECURITY.md",
            ".github/SECURITY.md",
        ),
    )

    assert result == (
        True,
        ".github/SECURITY.md",
    )


def test_repository_file_exists_reraises_non_404() -> None:
    endpoint = "/repos/owner/repository/contents/SECURITY.md"

    client = FakeGitHubClient(
        {
            endpoint: GitHubAPIError(
                "Forbidden",
                status_code=403,
            )
        }
    )

    with pytest.raises(GitHubAPIError) as exc_info:
        repository_file_exists(
            client=client,
            owner="owner",
            repository="repository",
            paths=("SECURITY.md",),
        )

    assert exc_info.value.status_code == 403


def test_repository_file_content_decodes_valid_base64() -> None:
    endpoint = "/repos/owner/repository/contents/.github/workflows/test.yml"

    encoded = base64.b64encode(b"name: Test\n").decode("ascii")

    client = FakeGitHubClient(
        {
            endpoint: {
                "encoding": "base64",
                "content": encoded,
            }
        }
    )

    content = get_repository_file_content(
        client=client,
        owner="owner",
        repository="repository",
        path=".github/workflows/test.yml",
    )

    assert content == "name: Test\n"


def test_repository_file_content_accepts_github_base64_line_breaks() -> None:
    endpoint = "/repos/owner/repository/contents/.github/workflows/test.yml"

    encoded = base64.b64encode(b"name: Test\n").decode("ascii")

    wrapped = f"{encoded[:4]}\n{encoded[4:]}"

    client = FakeGitHubClient(
        {
            endpoint: {
                "encoding": "base64",
                "content": wrapped,
            }
        }
    )

    content = get_repository_file_content(
        client=client,
        owner="owner",
        repository="repository",
        path=".github/workflows/test.yml",
    )

    assert content == "name: Test\n"


def test_repository_file_content_rejects_invalid_base64() -> None:
    endpoint = "/repos/owner/repository/contents/.github/workflows/test.yml"

    client = FakeGitHubClient(
        {
            endpoint: {
                "encoding": "base64",
                "content": "%%%%not-base64%%%%",
            }
        }
    )

    content = get_repository_file_content(
        client=client,
        owner="owner",
        repository="repository",
        path=".github/workflows/test.yml",
    )

    assert content is None


def test_workflow_contents_only_fetches_repository_yaml_workflows() -> None:
    workflow_path = ".github/workflows/test.yml"

    endpoint = f"/repos/owner/repository/contents/{workflow_path}"

    encoded = base64.b64encode(b"name: Test\n").decode("ascii")

    client = FakeGitHubClient(
        {
            endpoint: {
                "encoding": "base64",
                "content": encoded,
            }
        }
    )

    workflows = [
        {
            "path": workflow_path,
        },
        {
            "path": "dynamic/dependabot/update-graph",
        },
        {
            "path": ".github/workflows/readme.txt",
        },
        {
            "path": ".github/workflows/../outside.yml",
        },
    ]

    contents = get_github_actions_workflow_contents(
        client=client,
        owner="owner",
        repository="repository",
        workflows=workflows,
    )

    assert contents == {
        workflow_path: "name: Test\n",
    }

    assert client.calls == [
        endpoint,
    ]
