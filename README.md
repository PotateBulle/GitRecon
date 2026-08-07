# GitRecon

[English](README.md) | [Français](README_FR.md)

GitRecon is a command-line repository intelligence and security analysis tool for GitHub.

It collects public repository metadata, inspects GitHub Actions workflows, analyzes workflow permissions and dependencies, detects security-relevant patterns, and can export the resulting analysis as structured JSON.

GitRecon is designed for defensive security analysis, repository auditing, GitHub Actions review, and CI/CD security assessment.

## Features

GitRecon currently provides:

- GitHub repository metadata collection
- Programming language analysis
- Contributor, branch, and release statistics
- Security-related file detection
- GitHub Actions workflow discovery
- Workflow YAML parsing
- GitHub Actions dependency extraction
- Workflow permission analysis
- GitHub Actions security findings
- Security automation detection
- JSON report export
- Automated test coverage with pytest

## Repository Analysis

GitRecon collects general information about a repository, including:

- Repository name and owner
- Description
- Default branch
- Main programming language
- Stars
- Forks
- Open issues
- Creation date
- Last update date
- Last push date
- Languages and their proportions
- Contributors
- Branches
- Releases

## Security Files

GitRecon checks for files commonly associated with repository security and project governance:

- `SECURITY.md`
- License files
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- Dependabot configuration

The goal is to provide a quick overview of the repository's security and maintenance posture.

## GitHub Actions Analysis

GitRecon discovers GitHub Actions workflows and analyzes their contents when the workflow YAML is accessible.

For each workflow, GitRecon can extract:

- Workflow name
- Workflow path
- Workflow state
- External actions
- Complete `uses:` references
- Explicit workflow permissions
- Explicit job permissions
- Security findings

Example action reference:

```text
actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
```

GitRecon distinguishes first-party GitHub Actions from third-party dependencies and checks how action references are pinned.

## GitHub Actions Security Rules

GitRecon currently implements the following rules:

| Rule | Severity | Description |
|---|---|---|
| `GH-ACTIONS-001` | HIGH | Action reference uses `@main` or `@master` |
| `GH-ACTIONS-002` | MEDIUM | Action is not pinned to a full commit SHA |
| `GH-ACTIONS-003` | INFO | Third-party GitHub Actions dependency |
| `GH-ACTIONS-004` | HIGH | `write-all` permission detected |
| `GH-ACTIONS-005` | MEDIUM | `pull_request_target` trigger detected |
| `GH-ACTIONS-006` | MEDIUM | `contents: write` permission detected |
| `GH-ACTIONS-007` | LOW | `pull-requests: write` permission detected |
| `GH-ACTIONS-008` | LOW | `issues: write` permission detected |
| `GH-ACTIONS-009` | MEDIUM | `id-token: write` permission detected |
| `GH-ACTIONS-010` | LOW | `packages: write` permission detected |
| `GH-ACTIONS-011` | HIGH | `pull_request_target` combined with write permissions |

These findings are security indicators and must be interpreted in context.

For example, `contents: write` may be legitimate for a release workflow, while `id-token: write` is commonly used for OpenID Connect authentication.

A finding does not automatically mean that a workflow is vulnerable.

## Security Automation Detection

GitRecon can identify repository automation related to:

- CodeQL
- Zizmor
- Dependency Review
- Dependency tooling
- Tests
- Release workflows

This provides a quick overview of the CI/CD and security mechanisms already present in a repository.

## Installation

Clone the repository:

```bash
git clone https://github.com/PotateBulle/GitRecon.git
cd GitRecon
```

Create a Python virtual environment:

```bash
python -m venv .venv
```

Activate it.

### Bash / Zsh

```bash
source .venv/bin/activate
```

### Fish

```fish
source .venv/bin/activate.fish
```

Install GitRecon in editable mode:

```bash
pip install -e .
```

Verify the installation:

```bash
gitrecon --help
```

## GitHub Token

GitRecon uses the GitHub API.

A GitHub token is recommended to benefit from higher API rate limits and access the endpoints required by the analysis.

Create a `.env` file at the root of the project:

```env
GITHUB_TOKEN=your_github_token
```

Never commit your `.env` file or GitHub token.

## Usage

Analyze a repository using the `owner/repository` format:

```bash
gitrecon scan owner/repository
```

A complete GitHub URL is also supported:

```bash
gitrecon scan https://github.com/owner/repository
```

URLs ending with `.git` are supported as well:

```bash
gitrecon scan https://github.com/owner/repository.git
```

## JSON Export

Starting with GitRecon v0.3.6, repository analysis can be exported as JSON.

Run:

```bash
gitrecon scan owner/repository --json
```

GitRecon automatically creates the `reports/` directory and generates a report named after the repository owner and repository name:

```text
reports/owner-repository.json
```

A custom file name can be specified with:

```bash
gitrecon scan owner/repository --json -o audit
```

Result:

```text
reports/audit.json
```

The `.json` extension is automatically added when necessary.

Generated reports are ignored by Git and are not intended to be committed to the repository.

## JSON Structure

A GitRecon JSON report contains three main sections:

```json
{
  "repository": {},
  "analysis": {},
  "security": {}
}
```

The security section contains information about:

```text
security
├── security_policy
├── license
├── code_of_conduct
├── contributing_guide
├── dependabot
├── github_actions
│   └── workflows
│       ├── actions
│       ├── uses
│       ├── permissions
│       └── findings
├── automation
├── workflow_security
└── warnings
```

This format makes GitRecon reports suitable for:

- Security tooling
- CI/CD pipelines
- Data processing
- Repository inventories
- Dashboards
- Further automated analysis

## Example Security Finding

```json
{
  "rule_id": "GH-ACTIONS-006",
  "title": "Permission contents en écriture",
  "description": "Le workflow dispose d'un accès en écriture au contenu du dépôt.",
  "severity": "MEDIUM",
  "workflow": "Publish",
  "path": ".github/workflows/publish.yaml",
  "evidence": "contents: write (job: create-release)",
  "recommendation": "Limiter contents: write aux workflows et aux jobs qui doivent réellement modifier le contenu du dépôt."
}
```

Some finding descriptions are currently generated in French because they come directly from GitRecon's internal security rules.

## Development

Run Ruff:

```bash
ruff check tests gitrecon
```

Format the project:

```bash
ruff format tests gitrecon
```

Run the test suite:

```bash
pytest -q
```

GitRecon v0.3.6 currently includes:

```text
76 passed
```

## Project Structure

```text
GitRecon/
├── gitrecon/
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── repository.py
│   │   └── security.py
│   ├── github/
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── repositories.py
│   │   └── security.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── analysis.py
│   │   ├── repository.py
│   │   └── security.py
│   ├── output/
│   │   ├── __init__.py
│   │   ├── json.py
│   │   └── terminal.py
│   ├── __init__.py
│   ├── cli.py
│   └── config.py
├── tests/
│   ├── __init__.py
│   ├── test_json_output.py
│   └── test_security_analysis.py
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── README_FR.md
└── pyproject.toml
```

## Current Version

Current stable version:

```text
v0.3.6
```

Main additions in v0.3.6:

- JSON report export
- Automatic `reports/` directory creation
- Default report file names
- Custom report names with `--output`
- Workflow serialization
- Permission serialization
- Security finding serialization
- JSON validation tests
- 76 automated tests
- CLI robustness improvements

## Limitations

GitRecon relies on information exposed by the GitHub API.

Some workflows exposed by GitHub may not correspond to standard YAML files stored directly in `.github/workflows/`.

GitHub can expose internal or dynamically generated workflows whose content cannot be retrieved through the repository contents API.

When workflow content is unavailable, GitRecon preserves the available workflow metadata and marks its content as unavailable instead of treating it as an analysis failure.

GitRecon findings must also be interpreted according to the repository's actual CI/CD architecture.

The absence of findings does not guarantee that a repository or workflow is secure.

## Security

GitRecon is intended for defensive repository analysis, security auditing, and security research.

Never expose GitHub access tokens in:

- Source code
- Commits
- Issues
- Screenshots
- Reports
- Debug logs

If you discover a security issue affecting GitRecon itself, avoid publicly disclosing sensitive exploitation details before the issue can be reviewed.

## Contributing

Contributions are welcome.

This includes:

- Bug reports
- New security rules
- Detection improvements
- Documentation improvements
- Tests
- Code quality improvements

Before submitting changes, run:

```bash
ruff check tests gitrecon
pytest -q
```

New security detection rules should ideally include dedicated automated tests.

## License

GitRecon is distributed under the terms described in the [`LICENSE`](LICENSE) file.

## Disclaimer

GitRecon provides automated repository intelligence and security indicators.

Its findings are intended to assist defensive analysis and should not replace manual security review.

The presence of a finding does not necessarily indicate a vulnerability.

The absence of findings does not guarantee that a repository, workflow, or CI/CD pipeline is secure.