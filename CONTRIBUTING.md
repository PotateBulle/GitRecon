# Contributing to GitRecon

Thank you for your interest in contributing to GitRecon.

GitRecon is an open-source command-line tool focused on GitHub repository intelligence, GitHub Actions analysis, and defensive security assessment.

Contributions are welcome, including bug fixes, new security rules, tests, documentation improvements, code quality improvements, and CI/CD enhancements.

## Code of Conduct

Be respectful and constructive when interacting with other contributors.

Discussions, issues, pull requests, and reviews should remain technical, professional, and focused on improving the project.

## Before Contributing

Before starting significant work, check the existing issues and pull requests to avoid duplicating an ongoing contribution.

For substantial changes, it is recommended to open an issue first and describe:

- The problem you want to solve
- The proposed approach
- The expected impact
- Any compatibility considerations
- Any security implications

Small fixes and documentation improvements can usually be submitted directly as pull requests.

## Development Environment

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

Install GitRecon with the development dependencies:

```bash
pip install -e ".[dev]"
```

## Project Structure

The main project directories are:

```text
gitrecon/
├── analysis/
├── github/
├── models/
├── output/
├── cli.py
└── config.py

tests/
├── test_github_security.py
├── test_json_output.py
└── test_security_analysis.py
```

The main responsibilities are:

- `gitrecon/github/` handles communication with the GitHub API
- `gitrecon/analysis/` interprets collected data and applies security rules
- `gitrecon/models/` contains internal data structures
- `gitrecon/output/` handles terminal and JSON output
- `tests/` contains automated tests

## Code Style

GitRecon uses Ruff for code quality and formatting.

Before submitting a pull request, run:

```bash
ruff check tests gitrecon
```

Format the code with:

```bash
ruff format tests gitrecon
```

Then run Ruff again:

```bash
ruff check tests gitrecon
```

Code should remain compatible with Python 3.11 and newer.

Prefer:

- Clear function names
- Small and focused functions
- Explicit type annotations
- Defensive validation of external data
- Minimal duplication
- Clear docstrings
- Simple comments only when they improve readability

Avoid unnecessary abstractions or complex logic when a simpler implementation is sufficient.

## Testing

All changes should preserve the existing test suite.

Run:

```bash
pytest -q
```

New features should include dedicated automated tests.

Bug fixes should ideally include a regression test reproducing the original issue.

Security-related changes should include tests covering malformed, unexpected, or hostile input where relevant.

## Security Rules

GitRecon includes GitHub Actions security rules identified by IDs such as:

```text
GH-ACTIONS-001
GH-ACTIONS-002
GH-ACTIONS-003
...
```

When adding a new security rule:

1. Use the next available rule identifier
2. Define a clear severity
3. Provide a concise title
4. Explain why the behavior may be security-relevant
5. Include useful evidence
6. Provide a practical recommendation
7. Add automated tests
8. Avoid classifying contextual behavior as a confirmed vulnerability

Security findings are indicators and must remain contextual.

For example, permissions such as:

```text
contents: write
id-token: write
```

may be legitimate depending on the workflow.

## GitHub Actions Security

GitRecon analyzes GitHub Actions workflows defensively.

When modifying workflow parsing or security analysis, consider:

- Mutable action references
- Full commit SHA pinning
- Third-party actions
- Workflow-level permissions
- Job-level permissions
- `pull_request_target`
- Write permissions
- OIDC permissions
- Malformed YAML
- YAML aliases and cyclic references
- Unexpected GitHub API responses
- Dynamic GitHub workflows

Do not assume that all workflow data returned by GitHub corresponds to a standard YAML file stored in the repository.

## Security Validation

Before submitting security-sensitive changes, run:

```bash
ruff check tests gitrecon
pytest -q
bandit -r gitrecon
pip-audit
```

A normal local development installation of GitRecon may cause `pip-audit` to report that the local `gitrecon` package cannot be found on PyPI.

This is expected when GitRecon is installed locally in editable mode.

## Dependencies

Avoid adding new runtime dependencies unless they provide clear value.

When proposing a new dependency, consider:

- Maintenance status
- Security history
- License compatibility
- Necessity
- Package size
- Transitive dependencies

Development-only tools should be added under:

```toml
[project.optional-dependencies]
dev = []
```

Runtime dependencies should remain under:

```toml
[project]
dependencies = []
```

## GitHub API Changes

Changes involving GitHub API communication should:

- Handle HTTP errors explicitly
- Preserve useful status information
- Avoid relying on string matching for HTTP status codes
- Validate response types
- Handle missing data gracefully
- Avoid exposing access tokens or credentials
- Avoid unnecessary API requests
- Respect GitHub API rate limits

## JSON Output

Changes to JSON serialization should preserve backwards compatibility when reasonably possible.

If the JSON structure changes, tests should verify the new structure.

Generated reports must remain inside the `reports/` directory unless the project explicitly changes this behavior.

Reports must never contain the GitHub authentication token.

## Commit Messages

Use clear and concise commit messages.

Examples:

```text
feat: add repository security analysis
fix: handle unavailable workflow content
security: harden YAML workflow parsing
test: add GitHub API regression tests
docs: improve contribution guide
ci: pin GitHub Actions to commit SHAs
```

Conventional-style prefixes are recommended:

```text
feat:
fix:
security:
test:
docs:
ci:
refactor:
chore:
```

## Pull Requests

A pull request should clearly explain:

- What changed
- Why the change is needed
- How it was tested
- Whether it changes security behavior
- Whether it changes JSON output or CLI behavior

Keep pull requests focused on one logical change when possible.

Before submitting:

```bash
ruff check tests gitrecon
pytest -q
```

For security-sensitive changes:

```bash
bandit -r gitrecon
pip-audit
```

## Reporting Security Vulnerabilities

Do not report exploitable security vulnerabilities through public issues when sensitive details could put users at risk.

Please follow the instructions in:

[`SECURITY.md`](SECURITY.md)

## Documentation

Update documentation when a change affects:

- CLI usage
- Installation
- Security rules
- JSON output
- Configuration
- Dependencies
- Supported behavior

If a change affects user-facing behavior, update both:

```text
README.md
README_FR.md
```

when appropriate.

## License

By contributing to GitRecon, you agree that your contribution may be distributed under the same license as the project.

See:

[`LICENSE`](LICENSE)

## Final Checklist

Before submitting a contribution, verify:

```text
[ ] Ruff passes
[ ] Tests pass
[ ] New behavior is tested
[ ] Security-sensitive code has been reviewed
[ ] No credentials or tokens are included
[ ] Documentation has been updated when necessary
[ ] Commit messages are clear
[ ] The pull request explains the change
```

Thank you for contributing to GitRecon.