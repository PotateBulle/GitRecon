# Security Policy

GitRecon is a defensive security tool designed to analyze GitHub repositories, GitHub Actions workflows, permissions, dependencies, and repository security indicators.

Security issues affecting GitRecon itself are taken seriously.

## Supported Versions

GitRecon is currently maintained on the latest stable release.

| Version | Supported |
|---|---|
| `0.3.7a1` | Yes |
| `0.3.7` | Security fixes only |
| `0.3.6` | No |
| `< 0.3.6` | No |

Users are encouraged to run the latest stable version whenever possible.

## Recent Security Hardening

GitRecon v0.3.7 and v0.3.7a1 introduced several security and robustness improvements.

These changes include:

- Structured GitHub API error handling
- Reliable HTTP status code handling
- Strict GitHub Actions workflow path validation
- Filtering of dynamic or invalid workflow paths
- Strict Base64 decoding
- Protection against cyclic YAML aliases
- Workflow YAML size limits
- Defensive validation of GitHub API responses
- Improved GitHub pagination handling
- Restricted setuptools package discovery
- Patched setuptools requirement (`>=83.0.0`)
- Automated CI validation
- Automated security testing with Bandit
- Dependency auditing with pip-audit
- GitHub Actions pinned to full commit SHAs
- Additional security regression tests

The current stable release, `v0.3.7a1`, includes these fixes and security patches.

## Security Validation

GitRecon currently uses several controls during development and continuous integration:

- Ruff for static code quality checks
- pytest for automated regression testing
- Bandit for Python security analysis
- pip-audit for dependency vulnerability auditing
- Dependabot for dependency monitoring
- GitHub Actions for automated CI validation

The current automated test suite contains:

```text
85 tests
```

The current security validation status for `v0.3.7a1` is:

```text
Ruff: passed
pytest: 85 passed
Bandit: no issues identified
pip-audit: no known vulnerabilities found
GitRecon self-scan: 0 workflow security findings
```

## Reporting a Vulnerability

If you discover a vulnerability affecting GitRecon, please avoid publishing sensitive exploitation details through a public issue before the problem can be reviewed.

Prefer GitHub's private vulnerability reporting or Security Advisory functionality when available.

If private reporting is not available, contact:

```text
bashxo@protonmail.com
```

Please include, when possible:

- A clear description of the vulnerability
- The affected GitRecon version
- Steps required to reproduce the issue
- The expected behavior
- The observed behavior
- The potential security impact
- Relevant logs or error messages
- A minimal proof of concept when appropriate
- Suggested remediation, if known

Do not include unrelated secrets, access tokens, credentials, private repository data, or personal information.

## Scope

Examples of security issues that may be considered in scope include:

- GitHub token exposure
- Credential or secret disclosure
- Unsafe GitHub API response handling
- Path traversal
- Unsafe file handling
- Arbitrary file writes
- Command execution
- Code injection
- Unsafe YAML processing
- Denial-of-service conditions in workflow parsing
- Recursive or cyclic YAML handling issues
- Base64 parsing vulnerabilities
- Dependency or supply-chain vulnerabilities
- Authentication or authorization issues
- Sensitive information disclosure
- Security rule bypasses with meaningful impact

## Out of Scope

The following generally do not constitute security vulnerabilities by themselves:

- Expected GitHub API rate limiting
- Missing optional repository governance files
- Informational GitHub Actions findings without demonstrated impact
- Legitimate workflow write permissions required by the repository
- Third-party action usage without an actual exploitable condition
- Unsupported or malformed input that is safely rejected
- Findings caused exclusively by outdated local environments
- Vulnerabilities affecting third-party repositories rather than GitRecon itself

Automated scanner results should be manually validated before being reported as vulnerabilities.

## GitHub Actions Security

GitRecon analyzes GitHub Actions workflows that may originate from untrusted repositories.

The parser and analysis engine therefore apply defensive controls including:

- Workflow path validation
- YAML size limits
- Protection against cyclic YAML aliases
- Validation of parsed structures
- Filtering of non-file and dynamically generated workflows
- Detection of mutable action references
- Analysis of explicit workflow and job permissions

GitRecon's own CI workflows use read-only repository permissions where possible:

```yaml
permissions:
  contents: read
```

GitHub Actions used by the project are pinned to full commit SHAs to reduce supply-chain risk.

## Dependency Security

Runtime and development dependencies are monitored through:

- Dependabot
- pip-audit
- CI validation

The project currently requires a patched setuptools version for builds:

```text
setuptools>=83.0.0
```

New dependencies should be reviewed for:

- Maintenance status
- Security history
- Necessity
- License compatibility
- Transitive dependency impact

## GitHub Tokens

GitRecon may use a GitHub token through the environment variable:

```text
GITHUB_TOKEN
```

Tokens must never be committed to the repository.

Do not place tokens in:

- Source code
- Configuration tracked by Git
- JSON reports
- Issues
- Pull requests
- Screenshots
- Debug logs
- Test fixtures

Local secrets should remain in `.env`, which must stay excluded from version control.

## Security Response Process

When a valid vulnerability is reported, the expected process is:

1. Reproduce and validate the issue
2. Determine affected versions
3. Assess severity and impact
4. Develop a minimal corrective patch
5. Add regression tests
6. Run the complete security validation suite
7. Publish a patched release
8. Coordinate disclosure when appropriate

Security patches should not be considered complete until relevant regression tests have been added when practical.

## Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability.

Once a fix has been released, relevant technical details may be documented through GitHub releases, security advisories, or project documentation when appropriate.

## Security Tools

Before releasing security-sensitive changes, the following commands should pass:

```bash
ruff check tests gitrecon
pytest -q
bandit -r gitrecon
pip-audit
```

A locally installed editable version of GitRecon may appear in pip-audit as an unaudited local package because GitRecon is not necessarily available on PyPI.

This does not indicate a known vulnerability in GitRecon itself.

## Contact

Security contact:

```text
bashxo@protonmail.com
```

Thank you for helping improve the security and robustness of GitRecon.
