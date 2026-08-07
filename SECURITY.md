# Security Policy

## Supported Versions

GitRecon is currently maintained on the latest stable release.

| Version | Supported |
|---|---|
| 0.3.x | Yes |
| < 0.3 | No |

## Reporting a Vulnerability

If you discover a security vulnerability affecting GitRecon, please do not disclose sensitive exploitation details publicly before the issue can be reviewed.

Prefer a private report through GitHub Security Advisories when available.

If private reporting is not available, contact:

bashxo@protonmail.com

Please include, when possible:

- A clear description of the vulnerability
- The affected GitRecon version
- Steps required to reproduce the issue
- The expected and observed behavior
- Potential security impact
- Relevant logs or proof-of-concept details
- Suggested remediation, if known

Do not include secrets, access tokens, credentials, or unrelated sensitive data in reports.

## Response Process

Security reports will be reviewed as soon as reasonably possible.

Depending on the issue, the response may include:

1. Reproduction and impact assessment
2. Development of a fix
3. Regression tests
4. Security validation
5. Publication of a patched release
6. Coordinated disclosure when appropriate

## Scope

Security issues that may be relevant include:

- GitHub token exposure
- Unsafe handling of GitHub API responses
- Path traversal
- Unsafe file handling
- Workflow parsing vulnerabilities
- YAML parsing or denial-of-service issues
- Command execution vulnerabilities
- Dependency or supply-chain issues
- Sensitive information disclosure

Automated security findings that do not demonstrate a meaningful impact may require additional validation before being treated as vulnerabilities.

## Security Practices

GitRecon currently uses several controls during development:

- Ruff for static code quality checks
- pytest for automated testing
- Bandit for Python security analysis
- pip-audit for dependency vulnerability checks
- Defensive validation of GitHub API responses
- Strict workflow path filtering
- Restricted YAML processing
- Automated regression tests

## Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability.

Thank you for helping improve GitRecon security.