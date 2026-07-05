# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Redactrus is a security-critical library whose purpose is to prevent sensitive data leakage in logs. A bug that causes redaction to silently fail (a false negative) is treated as a **critical security vulnerability**.

### How to Report

Use [GitHub Private Security Advisories](https://github.com/ibreakthecloud/redactrus/security/advisories/new) to report vulnerabilities confidentially.

Please include:
- A description of the vulnerability
- Steps to reproduce (ideally a minimal Go test case)
- The type of sensitive data affected (password, API key, email, etc.)
- Whether the issue is a false negative (data not redacted) or false positive (data incorrectly redacted)

### Response SLA

| Severity | Acknowledgement | Patch Release |
|----------|----------------|---------------|
| Critical (false negative — data leaks) | 24 hours | 7 days |
| High     | 48 hours       | 14 days       |
| Medium   | 72 hours       | 30 days       |
| Low      | 7 days         | Next release  |

### What Constitutes a Security Vulnerability

- **Critical**: A built-in redactor fails to redact a clearly sensitive value that matches its documented pattern
- **High**: A race condition that could cause redaction to be skipped
- **Medium**: A pattern that is too broad (false positive, redacting non-sensitive data)
- **Low**: Documentation gaps that could lead to misconfiguration

## Responsible Disclosure

We follow coordinated disclosure. We ask that you give us the time outlined above to address the issue before any public disclosure. We will credit reporters in the release notes unless you prefer to remain anonymous.
