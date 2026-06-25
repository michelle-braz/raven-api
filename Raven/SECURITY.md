# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in RAVEN, please report it **privately**
rather than opening a public issue.

**Contact:** security@ravenrisk.dev

Include in your report:
- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact (authentication bypass, data exposure, etc.)
- Your suggested severity (critical / high / medium / low)

You can expect an acknowledgement within 48 hours and a resolution timeline
within 7 days for critical issues.

## Scope

The following are in scope:
- Authentication and authorization bypasses (`/v1/analyze`, `/beta/*`)
- API key exposure or predictable key generation
- Rate limiting bypasses
- Input validation issues leading to unexpected behavior

The following are out of scope:
- Denial-of-service via extremely large payloads (covered by infra-level limits)
- Issues in dependencies — please report those upstream

## Supported Versions

RAVEN is currently in closed beta. Only the `main` branch is supported.
