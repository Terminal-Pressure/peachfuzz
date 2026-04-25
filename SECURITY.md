# Security Policy

PeachFuzz / CactusFuzz is a defensive and authorization-first fuzzing project for parser, API, schema, and AI-agent safety testing.

## Supported security posture

- PeachFuzz is defensive, local-only, and CI-safe by default.
- CactusFuzz is authorized-lab only and scope-gated.
- The project does not support unauthorized scanning, exploit delivery, credential theft, persistence, shell payloads, or third-party contact.
- Fuzzing targets must be local registered harnesses, owned lab assets, or explicit written-scope systems.

## Reporting vulnerabilities

Report vulnerabilities privately to CyberViser / 0AI maintainers. Include:

1. A concise summary of the issue.
2. Affected component, commit, version, or configuration.
3. Reproduction steps using local-only test inputs where possible.
4. Expected impact and any safe proof-of-concept payloads.
5. Whether credentials, secrets, or third-party systems were involved.

Do not publicly disclose exploitable details until maintainers have reviewed and coordinated a fix.

## Out of scope

The following are out of scope and may be ignored or rejected:

- Testing domains, IPs, repositories, packages, or infrastructure you do not own or have explicit authorization to assess.
- Reports requiring exploit execution against third parties.
- Denial-of-service testing outside an approved change window.
- Social engineering, phishing, credential harvesting, persistence, malware, or data exfiltration.
- Automated network scanning without written authorization.

## Continuous security baseline

This repository should maintain:

- CodeQL code scanning.
- Dependabot alerts and security updates.
- Dependency auditing with pip-audit and OSV Scanner.
- Semgrep SAST.
- Trivy filesystem/container-context scanning when container assets exist.
- Checkov scanning for GitHub Actions, Dockerfile, Terraform, and Kubernetes assets.
- GitHub secret scanning and push protection enabled in repository settings.
- Branch protection requiring pull requests, review, passing checks, and signed commits where possible.

## Human-in-the-loop rule

Automated assistants, fuzzing agents, and self-refinement modes may generate reports, patches, reproducers, and recommendations. They must not directly deploy, exploit, scan third-party assets, bypass review, or merge high-impact changes without human approval.
