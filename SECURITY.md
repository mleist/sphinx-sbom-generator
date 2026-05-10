# Security Policy

## Supported versions

Only the latest minor release receives security updates.

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Instead, use GitHub's [private vulnerability reporting][gh-pvr] for this
repository, or email **security@example.com** with:

- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal proof of concept.
- Affected version(s).
- Your contact info if you'd like to be credited.

You can expect:

- An acknowledgement within 3 working days.
- A status update within 7 working days.
- Coordinated disclosure once a fix is available.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

## Scope

In scope:

- Vulnerabilities in the `sbom_generator` package itself.
- Issues that cause the tool to under-report known CVEs in scanned
  manifests (false negatives).

Out of scope:

- Vulnerabilities in upstream registries (PyPI, npm, OSV.dev).
- Vulnerabilities in user-supplied manifests.
