# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses calendar-independent release versions while an established release scheme is adopted.

## Unreleased

### Added

- Opt-in authenticated MCP/AI integration with read-only incident, alert, and evidence tools.
- MCP alert search and curated alert evidence queries.
- Detection rules for disabling AWS security monitoring, removing IAM MFA devices, and public EBS
  snapshot sharing.
- Guardrail documentation for AI-assisted investigation and remediation.
- API security response headers.
- Root `Makefile` targets for common setup and validation workflows.
- Contributor guide and architecture documentation.
- CI dependency vulnerability checks for Python and npm packages.

### Changed

- Expanded local ignores for environment variants, logs, caches, IDE files, and Terraform state.
- Updated frontend scripts with lint and combined check targets.

### Security

- Added baseline `nosniff`, frame-denial, referrer, and opener-protection headers.
