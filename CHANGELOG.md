## Compliance dashboard and evidence intake

- Add 14 firewall checks mapped to nine cybersecurity/audit frameworks, with explicit findings, missing evidence and manual-review states.
- Add dashboard framework/status filters, evidence details, remediation and framework sources.
- Add an evidence collection guide and vendor CSV template export; open the app on the guide.
- Import FortiOS configuration with VDOM isolation, unknown counters, structure validation and initial management-baseline checks.
- Include compliance summary, evidence and collection instructions in Excel/JSON.

## C# analysis improvements

- Restored the native .NET/Avalonia implementation after PR #3, as requested.
- Require coverage across traffic selectors for shadow findings.
- Review unused permit rules for exposure and profiles; exclude deny rules from those findings.
- Correct disabled status, numeric/unknown hit counters and named log profiles.
- Retain PAN-OS negation, schedule and user constraints; correct workbook denominators.
- Add focused native regression tests and document reference comparisons.

# Firewall Rule Review changelog

## [Unreleased]

### Added
- Native .NET 10 headless core, CLI, offline regression gate, and Avalonia desktop workflow.
- Compact validation scripts, cross-platform CI, local self-contained packaging and resumable migration handoff.

### Changed
- Keep the legacy implementation as a reference while using C# for the migrated desktop.

### Fixed
- Preserve unknown hit counters and unknown CIS evidence; do not manufacture zero-hit counts or passing controls.
- Handle IPv4/IPv6 address overlaps without mixed-family crashes and label address-only shadowing limitations.
- Validate required input headers, preserve quoted CSV fields, and export workbooks atomically with their existing worksheet identities.
