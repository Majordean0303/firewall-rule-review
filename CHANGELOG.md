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
