# Firewall Rule Review migration

- Branch: `migration/avalonia/firewall-rule-review`.
- Runtime: .NET 10 LTS; native C# core, CLI and Avalonia desktop.
- Preserve the original implementation for parity/reference; it is not required by the new desktop.
- Run `pwsh -File scripts/test-all.ps1` for offline core tests and CLI/desktop builds.
- Use `scripts/test-core.ps1 -Filter ... -NoRestore` for focused checks. Logs/TRX: ignored `artifacts/`.
- Run `scripts/package.ps1 -Runtime win-x64` (or an advertised RID) for local self-contained packaging.
- No production release, merge, installer execution or live network validation is performed.
- Native Windows/macOS rendering and representative real-data workflows require morning review.

## Implementation and validation

- Baseline: `5f9d6c527e2fdeecee0a570d180f1d548479fe25`.
- Native CSV/XLSX and PAN-OS brace-text import, Palo Alto/Fortinet analytics, NIST/CIS configuration evidence and workbook generation.
- Legacy risk metrics and subset tables match captured Python outputs for both vendors and PAN-OS CLI.
- Retain workbook sheet identities and standard dashboard metric positions; add explicitly labeled overlap candidates and unknown-evidence notices.
- Missing CLI hit counters remain unknown instead of becoming zero; absent CIS configuration context remains unknown instead of a passing control.
- Core gate: 20 tests, including subnet math, quoted CSV, workbook contents/re-import, missing headers and cancellation. Two Skia-backed UI checks cover themes and import/Excel export; CLI and desktop build locally.
- Manual review: native visual behavior, large field exports, rule-intent interpretation, self-contained packages.
- Shadowed Rules is the existing address-only candidate heuristic, not proof of complete policy shadowing or a safe deletion plan.
- Next serial application: Network-IP-to-Port-Tracer.
