# C# review logic improvements

Work follows merge of PR #3 at 9958d03. Both existing branches are ancestors of
main. The C# migration is restored on this branch following the user's explicit
request to implement the improvements in C#, with Python retained as reference.

## Reference comparison

[FortiGate-Configuration-Review](https://github.com/babakb22/FortiGate-Configuration-Review)
audits device-wide CIS settings from raw FortiOS configuration using checks.json
and section-specific checks: management timeout, SSH/TLS, passwords, NTP and VDOMs.
Policy CSVs lack that evidence, so this change does not claim those controls pass
or import regex checks as proof of compliance.

[palo_alto_firewall_analyzer](https://github.com/moshekaplan/palo_alto_firewall_analyzer)
compares all traffic selectors for shadowing, expands groups and reconstructs
inherited Panorama rule order. It also separates logging/profile checks. Those
ideas inform the native implementation; no reference source code was copied.
Its missing-profile validator itself compares a boolean disabled value to 'yes',
which reinforces the need to validate behavior instead of copying it wholesale.

## Native changes

- ReviewEngine.ShadowedRules replaces the address-only heuristic in analysis.
  One earlier terminal policy must cover source, destination, zones/interfaces,
  service and (for Palo Alto) application and URL category. Action need not match:
  an earlier deny can make a later allow unreachable. Lists, networks, wildcards
  and identical object names are supported; IPv4 and IPv6 cannot cross-match.
- Exported context, user, HIP, target and schedule constraints must match.
  Negated or incomplete rules cannot produce a shadow claim. Cancellation is
  checked within the quadratic scan. The old AddressOverlapCandidates helper
  remains available for existing callers but no longer populates Shadowed Rules.
- Enabled permit policies retain security findings even with zero hits.
  Deny policies no longer produce permissive-access or missing-profile findings.
  Logging is reviewed for all enabled policies, including denies.
- Empty profiles/log settings are missing; named CLI forwarding profiles are
  recognized. This checks missing forwarding configuration, not session-log
  completeness, profile content or a mandated organizational logging profile.
- Counters accept decimal numeric strings and thousands separators. Unknown or
  invalid counters are excluded from both zero-hit and positive-hit buckets.
- Explicit Disabled fields take precedence over the legacy _Disabled name suffix;
  arbitrary names containing Disabled no longer disable a policy. Fortinet accepts
  both enable/disable and enabled/disabled status forms.
- PAN-OS input retains disabled, negation, schedule and source-user constraints.
  Workbook posture denominators use active policies instead of only used policies.

## Reviewed fixture changes

- Palo Alto: shadow count 4 -> 2. Only zero and unknown-object are covered by prior
  matching policies; admin and cleartext have different services from broad.
- Fortinet: source/destination-any counts 2 -> 1, excluding deny. Shadow count
  2 -> 3: stale, deny and no-log are covered, including wildcard policy coverage.
- PAN-OS: default-deny no longer triggers source/destination/service-any,
  missing-profile or high-risk findings. Its missing logging remains reviewable.
  Tag findings exclude deny; both policies remain medium due to missing logging.

## Boundaries and validation

Exports must be in actual evaluation order within one rulebase. Full group/object
resolution, inherited Panorama ordering, port-range containment, combined coverage
by multiple policies and device-wide FortiOS CIS auditing remain future work.
The current brace parser flattens configuration contexts; its repeated-name notes
must be reviewed. Missing optional columns do not prove those constraints absent.
Shadow findings are review candidates, not instructions to delete policies.

Run `dotnet test FirewallReview.Tests`, `dotnet test FirewallReview.UiTests` and
`dotnet build FirewallRuleReview.sln`. Tests cover selector mismatches, actual
coverage, opposite actions, scope/schedule/negation, disabled rules, unknown and
formatted counters, both vendors, workbook export/import and Avalonia workflows.
