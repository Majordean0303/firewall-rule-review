# Compliance dashboard and scan evidence

The native C# desktop and CLI now assess 14 unique firewall checks and map them
into nine framework views. Mapped rows are not independent vulnerabilities:
one policy finding can support several frameworks. Dashboard counts identify
unique checks; each framework summary counts its own mapped checks.

Supported mappings: CIS Controls v8.1; NIST CSF 2.0; NIST SP 800-53 Rev. 5;
NIST SP 800-41 Rev. 1; ISO/IEC 27001:2022; PCI DSS v4.0.1; SOC 2 TSC (2017,
2022 points of focus); HIPAA Security Rule; GDPR Article 32.

These are author-created, thematic mappings of firewall evidence. They are not
endorsed mappings, complete benchmark implementations, certification or legal
applicability determinations. Licensed standards and the assessor's selected
version and scope remain authoritative. Version-specific CIS vendor benchmarks
are not claimed: configuration thresholds are explicitly local review baselines.

## Status meanings

- Finding: the check identified a condition requiring review; it is not by itself
  a conclusion that a statutory or contractual requirement was violated.
- No finding: the narrow check found no issue in the supplied fields. It does not
  prove network-wide compliance, successful log delivery or profile effectiveness.
- Needs evidence: inputs are missing, unknown or outside the supplied scope.
- Manual review: applicability or effectiveness needs an assessor, such as network
  segmentation tests, log retention, approval records and compensating controls.

All nine frameworks expose the same technical evidence through category-level
references; the framework selector filters those mappings. Regulatory applicability
must be established independently (for example payment data, ePHI or personal data).

## Using the dashboard

The app opens on **Required evidence**, including vendor commands and CSV headers.
Choose Palo Alto or Fortinet and **Save CSV template** to produce a header-only file.
Add one row per policy in evaluation order, preserving quoted multi-value cells.
Select **Open evidence** to import and scan. The Policy scan tab retains policy
categories and evidence. Compliance offers framework/status filters, counts,
affected policy identifiers, next steps and source references. The Excel workbook
adds Compliance Summary, Compliance Evidence and Required Evidence sheets; JSON
contains the complete mapped rows.

## Supported input and collection

The in-app guide is defined once in `EvidenceGuide.cs` and reused by Excel export.
Palo Alto CSV/XLSX requires all fields shown in the guide; include explicit status,
negation, source users, schedules and scope. PAN-OS text must be brace format.
Set terminal output with `set cli config-output-format default`, then collect
configuration-mode `show` (candidate configuration; confirm no uncommitted changes)
and operational `show system info`. If `show config running` emits XML, it cannot
be imported by this brace parser. Counter syntax is version-dependent; the guide
includes `show rule-hit-count vsys vsys-name vsys1 rule-base security rules all`.
Counters that do not match the recognized table layout remain unknown. Use CSV
hit-count columns when raw counters cannot be matched.

FortiOS input now supports `.txt`, `.conf` and `.cfg`, as well as CSV/XLSX.
`show full-configuration` captures explicit defaults, or collect complete
`show full-configuration firewall policy`, `show full-configuration system global`
and `show full-configuration system password-policy` sections. Keep all
config/edit/next/end boundaries and VDOM scope. `get system status` supplies version
context for manual assessment; it is not currently parsed into firmware findings.
Commands and privileges vary by installed FortiOS/PAN-OS version.

The FortiOS parser keeps policy order and VDOM identifiers, rejects truncated
structure, preserves negation/user constraints and marks counters unknown.
Initial management checks evaluate explicit idle timeout and password policy.
Missing fields remain unknown. Multiple captured settings cannot let a later
passing section hide an earlier failing section. Internet-service and negated-service
policies are excluded from shadow claims. Groups remain named references.
Only `config firewall policy` is imported; policy6, local-in, proxy policies,
NAT and routing are not assessed.

Full device configuration may contain secrets: redact credentials and keys while
preserving rule selectors and configuration structure. No device write is required.
Separate audit artifacts such as topology, approvals, retention and segmentation
results are listed for assessor review; arbitrary attachments are not parsed.

## Sources checked for mapping and collection guidance

- https://www.cisecurity.org/controls/CIS-controls-navigator
- https://www.nist.gov/cyberframework
- https://csrc.nist.gov/pubs/sp/800/53/r5/final
- https://csrc.nist.gov/pubs/sp/800/41/r1/final
- https://www.iso.org/standard/27001
- https://www.pcisecuritystandards.org/document_library/?category=pcidss
- https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html
- https://eur-lex.europa.eu/eli/reg/2016/679/oj
- https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/get-started-with-the-cli/customize-the-cli
- https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-cli-ops-command-hierarchy
- https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/567401/dialup-ipsec-vpn-using-custom-tcp-port

## Validation

Native regression tests cover framework coverage, missing evidence, explicit
findings, VDOM isolation, malformed/incomplete configuration, vendor mismatch,
conflicting configuration values, templates, JSON and workbook evidence sheets.
Avalonia headless tests exercise framework/status filters and the new tabs.
Native desktop font rendering and real device exports still need manual validation.
