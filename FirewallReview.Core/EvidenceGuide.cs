namespace FirewallReview.Core;

public static class EvidenceGuide
{
    public static string Headers(FirewallVendor vendor) => vendor == FirewallVendor.Fortinet
        ? "Policy,Name,Status,From,Source,To,Destination,Service,Action,Security Profiles,Log,Hit Count,Description,VDOM,Schedule"
        : "Name,Disabled,Source Zone,Source Address,Destination Zone,Destination Address,Application,Service,URL Category,Action,Profile,Options,Tags,Rule Usage Hit Count,Description,Negate Source,Negate Destination,Schedule,Source User,VSYS";
    public const string Text = """
    START HERE
    Import one device / effective rulebase at a time, in firewall evaluation order.
    CSV/XLSX: first row must contain headers; quote cells containing commas.
    Use Open evidence to scan, then inspect Compliance for findings and missing evidence.
    CSV template saves the headers for the vendor selected above. Auto-detect defaults to Palo Alto.

    PALO ALTO — supported CSV/XLSX or brace-format CLI text
    Required columns: Name, Source Zone, Source Address, Destination Zone,
    Destination Address, Application, Service, URL Category, Action, Profile,
    Options, Tags, and Rule Usage Hit Count (or Rule Usage Rule Usage).
    Include Disabled, Description, Source User, Schedule, Negate Source,
    Negate Destination and VSYS when available. Unknown hit counters may be blank.
    CLI collection: capture the complete running configuration in brace format
    Set CLI display to brace format: set cli config-output-format default
    then use configure / show / exit. Capture show system info in operational mode.
    The configuration-mode show is candidate configuration: confirm no pending changes
    before using it to assess running policy. If collecting show config running,
    ensure the captured output uses braces; this importer rejects XML.
    Optional counters: show rule-hit-count vsys vsys-name vsys1 rule-base security rules all
    Replace vsys1 with the reviewed scope. Command syntax/output varies by PAN-OS version.
    Save the full brace configuration and optional status/counter output into one .txt file.
    XML and set-format configuration are not supported. Counter tables that cannot be
    matched remain unknown. Supply a CSV with hit counters when needed.
    The brace importer does not reconstruct Panorama hierarchy; use a scoped effective
    rule export for inherited policies and review the coverage notes.

    FORTIGATE — CSV/XLSX or FortiOS configuration text (.txt/.conf/.cfg)
    Required CSV columns: Name or Policy, Status, From, Source, To, Destination,
    Service, Action, Security Profiles, Log, Hit Count. Include VDOM, Schedule,
    Description and source/destination negation when available.
    CLI: show full-configuration (in the authorized scope) captures policies and
    explicit defaults. Also collect get system status for model/FortiOS context.
    For a focused policy scan: show full-configuration firewall policy
    For management evidence: show full-configuration system global and
    show full-configuration system password-policy
    Preserve config/edit/next/end boundaries and VDOM names in one text file.
    Raw configuration has no hit telemetry; use the policy CSV export with Hit Count
    for stale-rule review. Address and service groups remain named references.
    Missing configuration sections are Needs evidence, not a successful check.

    ADDITIONAL AUDIT EVIDENCE
    Rule owners and business justification; approvals and review dates; complete
    address/service definitions; network/data-flow diagrams and regulated-data scope;
    segmentation test results; traffic/session logs, delivery and retention evidence;
    authentication/MFA and administrator permissions; approved exceptions.
    These records need assessor review and are not parsed as policy CSVs.

    COLLECTION QUALITY
    Preserve order, names, selectors and configuration structure. Remove credentials,
    private keys and secret values from collected files. Do not replace missing
    evidence with zero, none or a passing value. No device changes are required.
    Findings apply to captured evidence, not an attestation of organizational compliance.
    """;
}
