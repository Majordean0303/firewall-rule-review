namespace FirewallReview.Core;

public sealed record AuditCheck(string Id, string Area, string Status, string Evidence, string Recommendation, string RequiredEvidence, string AffectedRules);
public sealed record ComplianceRow(string Framework, string Reference, string Check, string Status, string Evidence, string Recommendation, string RequiredEvidence, string AffectedRules, string Source)
{
    public string Title => Check switch
    {
        "NET-01" => "Broad permitted addresses",
        "NET-02" => "Unrestricted services",
        "NET-03" => "Missing inspection profiles",
        "NET-04" => "Policy shadowing",
        "LOG-01" => "Policy logging",
        "ENC-01" => "Cleartext services",
        "REV-01" => "Unused policy review",
        "REV-02" => "Business justification",
        "CFG-idle_timeout" => "Administrator idle timeout",
        "CFG-login_banner" => "Login banner",
        "CFG-pwd_complexity" => "Password baseline",
        "CFG-mgmt_acls" => "Management access restrictions",
        "CFG-zone_protection" => "Zone protection",
        "MAN-01" => "Scope and operating effectiveness",
        _ => Check
    };
}
public sealed record FrameworkSummary(string Framework, int Findings, int NoFinding, int NeedsEvidence, int ManualReview);

public static class Compliance
{
    public const string Scope = "Firewall evidence assessment only. Framework mappings are advisory; applicability, compensating controls and organization-wide compliance require assessor review. No finding means only that this check found no issue in the supplied evidence.";
    // References intentionally stay at the control family/category level where a policy export
    // cannot establish every subrequirement. Do not turn absence of a finding into certification.
    private sealed record Framework(string Name, string Network, string Logging, string Review, string Crypto, string Source);
    private static readonly Framework[] Frameworks =
    [
        new("CIS Controls v8.1", "Controls 4, 12, 13", "Control 8", "Controls 4, 12", "Controls 3, 12", "https://www.cisecurity.org/controls/CIS-controls-navigator"),
        new("NIST CSF 2.0", "PR.IR / PR.PS", "PR.PS / DE.CM", "GV.PO / ID.IM", "PR.DS", "https://www.nist.gov/cyberframework"),
        new("NIST SP 800-53 Rev. 5", "SC-7 / AC-4 / CM-7", "AU-2 / AU-12", "CM-3 / CA-7", "SC-8 / SC-13", "https://csrc.nist.gov/pubs/sp/800/53/r5/final"),
        new("NIST SP 800-41 Rev. 1", "Firewall policy", "Logging and monitoring", "Policy management", "Secure management", "https://csrc.nist.gov/pubs/sp/800/41/r1/final"),
        new("ISO/IEC 27001:2022", "Annex A: network security", "Annex A: logging and monitoring", "Annex A: configuration and change management", "Annex A: cryptography", "https://www.iso.org/standard/27001"),
        new("PCI DSS v4.0.1", "Requirement 1", "Requirement 10", "Requirements 1, 12", "Requirements 2, 4", "https://www.pcisecuritystandards.org/document_library/?category=pcidss"),
        new("SOC 2 (2017 TSC, 2022 points of focus)", "CC6", "CC7", "CC8", "CC6", "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022"),
        new("HIPAA Security Rule", "164.312(a)", "164.312(b)", "164.308(a)(1), (a)(8)", "164.312(e)", "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"),
        new("GDPR", "Article 32(1)(b)", "Article 32", "Article 32(1)(d)", "Article 32(1)(a)", "https://eur-lex.europa.eu/eli/reg/2016/679/oj")
    ];
    public static IReadOnlyList<string> Names => Frameworks.Select(f => f.Name).ToArray();
    private static bool Is(string a, params string[] values) => values.Any(v => a.Equals(v, StringComparison.OrdinalIgnoreCase));
    public static List<ComplianceRow> Evaluate(ReviewResult report)
    {
        bool pa = report.Vendor == FirewallVendor.PaloAlto;
        var active = report.Tables["Active Rules"];
        var permit = active.Where(r => Is(r.Get("Action"), "allow", "accept")).ToList();
        var checks = new List<AuditCheck>();
        void Check(string id, string area, IEnumerable<PolicyRule> scope, Func<PolicyRule, bool> bad, string[] fields, string recommendation, string evidence, Func<PolicyRule, bool>? incomplete = null)
        {
            var rows = scope.ToList();
            var missing = rows.Where(r => fields.Any(f => !r.Fields.ContainsKey(f) || Is(r.Get(f), "", "unknown", "not captured")) || (incomplete?.Invoke(r) ?? false)).ToList();
            // Blank profile/log cells are explicit missing configuration only in imported policy exports;
            // absent columns or unknown values mean evidence is unavailable.
            var affected = rows.Where(bad).ToList();
            var status = rows.Count == 0 ? "Needs evidence" : affected.Count > 0 ? "Finding" : missing.Count > 0 ? "Needs evidence" : "No finding";
            checks.Add(new(id, area, status, $"{affected.Count} flagged / {rows.Count} scoped policies; {missing.Count} with incomplete evidence. " + evidence,
                recommendation, string.Join(", ", fields), string.Join(", ", affected.Select(r => $"{r.Position}: {r.Name}"))));
        }
        var source = pa ? "Source Address" : "Source";
        var dest = pa ? "Destination Address" : "Destination";
        Check("NET-01", "Network", permit, r => Is(r.Get(source), "any", "all", "0.0.0.0/0", "::/0") || Is(r.Get(dest), "any", "all", "0.0.0.0/0", "::/0"), [source, dest, "Action"],
            "Validate business need; narrow permitted sources/destinations and document exceptions.", "Broad access is a review finding, not proof of a standards violation.");
        Check("NET-02", "Network", permit, r => Is(r.Get("Service"), "any", "all"), ["Service", "Action"], "Restrict services to approved protocols and ports.", "Named service groups need object definitions for full coverage.");
        var log = pa ? "Options" : "Log";
        Check("LOG-01", "Logging", active, r => r.Fields.ContainsKey(log) && Is(r.Get(log), "", "none", "disabled", "disable", "utm"), [log],
            "Enable appropriate session logging and forwarding; verify receipt and retention in the log platform.", "A configured profile does not prove successful log delivery or retention.");
        var profile = pa ? "Profile" : "Security Profiles";
        Check("NET-03", "Network", permit, r => r.Fields.ContainsKey(profile) && Is(r.Get(profile), "", "none", "no-inspection"), [profile, "Action"],
            "Apply appropriate inspection profiles or record an approved exception.", "Profile names alone do not validate profile content.");
        Check("ENC-01", "Crypto", permit, r => System.Text.RegularExpressions.Regex.IsMatch(r.Get("Service"), @"(?:^|[-_\s,;:/])(?:21|23|80|ftp|telnet|http)(?:[-_\s,;:/]|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)), ["Service"],
            "Replace cleartext protocols or document required protected transport and compensating controls.", "Service-name heuristic; encrypted tunnels and custom objects require review.");
        var zeroPositions = report.Tables["Zero Hit Rules"].Select(r => r.Position).ToHashSet();
        var hitField = pa ? (active.Any(r => r.Fields.ContainsKey("Rule Usage Hit Count")) ? "Rule Usage Hit Count" : "Rule Usage Rule Usage") : "Hit Count";
        Check("REV-01", "Review", active, r => zeroPositions.Contains(r.Position), [hitField],
            "Review owner, purpose and observation period before retiring unused policies.", "Zero hits may reflect a reset or insufficient observation time.",
            r => !Is(r.Get(hitField), "unused") && !(decimal.TryParse(r.Get(hitField).Replace(",", ""), System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var count) && count >= 0));
        var shadow = report.Tables["Shadowed Rules"];
        checks.Add(new("NET-04", "Network", shadow.Count > 0 ? "Finding" : "Manual review", $"{shadow.Count} shadow candidates from available selectors.", "Verify full objects, rule order, negation and inherited scope before removing a policy.", "Complete effective rulebase and object/group definitions", string.Join(", ", shadow.Select(r => r.Name))));
        var documented = active.Where(r => Is(r.Get("NIST Documented"), "yes", "no") || (r.Fields.ContainsKey("Description") && !Is(r.Get("Description"), "unknown", "not captured"))).ToList();
        var undocumented = documented.Where(r => Is(r.Get("NIST Documented"), "no") || (r.Fields.ContainsKey("Description") && r.Get("Description") == "")).ToList();
        checks.Add(new("REV-02", "Review", undocumented.Count > 0 ? "Finding" : documented.Count < active.Count || active.Count == 0 ? "Needs evidence" : "No finding",
            $"{documented.Count}/{active.Count} policies include documentation evidence; {undocumented.Count} missing rationale.", "Record rule owner, business justification, approval and review date.", "Description or NIST Documented, plus approval/review records", string.Join(", ", undocumented.Select(r => r.Name))));
        foreach (var key in new[] { "idle_timeout", "login_banner", "pwd_complexity", "mgmt_acls", "zone_protection" })
        {
            var check = report.Cis?.GetValueOrDefault(key);
            checks.Add(new("CFG-" + key, "Network", check?.Status == "Fail" ? "Finding" : check?.Status == "Pass" ? "No finding" : "Needs evidence",
                check is null ? "Configuration setting not captured." : check.Desc + ": " + check.Value,
                "Review the captured setting against the applicable vendor/version benchmark and local baseline.", "Full device configuration including " + key, ""));
        }
        checks.Add(new("MAN-01", "Review", "Manual review", "Applicability and operating effectiveness cannot be established from a firewall export.",
            "Validate regulated-data scope, segmentation tests, change approvals, periodic reviews, log retention, incident response and exceptions with the assessor.", "Network/data-flow diagrams, asset scope, tickets, log samples and test results", ""));
        return Frameworks.SelectMany(f => checks.Select(c => new ComplianceRow(f.Name, c.Area switch
        {
            "Logging" => f.Logging,
            "Review" => f.Review,
            "Crypto" => f.Crypto,
            _ => f.Network
        },
            c.Id, c.Status, c.Evidence, c.Recommendation, c.RequiredEvidence, c.AffectedRules, f.Source))).ToList();
    }
    public static List<FrameworkSummary> Summarize(IEnumerable<ComplianceRow> rows) => rows.GroupBy(r => r.Framework).Select(g => new FrameworkSummary(g.Key,
        g.Count(r => r.Status == "Finding"), g.Count(r => r.Status == "No finding"), g.Count(r => r.Status == "Needs evidence"), g.Count(r => r.Status == "Manual review"))).ToList();
}
