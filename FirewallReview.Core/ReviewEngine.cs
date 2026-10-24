using System.Net;
using System.Globalization;
using System.Text.RegularExpressions;
namespace FirewallReview.Core;

public static class ReviewEngine
{
    private static readonly Regex Admin = new(@"(?:^|[-_\s,;:/])(?:22|3389|rdp|ssh)(?:[-_\s,;:/]|$)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));
    private static readonly Regex Cleartext = new(@"(?:^|[-_\s,;:/])(?:21|23|80|ftp|telnet|http)(?:[-_\s,;:/]|$)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));
    private static bool Eq(string x, string y) => x.Trim().Equals(y, StringComparison.OrdinalIgnoreCase);
    private static bool Missing(string value) => value.Length == 0 || Eq(value, "none");
    private static bool Truth(string value) => new[] { "yes", "true", "1", "disabled", "disable" }.Any(v => Eq(value, v));
    private static decimal? Counter(string value) => decimal.TryParse(value.Replace(",", ""), NumberStyles.Number, CultureInfo.InvariantCulture, out var number) && number >= 0 ? number : null;
    public static ReviewResult Analyze(PolicyInput input, string site, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        if (input.Vendor == FirewallVendor.Auto)
            throw new ArgumentException("A detected or selected vendor is required.");
        var pa = input.Vendor == FirewallVendor.PaloAlto;
        var rules = input.Rules;
        var notes = new List<string>(input.CoverageNotes);
        bool Disabled(PolicyRule r) => pa ? (r.Fields.ContainsKey("Disabled") ? Truth(r.Get("Disabled")) : r.Name.EndsWith("_Disabled", StringComparison.OrdinalIgnoreCase)) : (Eq(r.Get("Status"), "disabled") || Eq(r.Get("Status"), "disable"));
        bool Active(PolicyRule r) => pa ? !Disabled(r) : (Eq(r.Get("Status"), "enabled") || Eq(r.Get("Status"), "enable"));
        string Hit(PolicyRule r) => pa ? (r.Fields.ContainsKey("Rule Usage Hit Count") ? r.Get("Rule Usage Hit Count") : r.Get("Rule Usage Rule Usage")) : r.Get("Hit Count");
        bool Zero(PolicyRule r) => Counter(Hit(r)) == 0 || (pa && Eq(Hit(r), "unused"));
        bool Accept(PolicyRule r) => Eq(r.Get("Action"), "allow") || Eq(r.Get("Action"), "accept");
        bool Source(PolicyRule r) => Eq(r.Get(pa ? "Source Address" : "Source"), pa ? "any" : "all");
        bool Destination(PolicyRule r) => Eq(r.Get(pa ? "Destination Address" : "Destination"), pa ? "any" : "all") && (!pa || (Eq(r.Get("Application"), "any") && Eq(r.Get("URL Category"), "any")));
        bool Service(PolicyRule r) => (Eq(r.Get("Service"), pa ? "any" : "all") || (pa && Eq(r.Get("Service"), "application-default"))) && (!pa || (Eq(r.Get("Application"), "any") && Eq(r.Get("URL Category"), "any")));
        bool Profile(PolicyRule r) => Accept(r) && (pa ? Missing(r.Get("Profile")) : (Missing(r.Get("Security Profiles")) || r.Get("Security Profiles").Contains("no-inspection", StringComparison.OrdinalIgnoreCase)));
        bool Logs(PolicyRule r) => pa ? Missing(r.Get("Options")) : Missing(r.Get("Log")) || Eq(r.Get("Log"), "disable") || Eq(r.Get("Log"), "disabled") || Eq(r.Get("Log"), "utm");
        bool Tags(PolicyRule r) => pa && Eq(r.Get("Tags"), "none");
        bool High(PolicyRule r) => Accept(r) && (Source(r) || Destination(r) || Service(r) || Profile(r) || (pa && Cleartext.IsMatch(r.Get("Service"))));
        bool Medium(PolicyRule r) => !High(r) && (Zero(r) || Logs(r) || Tags(r) || (pa && Accept(r) && Admin.IsMatch(r.Get("Service"))));
        var disabled = rules.Where(Disabled).ToList();
        var active = rules.Where(Active).ToList();
        var zero = active.Where(Zero).ToList();
        var hit = active.Where(r => Counter(Hit(r)) > 0).ToList();
        var tables = new Dictionary<string, List<PolicyRule>> { { "Master Sheet", rules }, { "Disabled Rules", disabled }, { "Active Rules", active }, { "Zero Hit Rules", zero }, { "Active Hit Rules", hit }, { "Source Any Rules", active.Where(r => Accept(r) && Source(r)).ToList() }, { "Destination Any Rules", active.Where(r => Accept(r) && Destination(r)).ToList() }, { "Service Any Rules", active.Where(r => Accept(r) && Service(r)).ToList() }, { "Profile None", active.Where(r => Accept(r) && Profile(r)).ToList() }, { "Logs None", active.Where(Logs).ToList() }, { "Tags None", active.Where(r => Accept(r) && Tags(r)).ToList() } };
        var metrics = new Dictionary<string, int> { { "total_rules", rules.Count }, { "disabled_rules", disabled.Count }, { "active_rules", active.Count }, { "zero_hit_rules", zero.Count }, { "active_hit_rules", hit.Count }, { "source_any", tables["Source Any Rules"].Count }, { "destination_any", tables["Destination Any Rules"].Count }, { "service_any", tables["Service Any Rules"].Count }, { "profile_issue", tables["Profile None"].Count }, { "logs_none", tables["Logs None"].Count }, { "tags_none", tables["Tags None"].Count } };
        if (pa)
        {
            tables["Admin Ports"] = active.Where(r => Accept(r) && Admin.IsMatch(r.Get("Service"))).ToList();
            tables["Cleartext Protocols"] = active.Where(r => Accept(r) && Cleartext.IsMatch(r.Get("Service"))).ToList();
            var valid = active.Where(r => Accept(r) && r.Get("Source Address") != "" && !Eq(r.Get("Source Address"), "any") && r.Get("Destination Address") != "" && !Eq(r.Get("Destination Address"), "any")).ToList();
            var reverse = valid.GroupBy(r => (r.Get("Source Address"), r.Get("Destination Address"), r.Get("Service"))).ToDictionary(g => g.Key, g => g.Select(r => r.Name).ToHashSet());
            tables["Bi-Directional Duplicates"] = zero.Where(r => reverse.TryGetValue((r.Get("Destination Address"), r.Get("Source Address"), r.Get("Service")), out var names) && names.Any(n => n != r.Name)).ToList();
            tables["NIST Violations"] = active.Where(r => Eq(r.Get("NIST Documented"), "no")).ToList();
            metrics["admin_ports"] = tables["Admin Ports"].Count;
            metrics["cleartext_ports"] = tables["Cleartext Protocols"].Count;
            metrics["bidirectional_rules"] = tables["Bi-Directional Duplicates"].Count;
            metrics["undocumented_rules"] = tables["NIST Violations"].Count;
        }
        tables["Shadowed Rules"] = ShadowedRules(active, pa, token);
        metrics["shadowed_rules"] = tables["Shadowed Rules"].Count;
        var high = active.Where(High).ToList();
        var med = active.Where(Medium).ToList();
        var low = active.Where(r => !High(r) && !Medium(r)).ToList();
        tables["High Risk"] = high;
        tables["Medium Risk"] = med;
        tables["Low Risk"] = low;
        metrics["high_risk"] = high.Count;
        metrics["medium_risk"] = med.Count;
        metrics["low_risk"] = low.Count;
        var risk = rules.ToDictionary(r => r.Position, r => Disabled(r) ? "Disabled" : !Active(r) ? "Unknown status" : High(r) ? "High" : Medium(r) ? "Medium" : "Low");
        var unknown = active.Count(r => !Zero(r) && Counter(Hit(r)) is null);
        if (unknown > 0)
            notes.Add($"Hit counters missing for {unknown} active rules; these were not labeled zero-hit.");
        if (active.Count + disabled.Count < rules.Count)
            notes.Add("Some policies have unrecognized status and were excluded from active-rule metrics.");
        notes.Add("Shadow checks require input in evaluation order within one rulebase. All exported selectors must be covered by one earlier terminal rule. Unresolved groups, absent optional selectors and inherited rule ordering require manual review.");
        var report = new ReviewResult(site, input.Vendor, rules, metrics, tables, risk, notes, input.Nist, input.Cis);
        return report with { Compliance = Compliance.Evaluate(report) };
    }
    private static HashSet<string> Members(string value) => value.Trim('[', ']').Split(new[] { ',', ';', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(v => v.Trim('"', '\'')).ToHashSet(StringComparer.Ordinal);
    private static bool Covers(string prior, string current, bool address)
    {
        var first = Members(prior);
        var second = Members(current);
        if (first.Count == 0 || second.Count == 0 || first.Contains("unknown") || second.Contains("unknown"))
            return false;
        if (first.Any(v => Eq(v, "any") || Eq(v, "all")))
            return true;
        if (second.Any(v => Eq(v, "any") || Eq(v, "all")))
            return false;
        return second.All(v => first.Contains(v) || (address && Network.TryParse(v) is { } subnet && first.Any(p => Network.TryParse(p) is { } net && net.Contains(subnet))));
    }
    public static List<PolicyRule> ShadowedRules(IReadOnlyList<PolicyRule> rules, bool paloAlto, CancellationToken token = default)
    {
        string[] required = paloAlto
            ? ["Source Zone", "Source Address", "Destination Zone", "Destination Address", "Application", "Service", "URL Category"]
            : ["From", "Source", "To", "Destination", "Service"];
        string[] optional = ["Source User", "User", "Schedule", "Source HIP", "Destination HIP", "Target", "Rule Type", "VDOM", "Device Group", "Rulebase", "VSYS"];
        string[] negate = ["Negate Source", "Negate Destination", "negate-source", "negate-destination"];
        string[] terminal = ["allow", "accept", "deny", "drop", "reject", "reset-client", "reset-server", "reset-both"];
        bool Eligible(PolicyRule r) => terminal.Any(a => Eq(r.Get("Action"), a)) && !Truth(r.Get("Disabled"))
            && !Truth(r.Get("Unsupported Constraints")) && !Truth(r.Get("Status")) && !negate.Any(c => r.Get(c).Length > 0 && !Eq(r.Get(c), "no") && !Eq(r.Get(c), "false"))
            && required.All(c => r.Fields.ContainsKey(c) && r.Get(c).Length > 0);
        var found = new List<PolicyRule>();
        for (int i = 0; i < rules.Count; i++)
        {
            token.ThrowIfCancellationRequested();
            var current = rules[i];
            if (!Eligible(current))
                continue;
            for (int j = 0; j < i; j++)
            {
                token.ThrowIfCancellationRequested();
                var prior = rules[j];
                if (!Eligible(prior))
                    continue;
                if (!required.All(c => Covers(prior.Get(c), current.Get(c), c is "Source" or "Destination" or "Source Address" or "Destination Address")))
                    continue;
                // Conservative equality avoids treating schedules and context names as wildcards.
                if (!optional.All(c => prior.Get(c) == current.Get(c)))
                    continue;
                found.Add(current);
                break;
            }
        }
        return found;
    }
    public static List<PolicyRule> AddressOverlapCandidates(IReadOnlyList<PolicyRule> rules, string column, CancellationToken token = default)
    {
        var parsed = rules.Select(r => Network.TryParse(r.Get(column))).ToArray();
        var found = new List<PolicyRule>();
        for (int i = 0; i < rules.Count; i++)
        {
            token.ThrowIfCancellationRequested();
            if (parsed[i] is not { } current)
                continue;
            for (int j = 0; j < i; j++)
                if (parsed[j] is { } previous && previous.Contains(current))
                {
                    found.Add(rules[i]);
                    break;
                }
        }
        return found;
    }
    private sealed record Network(byte[] Bytes, int Prefix)
    {
        public static Network? TryParse(string text)
        {
            var parts = text.Split('/');
            if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var ip))
                return null;
            var bytes = ip.GetAddressBytes();
            int prefix = bytes.Length * 8;
            if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > bytes.Length * 8))
                return null;
            return new(bytes, prefix);
        }
        public bool Contains(Network other)
        {
            if (Bytes.Length != other.Bytes.Length || Prefix > other.Prefix)
                return false;
            int full = Prefix / 8;
            for (int i = 0; i < full; i++)
                if (Bytes[i] != other.Bytes[i])
                    return false;
            int remaining = Prefix % 8;
            return remaining == 0 || ((Bytes[full] ^ other.Bytes[full]) & (255 << (8 - remaining))) == 0;
        }
    }
}
