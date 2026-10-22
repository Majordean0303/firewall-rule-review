namespace FirewallReview.Core;

public enum FirewallVendor
{
    Auto, PaloAlto, Fortinet
}
public sealed record PolicyRule(int Position, Dictionary<string, string> Fields)
{
    public string Get(string key) => Fields.GetValueOrDefault(key, "").Trim();
    public string Name => Get("Name").Length > 0 ? Get("Name") : Get("Policy");
}
public sealed record CisCheck(string Status, string Value, string Desc);
public sealed record PolicyInput(FirewallVendor Vendor, List<PolicyRule> Rules, List<string> CoverageNotes, Dictionary<string, object?>? Nist = null, Dictionary<string, CisCheck>? Cis = null);
public sealed record ReviewResult(string Site, FirewallVendor Vendor, List<PolicyRule> Rules, Dictionary<string, int> Metrics, Dictionary<string, List<PolicyRule>> Tables, Dictionary<int, string> Risk, List<string> CoverageNotes, Dictionary<string, object?>? Nist, Dictionary<string, CisCheck>? Cis);
