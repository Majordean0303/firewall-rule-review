using FirewallReview.Core;
namespace FirewallReview.Tests;

public class LogicTests
{
    private static PolicyRule Rule(int position, params (string Key, string Value)[] changes)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Name"] = $"rule-{position}",
            ["Source Zone"] = "trust",
            ["Source Address"] = "10.0.0.0/8",
            ["Destination Zone"] = "untrust",
            ["Destination Address"] = "192.0.2.0/24",
            ["Application"] = "ssl",
            ["Service"] = "tcp/443",
            ["URL Category"] = "any",
            ["Action"] = "allow",
            ["Profile"] = "secure",
            ["Options"] = "forwarding-profile",
            ["Tags"] = "production",
            ["Rule Usage Hit Count"] = "1"
        };
        foreach (var (key, value) in changes)
            fields[key] = value;
        return new(position, fields);
    }
    private static ReviewResult Analyze(params PolicyRule[] rows) => ReviewEngine.Analyze(new(FirewallVendor.PaloAlto, rows.ToList(), []), "Test");

    [Theory]
    [InlineData("Source Zone", "dmz")]
    [InlineData("Destination Zone", "dmz")]
    [InlineData("Destination Address", "198.51.100.0/24")]
    [InlineData("Application", "web-browsing")]
    [InlineData("Service", "tcp/80")]
    public void Overlap_in_one_dimension_does_not_shadow(string field, string value)
    {
        Assert.Empty(Analyze(Rule(1), Rule(2, (field, value))).Tables["Shadowed Rules"]);
    }
    [Fact]
    public void One_prior_rule_must_cover_all_selectors()
    {
        Assert.Empty(Analyze(Rule(1, ("Destination Address", "198.51.100.0/24")),
            Rule(2, ("Source Address", "172.16.0.0/12")), Rule(3)).Tables["Shadowed Rules"]);
    }
    [Fact]
    public void Earlier_deny_shadows_later_allow_when_all_selectors_match()
    {
        var report = Analyze(Rule(1, ("Action", "deny"), ("Source Address", "any"), ("Service", "any")),
            Rule(2, ("Source Address", "10.1.1.1")));
        Assert.Equal(2, Assert.Single(report.Tables["Shadowed Rules"]).Position);
    }
    [Theory]
    [InlineData("Negate Source", "yes", "no")]
    [InlineData("Schedule", "work", "always")]
    [InlineData("VDOM", "root", "other")]
    [InlineData("Device Group", "parent", "child")]
    public void Constraints_and_context_boundaries_prevent_claims(string field, string first, string second)
    {
        Assert.Empty(Analyze(Rule(1, (field, first)), Rule(2, (field, second))).Tables["Shadowed Rules"]);
    }
    [Fact]
    public void Disabled_rules_do_not_shadow_or_rely_on_arbitrary_name_substrings()
    {
        var report = Analyze(Rule(1, ("Disabled", "yes")), Rule(2, ("Name", "Disabled-users")));
        Assert.Equal(1, report.Metrics["active_rules"]);
        Assert.Empty(report.Tables["Shadowed Rules"]);
    }
    [Theory]
    [InlineData("2001:db8::/32")]
    [InlineData("unresolved-object")]
    public void Different_address_families_and_unknown_objects_do_not_shadow(string address)
    {
        Assert.Empty(Analyze(Rule(1), Rule(2, ("Source Address", address))).Tables["Shadowed Rules"]);
    }
    [Fact]
    public void Lists_and_identical_objects_are_supported()
    {
        Assert.Single(Analyze(Rule(1, ("Source Address", "10.0.0.0/8, object-a")),
            Rule(2, ("Source Address", "10.1.1.1, object-a"))).Tables["Shadowed Rules"]);
    }
    [Fact]
    public void Zero_hit_rules_still_have_security_findings_but_deny_rules_do_not()
    {
        var report = Analyze(Rule(1, ("Source Address", "any"), ("Profile", ""), ("Rule Usage Hit Count", "0.0")),
            Rule(2, ("Source Address", "any"), ("Profile", "none"), ("Action", "deny")));
        Assert.Equal(1, report.Metrics["zero_hit_rules"]);
        Assert.Equal(1, report.Metrics["source_any"]);
        Assert.Equal(1, report.Metrics["profile_issue"]);
        Assert.Equal(1, report.Metrics["high_risk"]);
        Assert.Equal(0, report.Metrics["logs_none"]);
    }
    [Fact]
    public void Missing_and_formatted_counters_are_classified_correctly()
    {
        var report = Analyze(Rule(1, ("Rule Usage Hit Count", "unknown")), Rule(2, ("Rule Usage Hit Count", "1,000")));
        Assert.Equal(0, report.Metrics["zero_hit_rules"]);
        Assert.Equal(1, report.Metrics["active_hit_rules"]);
    }
    [Fact]
    public void Fortinet_requires_all_selectors_and_checks_unused_permit_rules()
    {
        var fields = new Dictionary<string, string>
        {
            ["Policy"] = "1",
            ["Status"] = "enable",
            ["From"] = "lan",
            ["To"] = "wan",
            ["Source"] = "all",
            ["Destination"] = "all",
            ["Service"] = "ALL",
            ["Action"] = "ACCEPT",
            ["Security Profiles"] = "",
            ["Log"] = "all",
            ["Hit Count"] = "0.0"
        };
        var second = new Dictionary<string, string>(fields) { ["Policy"] = "2", ["To"] = "dmz", ["Action"] = "DENY" };
        var report = ReviewEngine.Analyze(new(FirewallVendor.Fortinet, [new(1, fields), new(2, second)], []), "Forti");
        Assert.Empty(report.Tables["Shadowed Rules"]);
        Assert.Equal(1, report.Metrics["source_any"]);
        Assert.Equal(1, report.Metrics["profile_issue"]);
        second["To"] = "wan";
        Assert.Single(ReviewEngine.Analyze(new(FirewallVendor.Fortinet, [new(1, fields), new(2, second)], []), "Forti").Tables["Shadowed Rules"]);
    }
    [Fact]
    public void Shadow_scan_honors_cancellation()
    {
        using var source = new CancellationTokenSource();
        source.Cancel();
        Assert.Throws<OperationCanceledException>(() => ReviewEngine.ShadowedRules([Rule(1), Rule(2)], true, source.Token));
    }
}
