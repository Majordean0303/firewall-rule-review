using ClosedXML.Excel;
using FirewallReview.Core;
namespace FirewallReview.Tests;

public class ComplianceTests
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
    private const string Forti = """
    config system global
        set admintimeout 0
    end
    config system password-policy
        set status enable
        set minimum-length 8
    end
    config vdom
        edit "customer-a"
            config firewall policy
                edit 10
                    set name "internet access"
                    set srcintf "lan"
                    set dstintf "wan"
                    set srcaddr "all"
                    set dstaddr "all"
                    set service "ALL"
                    set action accept
                    set status enable
                    set logtraffic disable
                    set utm-status disable
                    set comments "Approved exception"
                next
            end
        next
        edit "customer-b"
            config firewall policy
                edit 10
                    set srcintf "lan"
                    set dstintf "wan"
                    set srcaddr "all"
                    set dstaddr "all"
                    set service "ALL"
                    set action deny
                next
            end
        next
    end
    """;
    [Fact]
    public void Forti_parser_keeps_vdom_scope_and_reports_explicit_bad_settings()
    {
        var input = FortiConfigParser.Parse(Forti);
        Assert.Equal(2, input.Rules.Count);
        Assert.Equal("customer-a", input.Rules[0].Get("VDOM"));
        Assert.Equal("customer-b", input.Rules[1].Get("VDOM"));
        Assert.Equal("unknown", input.Rules[0].Get("Hit Count"));
        Assert.Equal("Fail", input.Cis!["idle_timeout"].Status);
        Assert.Equal("Fail", input.Cis["pwd_complexity"].Status);
        var report = ReviewEngine.Analyze(input, "Forti");
        Assert.Empty(report.Tables["Shadowed Rules"]);
        Assert.Equal(0, report.Metrics["zero_hit_rules"]);
        Assert.Equal(9, report.Compliance.Select(r => r.Framework).Distinct().Count());
        Assert.All(report.Compliance.Where(r => r.Check == "NET-01"), r => Assert.Equal("Finding", r.Status));
        Assert.All(report.Compliance.Where(r => r.Check == "REV-01"), r => Assert.Equal("Needs evidence", r.Status));
        Assert.All(report.Compliance.Where(r => r.Check == "LOG-01"), r => Assert.Equal("Finding", r.Status));
    }
    [Fact]
    public void Forti_incomplete_structure_is_rejected()
    {
        Assert.Throws<InvalidDataException>(() => FortiConfigParser.Parse("config firewall policy\nedit 1\nset action accept"));
        Assert.Throws<InvalidDataException>(() => FortiConfigParser.Parse("config firewall policy\nedit 1\nend\nnext"));
    }
    [Fact]
    public void Forti_sections_with_omitted_settings_cannot_pass()
    {
        var input = FortiConfigParser.Parse(Forti.Replace("set admintimeout 0", "").Replace("set minimum-length 8", ""));
        Assert.Equal("Unknown", input.Cis!["idle_timeout"].Status);
        Assert.Equal("Unknown", input.Cis["pwd_complexity"].Status);
    }
    [Fact]
    public void Scoped_bad_settings_cannot_be_overwritten_by_later_good_settings()
    {
        var input = FortiConfigParser.Parse(Forti + "\nconfig system global\nset admintimeout 5\nend\n");
        Assert.Equal("Fail", input.Cis!["idle_timeout"].Status);
    }
    [Fact]
    public async Task Policy_only_evidence_does_not_claim_configuration_or_organization_compliance()
    {
        var report = ReviewEngine.Analyze(await PolicyReader.ReadAsync(Fixture("palo.csv")), "Test");
        Assert.All(report.Compliance.Where(r => r.Check.StartsWith("CFG-")), r => Assert.Equal("Needs evidence", r.Status));
        Assert.All(report.Compliance.Where(r => r.Check == "MAN-01"), r => Assert.Equal("Manual review", r.Status));
        Assert.DoesNotContain(report.Compliance, r => r.Status is "Compliant" or "Pass");
        Assert.All(report.Compliance, r => { Assert.NotEmpty(r.Source); Assert.NotEmpty(r.Recommendation); Assert.NotEmpty(r.RequiredEvidence); });
    }
    [Fact]
    public async Task Logging_and_profile_unknown_values_are_evidence_gaps()
    {
        var input = await PolicyReader.ReadAsync(Fixture("palo.csv"));
        foreach (var rule in input.Rules)
        {
            rule.Fields["Options"] = "unknown";
            rule.Fields["Profile"] = "unknown";
        }
        var report = ReviewEngine.Analyze(input, "Test");
        Assert.All(report.Compliance.Where(r => r.Check is "LOG-01" or "NET-03"), r => Assert.Equal("Needs evidence", r.Status));
    }
    [Fact]
    public async Task Invalid_counter_and_unknown_justification_are_not_clean_evidence()
    {
        var input = await PolicyReader.ReadAsync(Fixture("palo.csv"));
        foreach (var rule in input.Rules) { rule.Fields["Rule Usage Hit Count"] = "not-a-number"; rule.Fields["NIST Documented"] = "unknown"; }
        var report = ReviewEngine.Analyze(input, "Test");
        Assert.All(report.Compliance.Where(r => r.Check is "REV-01" or "REV-02"), r => Assert.Equal("Needs evidence", r.Status));
    }
    [Fact]
    public async Task Export_contains_framework_summary_evidence_and_collection_guide()
    {
        var report = ReviewEngine.Analyze(await PolicyReader.ReadAsync(Fixture("palo.csv")), "Test");
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".xlsx");
        try
        {
            WorkbookExport.Write(report, path);
            using var book = new XLWorkbook(path);
            Assert.Equal(11, book.Worksheet("Compliance Summary").LastRowUsed()!.RowNumber());
            Assert.Equal(report.Compliance.Count + 1, book.Worksheet("Compliance Evidence").LastRowUsed()!.RowNumber());
            Assert.Contains("show full-configuration", book.Worksheet("Required Evidence").Cell(1, 1).GetString());
            Assert.Contains("Compliance", WorkbookExport.Json(report));
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task Text_import_detects_Forti_and_rejects_vendor_mismatch()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".conf");
        try
        {
            await File.WriteAllTextAsync(path, Forti);
            Assert.Equal(FirewallVendor.Fortinet, (await PolicyReader.ReadAsync(path)).Vendor);
            await Assert.ThrowsAsync<InvalidDataException>(() => PolicyReader.ReadAsync(path, FirewallVendor.PaloAlto));
        }
        finally { File.Delete(path); }
    }
    [Theory]
    [InlineData(FirewallVendor.PaloAlto)]
    [InlineData(FirewallVendor.Fortinet)]
    public async Task Templates_have_accepted_headers(FirewallVendor vendor)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".csv");
        try
        {
            var header = EvidenceGuide.Headers(vendor);
            await File.WriteAllTextAsync(path, header + "\n" + string.Join(",", header.Split(',').Select(_ => "unknown")));
            Assert.Single((await PolicyReader.ReadAsync(path, vendor)).Rules);
        }
        finally { File.Delete(path); }
    }
}
