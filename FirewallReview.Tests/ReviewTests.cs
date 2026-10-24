using System.Text.Json.Nodes;
using ClosedXML.Excel;
using FirewallReview.Core;
namespace FirewallReview.Tests;

public class ReviewTests
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
    [Theory]
    [InlineData("palo", "csv")]
    [InlineData("forti", "csv")]
    [InlineData("panos", "txt")]
    public async Task Native_metrics_match_reviewed_security_expectations(string name, string extension)
    {
        var input = await PolicyReader.ReadAsync(Fixture(name + "." + extension));
        var result = ReviewEngine.Analyze(input, "Synthetic");
        var expected = JsonNode.Parse(await File.ReadAllTextAsync(Fixture(name + "-expected.json")))!["metrics"]!.AsObject();
        Assert.Equal(expected.Count, result.Metrics.Count);
        foreach (var (key, value) in expected)
            Assert.Equal(value!.GetValue<int>(), result.Metrics[key]);
    }
    [Fact]
    public async Task Native_PANOS_rows_match_Python_parser()
    {
        var input = await PolicyReader.ReadAsync(Fixture("panos.txt"));
        var expected = JsonNode.Parse(await File.ReadAllTextAsync(Fixture("panos-expected.json")))!["rows"]!.AsArray();
        Assert.Equal(expected.Count, input.Rules.Count);
        for (int i = 0; i < expected.Count; i++)
        foreach (var (key, value) in expected[i]!.AsObject())
            Assert.Equal(value!.GetValue<string>(), input.Rules[i].Get(key));
        Assert.NotNull(input.Cis);
        Assert.All(input.Cis.Values, c => Assert.Equal("Pass", c.Status));
        Assert.Equal(true, input.Nist!["default_deny_enforced"]);
    }
    [Theory]
    [InlineData("192.0.2.0/24", "192.0.2.20", true)]
    [InlineData("192.0.2.10/24", "192.0.2.128/25", true)]
    [InlineData("192.0.2.0/25", "192.0.2.128/25", false)]
    [InlineData("192.0.2.0/24", "2001:db8::1", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::/48", true)]
    [InlineData("object-name", "192.0.2.1", false)]
    [InlineData("any", "192.0.2.1", false)]
    [InlineData("192.0.2.0/99", "192.0.2.1", false)]
    public void Address_overlap_candidates_use_subnet_math_without_resolving_objects(string first, string second, bool overlap)
    {
        var rows = new[] { new PolicyRule(1, new() { { "Source", first } }), new PolicyRule(2, new() { { "Source", second } }) };
        Assert.Equal(overlap, ReviewEngine.AddressOverlapCandidates(rows, "Source").Count == 1);
    }
    [Fact]
    public async Task Missing_hit_counts_are_unknown_rather_than_zero()
    {
        var raw = await File.ReadAllTextAsync(Fixture("panos.txt"));
        var input = PanosParser.Parse(raw[..raw.IndexOf("web-access vsys1", StringComparison.Ordinal)]);
        var report = ReviewEngine.Analyze(input, "No counters");
        Assert.Equal(0, report.Metrics["zero_hit_rules"]);
        Assert.Contains(report.CoverageNotes, n => n.Contains("Hit counters missing"));
    }
    [Fact]
    public void Missing_CIS_context_is_unknown()
    {
        var raw = "security {\nrules {\ntest {\nsource any;\naction deny;\n}\n}\n}";
        var input = PanosParser.Parse(raw);
        Assert.All(input.Cis!.Values, c => Assert.Equal("Unknown", c.Status));
    }
    [Fact]
    public async Task Workbook_contains_preserved_sheets_and_rule_values()
    {
        var report = ReviewEngine.Analyze(await PolicyReader.ReadAsync(Fixture("palo.csv")), "Synthetic");
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".xlsx");
        try
        {
            WorkbookExport.Write(report, path);
            using var book = new XLWorkbook(path);
            Assert.True(book.Worksheets.Contains("Master Sheet"));
            Assert.True(book.Worksheets.Contains("Shadowed Rules"));
            Assert.True(book.Worksheets.Contains("Bi-Directional Duplicates"));
            Assert.Equal(report.Rules.Count + 1, book.Worksheet("Master Sheet").LastRowUsed()!.RowNumber());
            Assert.Equal("broad", book.Worksheet("Master Sheet").Cell(2, 1).GetString());
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task Missing_headers_are_reported()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".csv");
        try
        {
            await File.WriteAllTextAsync(path, "Name,Source Zone\nname,trust");
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => PolicyReader.ReadAsync(path));
            Assert.Contains("Missing required columns", ex.Message);
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task Quoted_CSV_fields_and_embedded_newlines_are_preserved()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".csv");
        try
        {
            var text = await File.ReadAllTextAsync(Fixture("palo.csv"));
            text = text.Replace("unknown-object", "\"unknown,\nobject\"");
            await File.WriteAllTextAsync(path, text);
            var input = await PolicyReader.ReadAsync(path);
            Assert.Contains(input.Rules, r => r.Name == "unknown,\nobject");
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task Cancellation_propagates_without_reading()
    {
        using var c = new CancellationTokenSource();
        c.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PolicyReader.ReadAsync(Fixture("palo.csv"), token: c.Token));
    }
    [Fact]
    public async Task Unknown_rule_status_is_reported()
    {
        var input = await PolicyReader.ReadAsync(Fixture("forti.csv"));
        input.Rules[0].Fields["Status"] = "unknown";
        var report = ReviewEngine.Analyze(input, "unknown");
        Assert.Equal("Unknown status", report.Risk[input.Rules[0].Position]);
        Assert.Contains(report.CoverageNotes, n => n.Contains("unrecognized status"));
    }
    [Fact]
    public async Task Generated_workbook_can_be_reimported_from_its_master_sheet()
    {
        var report = ReviewEngine.Analyze(await PolicyReader.ReadAsync(Fixture("palo.csv")), "Synthetic");
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".xlsx");
        try
        {
            WorkbookExport.Write(report, path);
            var input = await PolicyReader.ReadAsync(path);
            Assert.Equal(report.Rules.Count, input.Rules.Count);
            using var book = new XLWorkbook(path);
            Assert.Equal(report.Metrics["total_rules"], book.Worksheet("Dashboard").Cell(3, 1).GetValue<int>());
        }
        finally { File.Delete(path); }
    }
}
