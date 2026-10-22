using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using FirewallReview.Core;
namespace FirewallReview.Desktop;

public sealed record RuleRow(PolicyRule Rule, string Risk, FirewallVendor Vendor)
{
    public string Name => Rule.Name;
    public string Action => Rule.Get("Action");
    public string Source => Rule.Get(Vendor == FirewallVendor.PaloAlto ? "Source Address" : "Source");
    public string Destination => Rule.Get(Vendor == FirewallVendor.PaloAlto ? "Destination Address" : "Destination");
    public string Service => Rule.Get("Service");
    public string Hits => Rule.Get(Vendor == FirewallVendor.PaloAlto ? (Rule.Fields.ContainsKey("Rule Usage Hit Count") ? "Rule Usage Hit Count" : "Rule Usage Rule Usage") : "Hit Count");
    public string Evidence => string.Join(Environment.NewLine, Rule.Fields.Select(p => $"{p.Key}: {p.Value}"));
}
public partial class MainViewModel : UiOperation
{
    private ReviewResult? _result;
    public ObservableCollection<RuleRow> Rows { get; } = [];
    public ObservableCollection<string> Categories { get; } = [];
    public string[] VendorOptions { get; } = ["Auto-detect", "Palo Alto", "Fortinet"];
    [ObservableProperty] private int vendorIndex;
    [ObservableProperty] private string site = "Firewall review";
    [ObservableProperty] private string filename = "No policy export loaded";
    [ObservableProperty] private string summary = "Import Palo Alto CLI text or Palo Alto/Fortinet CSV and XLSX exports.";
    [ObservableProperty] private string coverage = "Risk groups are review heuristics; validate policy intent before changes.";
    [ObservableProperty] private string category = "Master Sheet";
    [ObservableProperty] private string search = "";
    [ObservableProperty] private RuleRow? selectedRule;
    [ObservableProperty] private string total = "—";
    [ObservableProperty] private string high = "—";
    [ObservableProperty] private string medium = "—";
    [ObservableProperty] private string low = "—";
    [ObservableProperty] private double zoom = 1;
    public bool HasReport => _result is not null;
    public IEnumerable<CisCheck> Benchmarks => _result?.Cis?.Values ?? Enumerable.Empty<CisCheck>();
    public string ConfigurationEvidence => _result?.Nist is null ? "No configuration benchmark evidence in this export." : string.Join(Environment.NewLine, _result.Nist.Select(p => $"{p.Key}: {(p.Value is IEnumerable<string> values ? string.Join(", ", values) : p.Value)}"));
    partial void OnCategoryChanged(string value) => Refresh();
    partial void OnSearchChanged(string value) => Refresh();
    private void Refresh()
    {
        Rows.Clear();
        if (_result is null)
            return;
        foreach (var rule in _result.Tables.GetValueOrDefault(Category, []).Where(r => string.Join(' ', r.Fields.Values).Contains(Search, StringComparison.OrdinalIgnoreCase)))
            Rows.Add(new(rule, _result.Risk[rule.Position], _result.Vendor));
        SelectedRule = Rows.FirstOrDefault();
    }
    public Task LoadAsync(string path) => RunAsync(async token => { Status = "Reading policies…"; var vendor = VendorIndex == 1 ? FirewallVendor.PaloAlto : VendorIndex == 2 ? FirewallVendor.Fortinet : FirewallVendor.Auto; var input = await Task.Run(() => PolicyReader.ReadAsync(path, vendor, token), token); var report = await Task.Run(() => ReviewEngine.Analyze(input, Site, token), token); token.ThrowIfCancellationRequested(); _result = report; Filename = Path.GetFileName(path); Total = report.Metrics["total_rules"].ToString(); High = report.Metrics["high_risk"].ToString(); Medium = report.Metrics["medium_risk"].ToString(); Low = report.Metrics["low_risk"].ToString(); Summary = $"{report.Vendor} · {report.Metrics["active_rules"]} active · {report.Metrics["disabled_rules"]} disabled · {report.Metrics["zero_hit_rules"]} zero-hit candidates"; Coverage = string.Join(Environment.NewLine, report.CoverageNotes); Categories.Clear(); foreach (var key in report.Tables.Keys) Categories.Add(key); Category = "Master Sheet"; Refresh(); OnPropertyChanged(nameof(HasReport)); OnPropertyChanged(nameof(Benchmarks)); OnPropertyChanged(nameof(ConfigurationEvidence)); Status = "Review ready"; });
    public Task ExportAsync(string path) => RunAsync(async token => { if (_result is null) throw new InvalidOperationException("Import a policy export first."); if (Path.GetExtension(path).Equals(".xlsx", StringComparison.OrdinalIgnoreCase)) await Task.Run(() => WorkbookExport.Write(_result, path, token), token); else await AtomicFile.WriteAsync(path, WorkbookExport.Json(_result), token); Status = "Report saved"; });
}
