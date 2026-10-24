using ClosedXML.Excel;
using System.Text.Json;
namespace FirewallReview.Core;

public static class WorkbookExport
{
    public static string Json(ReviewResult report) => JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
    public static void Write(ReviewResult report, string path, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var temporary = full + "." + Guid.NewGuid().ToString("N") + ".xlsx";
        try
        {
            using var workbook = new XLWorkbook();
            var dashboard = workbook.AddWorksheet("Dashboard");
            var summaryRows = new object?[][] {
new object?[] {report.Site.ToUpperInvariant(),"",""},
new object?[] {"Total Rules","Disabled Rules","Active Rules"},
new object?[] {report.Metrics.GetValueOrDefault("total_rules",0),report.Metrics.GetValueOrDefault("disabled_rules",0),report.Metrics.GetValueOrDefault("active_rules",0)},
new object?[] {"High Risk","Medium Risk","Low Risk"},
new object?[] {report.Metrics.GetValueOrDefault("high_risk",0),report.Metrics.GetValueOrDefault("medium_risk",0),report.Metrics.GetValueOrDefault("low_risk",0)},
new object?[] {"Active Rules","Zero Hit Review","Active Hit Rules"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("zero_hit_rules",0),report.Metrics.GetValueOrDefault("active_hit_rules",0)},
new object?[] {"Active Rules","Source Any","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("source_any",0),report.Metrics.GetValueOrDefault("source_any",0)},
new object?[] {"Active Rules","Destination Any","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("destination_any",0),report.Metrics.GetValueOrDefault("destination_any",0)},
new object?[] {"Active Rules","Service Any","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("service_any",0),report.Metrics.GetValueOrDefault("service_any",0)},
new object?[] {"Active Rules","Cleartext Protocols","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("cleartext_ports",0),report.Metrics.GetValueOrDefault("cleartext_ports",0)},
new object?[] {"Active Rules","Admin Mgmt Ports","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("admin_ports",0),report.Metrics.GetValueOrDefault("admin_ports",0)},
new object?[] {"Active Rules","Bi-Directional Duplicates","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("bidirectional_rules",0),report.Metrics.GetValueOrDefault("bidirectional_rules",0)},
new object?[] {"Active Rules","Shadowed Rules (Phase 3)","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("shadowed_rules",0),report.Metrics.GetValueOrDefault("shadowed_rules",0)},
new object?[] {"Active Rules","NIST Violations (Undoc)","To be reviewed"},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("undocumented_rules",0),report.Metrics.GetValueOrDefault("undocumented_rules",0)},
new object?[] {"Active Rules","Profile Issue",""},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("profile_issue",0),""},
new object?[] {"Active Rules","Logs None",""},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("logs_none",0),""},
new object?[] {"Active Rules","Tags None",""},
new object?[] {report.Metrics.GetValueOrDefault("active_rules",0),report.Metrics.GetValueOrDefault("tags_none",0),""}
};
            int row = 1;
            foreach (var cells in summaryRows)
            {
                for (int c = 0; c < cells.Length; c++)
                {
                    if (cells[c] is int number)
                        dashboard.Cell(row, c + 1).Value = number;
                    else
                        dashboard.Cell(row, c + 1).Value = cells[c]?.ToString() ?? "";
                }
                row++;
            }
            row++;
            foreach (var note in report.CoverageNotes)
            {
                dashboard.Cell(row++, 1).Value = note;
            }
            if (report.Nist is not null)
            {
                dashboard.Cell(++row, 1).Value = "NIST 800-41 TELEMETRY";
                foreach (var (key, value) in report.Nist)
                {
                    dashboard.Cell(++row, 1).Value = key;
                    dashboard.Cell(row, 2).Value = value is IEnumerable<string> list ? string.Join(", ", list) : value?.ToString() ?? "Unknown";
                }
            }
            if (report.Cis is not null)
            {
                dashboard.Cell(++row, 1).Value = "CIS PAN-OS BENCHMARKS";
                foreach (var c in report.Cis.Values)
                {
                    dashboard.Cell(++row, 1).Value = c.Desc;
                    dashboard.Cell(row, 2).Value = c.Status;
                    dashboard.Cell(row, 3).Value = c.Value;
                }
            }
            dashboard.Column(1).Width = 58;
            dashboard.Column(2).Width = 40;
            dashboard.Column(3).Width = 40;
            dashboard.Style.Alignment.WrapText = true;
            dashboard.Range(1, 1, 2, 3).Style.Fill.BackgroundColor = XLColor.FromHtml("#173E65");
            dashboard.Range(1, 1, 2, 3).Style.Font.FontColor = XLColor.White;
            dashboard.Range(1, 1, 2, 3).Style.Font.Bold = true;
            var headers = report.Rules.SelectMany(r => r.Fields.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            foreach (var (name, rules) in report.Tables)
            {
                token.ThrowIfCancellationRequested();
                var sheet = workbook.AddWorksheet(name);
                for (int c = 0; c < headers.Length; c++)
                    sheet.Cell(1, c + 1).Value = headers[c];
                for (int i = 0; i < rules.Count; i++)
                {
                    token.ThrowIfCancellationRequested();
                    for (int c = 0; c < headers.Length; c++)
                        sheet.Cell(i + 2, c + 1).Value = rules[i].Get(headers[c]);
                }
                if (headers.Length > 0)
                {
                    sheet.Range(1, 1, 1, headers.Length).Style.Font.Bold = true;
                    sheet.Range(1, 1, 1, headers.Length).Style.Fill.BackgroundColor = XLColor.FromHtml("#E8EEF6");
                    sheet.SheetView.FreezeRows(1);
                    sheet.Columns(1, headers.Length).Width = 24;
                    sheet.RangeUsed()?.SetAutoFilter();
                }
            }
            workbook.SaveAs(temporary);
            token.ThrowIfCancellationRequested();
            File.Move(temporary, full, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
