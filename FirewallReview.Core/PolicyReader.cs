using ClosedXML.Excel;
using Microsoft.VisualBasic.FileIO;
namespace FirewallReview.Core;

public static class PolicyReader
{
    public static async Task<PolicyInput> ReadAsync(string path, FirewallVendor vendor = FirewallVendor.Auto, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        if (!File.Exists(path))
            throw new FileNotFoundException("Policy export not found.", path);
        if (new FileInfo(path).Length > 128L * 1024 * 1024)
            throw new InvalidDataException("Policy export exceeds 128 MiB.");
        var extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is ".txt" or ".conf" or ".cfg")
            return PanosParser.Parse(await File.ReadAllTextAsync(path, token), token);
        List<string[]> data = [];
        if (extension == ".csv")
        {
            using var parser = new TextFieldParser(path);
            parser.SetDelimiters(",");
            parser.HasFieldsEnclosedInQuotes = true;
            parser.TrimWhiteSpace = false;
            while (!parser.EndOfData)
            {
                token.ThrowIfCancellationRequested();
                var fields = parser.ReadFields();
                if (fields is not null)
                    data.Add(fields.Select(f=>f.Replace("\r\n","\n").Replace('\r','\n')).ToArray());
                if (data.Count > 100001)
                    throw new InvalidDataException("Policy export exceeds 100,000 rules.");
            }
        }
        else if (extension == ".xlsx")
        {
            using var workbook = new XLWorkbook(path);
            var sheet = workbook.Worksheets.FirstOrDefault(s => s.Name == "Master Sheet") ?? workbook.Worksheets.FirstOrDefault(s => s.RangeUsed() != null) ?? throw new InvalidDataException("Workbook has no data.");
            var range = sheet.RangeUsed()!;
            if (range.RowCount() > 100001 || range.ColumnCount() > 500)
                throw new InvalidDataException("Policy workbook exceeds import limits.");
            foreach (var row in range.Rows())
            {
                token.ThrowIfCancellationRequested();
                data.Add(row.Cells().Select(c => c.GetFormattedString()).ToArray());
            }
        }
        else
            throw new InvalidDataException("Use a CSV, XLSX or Palo Alto CLI text export.");
        if (data.Count < 2)
            throw new InvalidDataException("The export has no policy rows.");
        var headers = data[0].Select(h => h.Trim().TrimStart('\uFEFF')).ToArray();
        if (headers.Any(string.IsNullOrWhiteSpace) || headers.Distinct(StringComparer.OrdinalIgnoreCase).Count() != headers.Length)
            throw new InvalidDataException("Headers must be nonempty and unique.");
        var palo = headers.Any(h => new[] { "Rule Usage Hit Count", "Rule Usage Rule Usage", "URL Category", "Source Zone", "Last Hit Date" }.Contains(h, StringComparer.OrdinalIgnoreCase));
        var forti = headers.Any(h => new[] { "Policy", "Security Profiles", "Hit Count", "From" }.Contains(h, StringComparer.OrdinalIgnoreCase));
        if (vendor == FirewallVendor.Auto)
        {
            if (palo == forti)
                throw new InvalidDataException("Vendor is ambiguous or unrecognized; select Palo Alto or Fortinet explicitly.");
            vendor = palo ? FirewallVendor.PaloAlto : FirewallVendor.Fortinet;
        }
        var required = vendor == FirewallVendor.PaloAlto ? new[] { "Name", "Source Zone", "Source Address", "Destination Zone", "Destination Address", "Application", "Service", "URL Category", "Action", "Profile", "Options", "Tags" } : new[] { "Status", "From", "Source", "To", "Destination", "Service", "Action", "Security Profiles", "Log", "Hit Count" };
        var missing = required.Where(h => !headers.Contains(h, StringComparer.OrdinalIgnoreCase)).ToList();
        if (vendor == FirewallVendor.PaloAlto && !headers.Contains("Rule Usage Hit Count", StringComparer.OrdinalIgnoreCase) && !headers.Contains("Rule Usage Rule Usage", StringComparer.OrdinalIgnoreCase))
            missing.Add("Rule Usage Hit Count");
        if (vendor == FirewallVendor.Fortinet && !headers.Contains("Name", StringComparer.OrdinalIgnoreCase) && !headers.Contains("Policy", StringComparer.OrdinalIgnoreCase))
            missing.Add("Name or Policy");
        if (missing.Count > 0)
            throw new InvalidDataException("Missing required columns: " + string.Join(", ", missing));
        var rules = new List<PolicyRule>();
        for (int i = 1; i < data.Count; i++)
        {
            token.ThrowIfCancellationRequested();
            if (data[i].Length != headers.Length)
                throw new InvalidDataException($"Row {i + 1} has {data[i].Length} fields; expected {headers.Length}.");
            rules.Add(new(i, headers.Select((h, j) => (h, data[i][j])).ToDictionary(x => x.h, x => x.Item2, StringComparer.OrdinalIgnoreCase)));
        }
        return new(vendor, rules, []);
    }
}
