using System.Text.RegularExpressions;
namespace FirewallReview.Core;

public static class PanosParser
{
    private sealed class Node : Dictionary<string, object?>
    {
    }
    private static string Text(object? value, string fallback = "") => value switch { null => fallback, Node n => string.Join(", ", n.Keys), bool b => b ? "True" : "False", _ => value.ToString()!.Trim('[', ']', ' ', '\"', '\'') };
    private static string Get(Node node, string key, string fallback = "") => Text(node.GetValueOrDefault(key), fallback);
    private static Node Child(Node node, string key) => node.GetValueOrDefault(key) as Node ?? new();
    private static IEnumerable<(string Key, Node Value)> Walk(Node root)
    {
        foreach (var (key, value) in root)
            if (value is Node n)
            {
                yield return (key, n);
                foreach (var item in Walk(n))
                    yield return item;
            }
    }
    public static PolicyInput Parse(string raw, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        var root = new Node();
        var stack = new Stack<Node>();
        stack.Push(root);
        var notes = new List<string>();
        foreach (var rawLine in raw.Split('\n'))
        {
            token.ThrowIfCancellationRequested();
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("=~") || line.StartsWith('['))
                continue;
            if (line.EndsWith('{'))
            {
                var key = line[..^1].Trim();
                if (key.StartsWith('"') || key.StartsWith('\''))
                {
                    var quote = key[0];
                    var end = key.IndexOf(quote, 1);
                    key = end >= 1 ? key[1..end] : key.Trim('"', '\'');
                }
                else
                    key = key.Split(' ')[0];
                var parent = stack.Peek();
                if (parent.GetValueOrDefault(key) is not Node child)
                {
                    child = new();
                    parent[key] = child;
                }
                stack.Push(child);
                if (stack.Count > 256)
                    throw new InvalidDataException("Configuration nesting exceeds 256 levels.");
            }
            else if (line.EndsWith('}'))
            {
                if (stack.Count > 1)
                    stack.Pop();
            }
            else if (line.EndsWith(';'))
            {
                var clean = line[..^1].Trim();
                var split = clean.IndexOf(' ');
                if (split >= 0)
                    stack.Peek()[clean[..split]] = clean[(split + 1)..].Trim('"', '\'');
                else
                    stack.Peek()[clean] = true;
            }
        }
        if (stack.Count > 1)
            notes.Add("Configuration contains unclosed braces; verify the complete export.");
        var rules = new Dictionary<string, Node>();
        foreach (var (key, node) in Walk(root))
            if (key == "security" && node.GetValueOrDefault("rules") is Node security)
                foreach (var (name, value) in security)
                    if (value is Node data)
                    {
                        if (rules.ContainsKey(name))
                            notes.Add($"Repeated rule name '{name}' across configuration contexts; last occurrence retained.");
                        rules[name] = data;
                    }
        var hits = new Dictionary<string, (string Count, string Last)>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in raw.Split('\n'))
        {
            var match = Regex.Match(line.Trim(), @"^(.*?)\s+(vsys\d+|shared|-)\s+(\d+)\s+(.*)$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));
            if (!match.Success)
                continue;
            var name = match.Groups[1].Value.Trim().Trim('"', '\'');
            var remainder = match.Groups[4].Value.Trim();
            var date = Regex.Match(remainder, @"^([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})");
            hits[name] = (match.Groups[3].Value, remainder.StartsWith('-') ? "none" : date.Success ? date.Groups[1].Value : remainder[..Math.Min(24, remainder.Length)].Trim());
        }
        var rows = new List<PolicyRule>();
        int position = 0;
        foreach (var (name, data) in rules)
        {
            token.ThrowIfCancellationRequested();
            var observed = hits.TryGetValue(name, out var hit);
            var ruleName = Get(data, "disabled") == "yes" ? name + "_Disabled" : name;
            rows.Add(new(++position, new(StringComparer.OrdinalIgnoreCase)
            {
                ["Name"] = ruleName,
                ["Disabled"] = Get(data, "disabled", "no"),
                ["Negate Source"] = Get(data, "negate-source", "no"),
                ["Negate Destination"] = Get(data, "negate-destination", "no"),
                ["Schedule"] = Get(data, "schedule", "none"),
                ["Source User"] = Get(data, "source-user", "any"),
                ["Source Zone"] = Get(data, "from", "any"),
                ["Source Address"] = Get(data, "source", "any"),
                ["Destination Zone"] = Get(data, "to", "any"),
                ["Destination Address"] = Get(data, "destination", "any"),
                ["Application"] = Get(data, "application", "any"),
                ["Service"] = Get(data, "service", "application-default"),
                ["URL Category"] = Get(data, "category", "any"),
                ["Action"] = Get(data, "action", "deny"),
                ["Profile"] = data.ContainsKey("profile-setting") ? "Configured" : "none",
                ["Options"] = Get(data, "log-setting", "none"),
                ["Tags"] = data.ContainsKey("tag") ? "Configured" : "none",
                ["Rule Usage Hit Count"] = observed ? hit.Count : "unknown",
                ["Last Hit Date"] = observed ? hit.Last : "unknown",
                ["NIST Documented"] = Get(data, "description").Length > 0 ? "Yes" : "No"
            }));
        }
        var nist = new Dictionary<string, object?> { { "sw_version", Regex.Match(raw, @"^sw-version:\s*(\S+)", RegexOptions.Multiline) is { Success: true } version ? version.Groups[1].Value : "Not Found (Please run \"show system info\")" }, { "default_deny_enforced", false } };
        var insecure = new List<string>();
        foreach (var (key, node) in Walk(root))
            if (key == "interface-management-profile")
                foreach (var (name, value) in node)
                    if (value is Node profile)
                    {
                        var protocols = new List<string>();
                        if (Get(profile, "telnet") == "yes")
                            protocols.Add("Telnet");
                        if (Get(profile, "http") == "yes")
                            protocols.Add("HTTP (Cleartext)");
                        if (protocols.Count > 0)
                            insecure.Add($"{name} ({string.Join(", ", protocols)})");
                    }
        nist["insecure_mgt_profiles"] = insecure;
        var last = rules.LastOrDefault(r => Get(r.Value, "disabled") != "yes");
        if (last.Value is not null)
            nist["default_deny_enforced"] = Get(last.Value, "action", "deny") == "deny" && Get(last.Value, "source", "any") is "any" or "True" && Get(last.Value, "destination", "any") is "any" or "True";
        var cis = new Dictionary<string, CisCheck> { { "idle_timeout", new("Unknown", "Not captured", "Admin Idle Timeout (≤ 10m)") }, { "login_banner", new("Unknown", "Not captured", "Legal Login Banner") }, { "pwd_complexity", new("Unknown", "Not captured", "Local Password Complexity") }, { "mgmt_acls", new("Unknown", "Not captured", "Management Interface ACLs") }, { "zone_protection", new("Unknown", "Not captured", "Untrust Zone Protection") } };
        foreach (var (key, node) in Walk(root))
        {
            if (key == "mgt-config")
            {
                var timeout = Get(Child(node, "authentication"), "idle-timeout");
                cis["idle_timeout"] = new(int.TryParse(timeout, out var minutes) && minutes <= 10 ? "Pass" : "Fail", int.TryParse(timeout, out _) ? timeout + " mins" : timeout == "never" ? "Never" : "Not Configured", cis["idle_timeout"].Desc);
                cis["login_banner"] = new(Get(node, "login-banner").Length > 0 ? "Pass" : "Fail", Get(node, "login-banner").Length > 0 ? "Configured" : "Not Configured", cis["login_banner"].Desc);
                var pwd = Child(node, "password-complexity");
                int.TryParse(Get(pwd, "minimum-length"), out var length);
                cis["pwd_complexity"] = Get(pwd, "enabled") == "yes" ? new(length >= 12 ? "Pass" : "Fail", length >= 12 ? $"Enforced (Min {length})" : $"Weak (Min {length})", cis["pwd_complexity"].Desc) : new("Fail", "Missing/Weak", cis["pwd_complexity"].Desc);
            }
            if (key == "interface-management-profile")
            {
                cis["mgmt_acls"] = new("Pass", "Secured", cis["mgmt_acls"].Desc);
                foreach (var (name, value) in node)
                    if (value is Node profile && (Get(profile, "ssh") == "yes" || Get(profile, "https") == "yes") && !profile.ContainsKey("permitted-ip"))
                        cis["mgmt_acls"] = new("Fail", "Open Profile: " + name, cis["mgmt_acls"].Desc);
            }
            if (key == "zone")
                foreach (var (name, value) in node)
                    if (value is Node zone && new[] { "untrust", "outside", "internet", "public" }.Any(s => name.Contains(s, StringComparison.OrdinalIgnoreCase)))
                    {
                        if (cis["zone_protection"].Status == "Unknown")
                            cis["zone_protection"] = new("Pass", "Secured", cis["zone_protection"].Desc);
                        if (!Child(zone, "network-profile").ContainsKey("zone-protection-profile"))
                            cis["zone_protection"] = new("Fail", "Missing on " + name, cis["zone_protection"].Desc);
                    }
        }
        if (rows.Count == 0)
            throw new InvalidDataException("No Palo Alto security rules found. Supply the complete brace-format security rule export.");
        return new(FirewallVendor.PaloAlto, rows, notes, nist, cis);
    }
}
