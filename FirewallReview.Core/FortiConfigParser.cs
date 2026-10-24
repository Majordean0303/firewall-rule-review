using System.Text.RegularExpressions;
namespace FirewallReview.Core;

public static class FortiConfigParser
{
    private sealed class Node(string kind, string name)
    {
        public string Kind { get; } = kind;
        public string Name { get; } = name;
        public Dictionary<string, string> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<Node> Children { get; } = [];
        public string Get(string key, string fallback = "unknown") => Values.GetValueOrDefault(key, fallback);
    }
    private static string Value(string text) => string.Join(", ", Regex.Matches(text, "\"([^\"]*)\"|([^\\s]+)", RegexOptions.None, TimeSpan.FromSeconds(1)).Select(m => m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value));
    public static PolicyInput Parse(string raw, CancellationToken token = default)
    {
        var root = new Node("root", "root");
        var stack = new Stack<Node>();
        stack.Push(root);
        foreach (var rawLine in raw.Split('\n'))
        {
            token.ThrowIfCancellationRequested();
            var line = rawLine.Trim();
            if (line.StartsWith("config ") || line.StartsWith("edit "))
            {
                if (stack.Count >= 128)
                    throw new InvalidDataException("FortiOS configuration nesting exceeds 128 levels.");
                var split = line.IndexOf(' ');
                var node = new Node(line[..split], line[(split + 1)..].Trim('"'));
                stack.Peek().Children.Add(node);
                stack.Push(node);
            }
            else if (line == "next" || line == "end")
            {
                var expected = line == "next" ? "edit" : "config";
                if (stack.Count == 1 || stack.Peek().Kind != expected)
                    throw new InvalidDataException("Unbalanced FortiOS config/edit/next/end structure.");
                stack.Pop();
            }
            else if (line.StartsWith("set "))
            {
                var parts = line[4..].Split(' ', 2);
                if (parts.Length == 2)
                    stack.Peek().Values[parts[0]] = Value(parts[1]);
            }
            else if (line.StartsWith("unset "))
                stack.Peek().Values.Remove(line[6..].Trim());
        }
        if (stack.Count != 1)
            throw new InvalidDataException("Incomplete FortiOS configuration: missing next/end. Export the complete configuration.");
        var rules = new List<PolicyRule>();
        var cis = new Dictionary<string, CisCheck>();
        var notes = new List<string> { "FortiOS configuration import: hit counters are unknown; named objects/groups are not expanded. Supply policy CSV counters for usage review. Missing explicit settings need evidence. Only config firewall policy is imported; policy6, local-in, proxy policies, NAT and routing are outside this scan." };
        void Record(string key, CisCheck check, string scope)
        {
            check = check with
            {
                Value = scope + ": " + check.Value
            };
            if (cis.TryGetValue(key, out var previous))
            {
                var status = previous.Status == "Fail" || check.Status == "Fail" ? "Fail" : previous.Status == "Unknown" || check.Status == "Unknown" ? "Unknown" : "Pass";
                check = check with
                {
                    Status = status,
                    Value = previous.Value + "; " + check.Value
                };
            }
            cis[key] = check;
        }
        void Visit(Node node, string vdom)
        {
            token.ThrowIfCancellationRequested();
            if (node.Name == "vdom" && node.Kind == "config")
            {
                foreach (var child in node.Children)
                    Visit(child, child.Name);
                return;
            }
            if (node.Kind == "config" && node.Name == "firewall policy")
                foreach (var policy in node.Children.Where(c => c.Kind == "edit"))
                {
                    if (rules.Count >= 100000)
                        throw new InvalidDataException("Policy export exceeds 100,000 rules.");
                    var profiles = new[] { "av-profile", "webfilter-profile", "ips-sensor", "application-list", "ssl-ssh-profile", "profile-group" }
                        .Where(policy.Values.ContainsKey).Select(k => policy.Get(k)).ToArray();
                    var inspection = policy.Get("utm-status") == "disable" ? "none" : profiles.Length > 0 ? string.Join(", ", profiles) : "unknown";
                    rules.Add(new(rules.Count + 1, new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Policy"] = policy.Name,
                        ["Name"] = policy.Get("name", policy.Name),
                        ["VDOM"] = vdom,
                        ["Status"] = policy.Get("status", "enable"),
                        ["Action"] = policy.Get("action", "deny"),
                        ["From"] = policy.Get("srcintf"),
                        ["To"] = policy.Get("dstintf"),
                        ["Source"] = policy.Get("srcaddr"),
                        ["Destination"] = policy.Get("dstaddr"),
                        ["Source User"] = policy.Get("users", policy.Get("groups", "any")),
                        ["Unsupported Constraints"] = new[] { "internet-service", "internet-service-src", "service-negate" }.Any(k => policy.Get(k) == "enable") ? "yes" : "no",
                        ["Service"] = policy.Get("service"),
                        ["Schedule"] = policy.Get("schedule"),
                        ["Negate Source"] = policy.Get("srcaddr-negate", "no") == "enable" ? "yes" : "no",
                        ["Negate Destination"] = policy.Get("dstaddr-negate", "no") == "enable" ? "yes" : "no",
                        ["Security Profiles"] = inspection,
                        ["Log"] = policy.Get("logtraffic") == "disable" ? "disabled" : policy.Get("logtraffic"),
                        ["Hit Count"] = "unknown",
                        ["Description"] = policy.Get("comments", "")
                    }));
                }
            if (node.Name == "system global" && node.Kind == "config")
            {
                var timeout = node.Get("admintimeout");
                Record("idle_timeout", new(int.TryParse(timeout, out var minutes) ? minutes is > 0 and <= 10 ? "Pass" : "Fail" : "Unknown", timeout, "Admin idle timeout (local review threshold: 1–10 minutes)"), vdom);
            }
            if (node.Name == "system password-policy" && node.Kind == "config")
            {
                var status = node.Get("status");
                var length = node.Get("minimum-length");
                Record("pwd_complexity", new(status == "disable" ? "Fail" : status == "enable" && int.TryParse(length, out var n) ? n >= 12 ? "Pass" : "Fail" : "Unknown", $"status={status}, minimum-length={length}", "Local password baseline (enabled; minimum 12 characters)"), vdom);
            }
            foreach (var child in node.Children)
                Visit(child, vdom);
        }
        Visit(root, "root");
        if (rules.Count == 0)
            throw new InvalidDataException("No config firewall policy entries found. Include the complete firewall policy section or use a policy CSV.");
        return new(FirewallVendor.Fortinet, rules, notes, null, cis);
    }
}
