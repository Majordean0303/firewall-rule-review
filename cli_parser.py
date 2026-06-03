import re
import pandas as pd

class PaloAltoCLIParser:
    def __init__(self, raw_text):
        self.raw_text = raw_text
        self.rules_dict = {}
        self.hit_counts = {}

    def parse(self):
        """Executes the 3-pass extraction and returns a Pandas DataFrame."""
        parsed_config = self._parse_panos_braces(self.raw_text)
        self._extract_security_rules(parsed_config)
        self._extract_hit_counts()
        return self._to_dataframe()

    def _parse_panos_braces(self, raw_text):
        """Stack parser that converts PAN-OS curly braces into a nested dictionary."""
        root = {}
        stack = [root]
        
        for line in raw_text.splitlines():
            line = line.strip()
            
            if not line or line.startswith('=~') or line.startswith('['):
                continue
                
            if line.endswith('{'):
                raw_key = line[:-1].strip()
                
                # Cleanly extract the actual rule name, completely ignoring appended UUIDs
                if raw_key.startswith('"') or raw_key.startswith("'"):
                    quote_char = raw_key[0]
                    end_idx = raw_key.find(quote_char, 1)
                    if end_idx != -1:
                        key = raw_key[1:end_idx]
                    else:
                        key = raw_key.strip('"\'')
                else:
                    key = raw_key.split(' ')[0]
                    
                new_dict = {}
                if key not in stack[-1]:
                    stack[-1][key] = new_dict
                stack.append(new_dict)
                
            elif line.endswith('}'):
                if len(stack) > 1:
                    stack.pop()
                    
            elif line.endswith(';'):
                clean_line = line[:-1].strip()
                parts = clean_line.split(' ', 1)
                if len(parts) == 2:
                    stack[-1][parts[0]] = parts[1].strip('"\'')
                else:
                    stack[-1][parts[0]] = True
        return root

    def _extract_security_rules(self, parsed_dict):
        """Recursively finds 'rules' dictionaries nested inside any 'security' block."""
        def search_dict(d):
            if not isinstance(d, dict):
                return
            for k, v in d.items():
                if k == 'security' and isinstance(v, dict) and 'rules' in v and isinstance(v['rules'], dict):
                    for rule_name, rule_data in v['rules'].items():
                        if isinstance(rule_data, dict):
                            self.rules_dict[rule_name] = rule_data
                elif isinstance(v, dict):
                    search_dict(v)
                    
        search_dict(parsed_dict)

    def _extract_hit_counts(self):
        """Extracts Hit Counts by anchoring on the VSYS column to avoid spacing issues."""
        # This matches: [Rule Name] [vsys1/shared/-] [Hit Count] [Timestamps]
        hit_pattern = re.compile(r'^(.*?)\s+(vsys\d+|shared|-)\s+(\d+)\s+(.*)$', re.IGNORECASE)
        
        for line in self.raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith('Rule Name') or line.startswith('---'):
                continue
                
            match = hit_pattern.search(line)
            if match:
                raw_rule_name = match.group(1).strip()
                
                # In the hit count table, UUIDs are never appended. 
                # Just strip surrounding quotes if PAN-OS added them for rules with spaces.
                rule_name = raw_rule_name.strip('"\'')
                
                hit_count = match.group(3)
                remainder = match.group(4).strip()
                
                last_hit = 'none'
                if not remainder.startswith('-'):
                    # Extract the date using Regex (e.g., Wed Jun  3 21:54:54 2026)
                    date_match = re.search(r'^([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})', remainder)
                    if date_match:
                        last_hit = date_match.group(1)
                    else:
                        last_hit = remainder[:24].strip()
                        
                self.hit_counts[rule_name.lower()] = {
                    'count': hit_count,
                    'last_hit': last_hit
                }

    def _to_dataframe(self):
        """Formats the merged data exactly how your app.py CSV logic expects it."""
        rows = []
        for rule_name, rule_data in self.rules_dict.items():
            
            hit_info = self.hit_counts.get(rule_name.lower(), {'count': '0', 'last_hit': 'none'})
            
            def clean_val(val):
                if isinstance(val, dict):
                    return ", ".join(str(k) for k in val.keys())
                if isinstance(val, str):
                    return val.strip('[] "\'')
                return str(val)

            if rule_data.get('disabled') == 'yes':
                rule_name = f"{rule_name}_Disabled"

            profile = 'none'
            if 'profile-setting' in rule_data:
                profile = 'Configured'
                
            tags = rule_data.get('tag', 'none')
            if isinstance(tags, dict):
                tags = "Configured"

            row = {
                'Name': rule_name,
                'Source Zone': clean_val(rule_data.get('from', 'any')),
                'Source Address': clean_val(rule_data.get('source', 'any')),
                'Destination Zone': clean_val(rule_data.get('to', 'any')),
                'Destination Address': clean_val(rule_data.get('destination', 'any')),
                'Application': clean_val(rule_data.get('application', 'any')),
                'Service': clean_val(rule_data.get('service', 'application-default')),
                'URL Category': clean_val(rule_data.get('category', 'any')),
                'Action': clean_val(rule_data.get('action', 'deny')),
                'Profile': profile,
                'Options': clean_val(rule_data.get('log-setting', 'none')),
                'Tags': clean_val(tags),
                'Rule Usage Hit Count': hit_info['count'],
                'Last Hit Date': hit_info['last_hit'] 
            }
            rows.append(row)
            
        return pd.DataFrame(rows)