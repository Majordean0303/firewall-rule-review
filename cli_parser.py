import re
import pandas as pd

class PaloAltoCLIParser:
    def __init__(self, raw_text):
        self.raw_text = raw_text
        self.rules_dict = {}
        self.hit_counts = {}
        
        # NEW: NIST 800-41 Level 2 Telemetry Payload
        self.nist_metrics = {
            'sw_version': 'Not Found (Please run "show system info")',
            'default_deny_enforced': False,
            'insecure_mgt_profiles': []
        }

    def parse(self):
        """Executes the extraction and returns a DataFrame + NIST Metrics."""
        parsed_config = self._parse_panos_braces(self.raw_text)
        
        self._extract_system_info()
        self._extract_security_rules(parsed_config)
        self._extract_mgt_profiles(parsed_config)
        self._check_default_deny()
        self._extract_hit_counts()
        
        return self._to_dataframe(), self.nist_metrics

    def _parse_panos_braces(self, raw_text):
        """Stack parser that converts PAN-OS curly braces into a nested dictionary."""
        root = {}
        stack = [root]
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith('=~') or line.startswith('['): continue
                
            if line.endswith('{'):
                raw_key = line[:-1].strip()
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
                if key not in stack[-1]: stack[-1][key] = new_dict
                stack.append(new_dict)
                
            elif line.endswith('}'):
                if len(stack) > 1: stack.pop()
                    
            elif line.endswith(';'):
                clean_line = line[:-1].strip()
                parts = clean_line.split(' ', 1)
                if len(parts) == 2: stack[-1][parts[0]] = parts[1].strip('"\'')
                else: stack[-1][parts[0]] = True
        return root

    def _extract_system_info(self):
        """NIST FEATURE: Extracts Firmware Version for Patch Management."""
        sw_match = re.search(r'^sw-version:\s*(\S+)', self.raw_text, re.MULTILINE)
        if sw_match:
            self.nist_metrics['sw_version'] = sw_match.group(1)

    def _extract_mgt_profiles(self, parsed_dict):
        """NIST FEATURE: Hunts for Interface Management Profiles with Telnet/HTTP enabled."""
        def search_profiles(d):
            if not isinstance(d, dict): return
            for k, v in d.items():
                if k == 'interface-management-profile' and isinstance(v, dict):
                    for prof_name, prof_data in v.items():
                        if isinstance(prof_data, dict):
                            insecure = []
                            if prof_data.get('telnet') == 'yes': insecure.append('Telnet')
                            if prof_data.get('http') == 'yes': insecure.append('HTTP (Cleartext)')
                            if insecure:
                                self.nist_metrics['insecure_mgt_profiles'].append(f"{prof_name} ({', '.join(insecure)})")
                elif isinstance(v, dict):
                    search_profiles(v)
        search_profiles(parsed_dict)

    def _check_default_deny(self):
        """NIST FEATURE: Checks if the final explicit rule is an ANY/ANY Deny."""
        if not self.rules_dict: return
        last_rule_name = list(self.rules_dict.keys())[-1]
        last_rule = self.rules_dict[last_rule_name]
        
        action = last_rule.get('action', 'deny')
        src = last_rule.get('source', 'any')
        dst = last_rule.get('destination', 'any')
        
        # If the last rule is a deny all, the firewall is correctly "Deny by Default"
        if action == 'deny' and (src == 'any' or src is True) and (dst == 'any' or dst is True):
            self.nist_metrics['default_deny_enforced'] = True

    def _extract_security_rules(self, parsed_dict):
        """Recursively finds 'rules' dictionaries."""
        def search_dict(d):
            if not isinstance(d, dict): return
            for k, v in d.items():
                if k == 'security' and isinstance(v, dict) and 'rules' in v and isinstance(v['rules'], dict):
                    for rule_name, rule_data in v['rules'].items():
                        if isinstance(rule_data, dict):
                            self.rules_dict[rule_name] = rule_data
                elif isinstance(v, dict):
                    search_dict(v)
        search_dict(parsed_dict)

    def _extract_hit_counts(self):
        """Extracts Hit Counts by anchoring on the VSYS column."""
        hit_pattern = re.compile(r'^(.*?)\s+(vsys\d+|shared|-)\s+(\d+)\s+(.*)$', re.IGNORECASE)
        for line in self.raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith('Rule Name') or line.startswith('---'): continue
            match = hit_pattern.search(line)
            if match:
                raw_rule_name = match.group(1).strip()
                rule_name = raw_rule_name.strip('"\'')
                hit_count = match.group(3)
                remainder = match.group(4).strip()
                last_hit = 'none'
                if not remainder.startswith('-'):
                    date_match = re.search(r'^([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})', remainder)
                    if date_match: last_hit = date_match.group(1)
                    else: last_hit = remainder[:24].strip()
                self.hit_counts[rule_name.lower()] = {'count': hit_count, 'last_hit': last_hit}

    def _to_dataframe(self):
        """Formats the merged data for Pandas."""
        rows = []
        for rule_name, rule_data in self.rules_dict.items():
            hit_info = self.hit_counts.get(rule_name.lower(), {'count': '0', 'last_hit': 'none'})
            
            def clean_val(val):
                if isinstance(val, dict): return ", ".join(str(k) for k in val.keys())
                if isinstance(val, str): return val.strip('[] "\'')
                return str(val)

            if rule_data.get('disabled') == 'yes': rule_name = f"{rule_name}_Disabled"

            # NIST FEATURE: Ensure the rule is documented
            desc = rule_data.get('description', '')
            is_documented = 'Yes' if desc else 'No'

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
                'Profile': 'Configured' if 'profile-setting' in rule_data else 'none',
                'Options': clean_val(rule_data.get('log-setting', 'none')),
                'Tags': 'Configured' if rule_data.get('tag') else 'none',
                'Rule Usage Hit Count': hit_info['count'],
                'Last Hit Date': hit_info['last_hit'],
                'NIST Documented': is_documented  # <-- New Column!
            }
            rows.append(row)
            
        return pd.DataFrame(rows)