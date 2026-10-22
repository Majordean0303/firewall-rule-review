# Firewall Rule Review — Avalonia migration

The active migration uses .NET 10, a native C# analysis core and Avalonia. Import
Palo Alto/Fortinet CSV or XLSX exports, or Palo Alto brace-format CLI text; review
risk groups and policy evidence, inspect captured configuration benchmarks, and
export the preserved Excel worksheets or JSON. No Python process, web server or
browser is needed by the migrated app.

```powershell
dotnet run --project FirewallReview.Desktop
dotnet run --project FirewallReview.Cli -- policies.csv report.xlsx "Site name"
./scripts/test-all.ps1
./scripts/package.ps1 -Runtime win-x64
```

**Interpretation:** risk buckets preserve the existing analysis heuristics.
`Shadowed Rules` lists address-overlap candidates and requires a full review of
zones, services, applications, rule order and intent. Missing CLI counters are
unknown, not zero hits. Missing CIS context is unknown, not a passing control.
The app does not push configuration or delete rules.

The original Python files remain development parity references.
`scripts/capture-python-baseline.py` regenerates synthetic baseline fixtures
using development-only pandas/openpyxl. Read `MIGRATION_STATE.md` and
`CHANGELOG.md` for validation and morning review limitations.

---

## Previous implementation documentation

# Firewall Policy Analyzer & Telemetry Dashboard 🛡️

An automated Python native Windows Desktop application designed to eliminate the manual, tedious process of reviewing firewall rules in spreadsheets. 

This tool parses raw configurations or CSV/Excel exports from Palo Alto and Fortinet firewalls and intelligently extracts risk metrics, permissive access, high-risk ports, and stale configurations to generate a clean, client-ready Excel Telemetry Report.

## ✨ Key Features

* **Automated Risk Profiling:** Mathematically evaluates firewall rules and categorizes them into High, Medium, and Low risk threat levels based on permissive access ('ANY') and missing security profiles.
* **Smart Auto-Detection:** Automatically navigates and parses disparate CLI text files or CSV/Excel headers to detect if the upload is from Palo Alto Networks (PAN-OS / Panorama) or Fortinet (FortiOS / FortiManager).
* **Zero-Hit / Stale Rule Identification:** Automatically filters out disabled rules and identifies active policies that have zero hits to clean up firewall CPU cycles.
* **Modern Desktop GUI:** Built with `customtkinter` featuring a dark-mode interface, native OS file selection, and smooth background multi-threading so the UI never freezes during heavy calculations.

## 📋 Prerequisites

If running the Python source code directly, ensure you have:

* **Python 3.9 or higher** installed.
* **pip** (Python package installer).
* The following Python libraries:
  * `customtkinter`
  * `pandas`
  * `openpyxl`

*(If using the compiled `.exe`, no installation is required!)*

## 💻 Usage & Required Data Dumps

To generate a **100% complete** telemetry matrix, the tool requires specific output from the firewall.

When exporting your ruleset, you can export CLI text (for Palo Alto) or a `.csv` / `.xlsx` format. For tabular data, ensure the following columns are included depending on your vendor:

* **Palo Alto:** Name, Source Zone & Address, Destination Zone & Address, Application, Service, URL Category, Action, Profile, Options, Tags, and Rule Usage Hit Count.
* **Fortinet:** Name/Policy, Status, From, Source, To, Destination, Service, Action, Security Profiles, Log, and Hit Count.

### Workflow:

1. **Launch the Application:**
   Double-click the `FirewallRuleReview.exe` file located in the `dist/` directory.
2. Fill in the generic site details (Target Node / Site Name).
3. **Browse** for your `.txt`, `.csv` or `.xlsx` config files.
4. Click **"ANALYZE & GENERATE REPORT"**.
5. The application will process your file and automatically prompt you to save the resulting Excel workbook.

## 🗂️ Project Structure

* `main.py`: The native Desktop GUI application.
* `engine.py`: The core Pandas data processing and analytics engine.
* `cli_parser.py`: The regex parser for Palo Alto CLI outputs.
* `build_executable.py`: A script to compile the application into a standalone `.exe`.
* `splash.png`: Loading screen image used by PyInstaller.