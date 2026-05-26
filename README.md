# Firewall Policy Analyzer & Telemetry Dashboard 🛡️

An automated Python and Flask-based internal tool designed to eliminate the manual, tedious process of reviewing firewall rules in spreadsheets. 

This tool parses raw CSV/Excel exports from Palo Alto and Fortinet firewalls and intelligently extracts risk metrics, permissive access, high-risk ports, and stale configurations to generate a clean, client-ready Excel Telemetry Report and an interactive Web Dashboard.

## ✨ Key Features

* **Automated Risk Profiling:** Mathematically evaluates firewall rules and categorizes them into High, Medium, and Low risk threat levels based on permissive access ('ANY') and missing security profiles.
* **Smart Auto-Detection:** Automatically navigates and parses disparate CSV/Excel headers to detect if the upload is from Palo Alto Networks (PAN-OS / Panorama) or Fortinet (FortiOS / FortiManager).
* **Zero-Hit / Stale Rule Identification:** Automatically filters out disabled rules and identifies active policies that have zero hits to clean up firewall CPU cycles.
* **Modern Web UI:** Built with custom CSS featuring a dark-mode "Glassmorphism" interface, interactive jQuery DataTables, and a dynamic Posture Health Score ring.

## 📋 Prerequisites

Before you begin, ensure you have the following ready on your local machine or server:

* **Python 3.9 or higher** installed.
* **pip** (Python package installer).
* Access to export firewall configurations in `.csv` or `.xlsx` format.
* The following Python libraries (can be installed via a `requirements.txt`):
  * `Flask`
  * `pandas`
  * `openpyxl`
  * `waitress`

## 💻 Usage & Required Data Dumps

To generate a **100% complete** telemetry matrix, the tool requires specific output from the firewall GUI or management server.

When exporting your ruleset, ensure you export to a `.csv` or `.xlsx` format and include the following columns depending on your vendor:

* **Palo Alto:** Name, Source Zone & Address, Destination Zone & Address, Application, Service, URL Category, Action, Profile, Options, Tags, and Rule Usage Hit Count.
* **Fortinet:** Name/Policy, Status, From, Source, To, Destination, Service, Action, Security Profiles, Log, and Hit Count.

### Workflow:

1. **Clone & Install:**
   ```bash
   git clone [https://github.com/YourUsername/firewall-policy-analyzer.git](https://github.com/YourUsername/firewall-policy-analyzer.git)
   cd firewall-policy-analyzer
   pip install -r requirements.txt
    ```

2. **Run the Application:**
```bash
python app.py

```


3. Open your web browser and navigate to `http://127.0.0.1:8080`.
4. Fill in the generic site details (Target Node / Site Name).
5. **Upload** your `.csv` or `.xlsx` config files into the upload zone.
6. Click **"Analyze & Generate"**.
7. Review the parsed data, risk metrics, and tables on the interactive web dashboard.
8. Click **"Export Report"** to download your complete multi-sheet Excel workbook.

## 🗂️ Project Structure

* `app.py`: The main Flask routing engine, Pandas risk-calculation logic, and Openpyxl Excel-export logic.
* `templates/index.html`: The Jinja2 HTML frontend for the upload gateway.
* `templates/summary.html`: The Jinja2 HTML frontend for the interactive telemetry dashboard and data tables.