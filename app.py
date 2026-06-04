import os
import uuid
import pandas as pd
import threading
import time
from flask import Flask, request, render_template, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

app = Flask(__name__)
app.secret_key = 'secure_key_for_flash_messages'

UPLOAD_FOLDER = 'temp_uploads'
OUTPUT_FOLDER = 'temp_outputs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route('/api/system/restart', methods=['POST'])
def system_restart():
    if request.remote_addr != '127.0.0.1':
        return "Unauthorized", 403
    def kill_app():
        time.sleep(1)
        os._exit(0)
    threading.Thread(target=kill_app).start()
    return "Application is restarting to apply new code...", 200

# -------------------------------------------------------------------
# ENGINE 1: PALO ALTO PROCESSOR
# -------------------------------------------------------------------
def process_palo_alto_rules(df, output_path, site_name, nist_metrics=None):
    disabled_df = df[df['Name'].astype(str).str.contains('Disabled', case=False, na=False)]
    active_df = df[~df['Name'].astype(str).str.contains('Disabled', case=False, na=False)]
    
    hit_col = 'Rule Usage Hit Count' if 'Rule Usage Hit Count' in df.columns else 'Rule Usage Rule Usage'
    zero_hit_df = active_df[
        (active_df[hit_col].astype(str).str.strip().str.lower() == 'unused') | 
        (active_df[hit_col] == 0) | (active_df[hit_col] == '0')
    ]
    
    active_hit_df = active_df.drop(zero_hit_df.index)
    
    risky_pattern = r'(?i)(?:^|[-_\s])(22|23|3389|445|135|139|20|21|telnet|rdp|ssh|smb|ftp)(?:[-_\s]|$)'
    risky_ports_df = active_hit_df[
        active_hit_df['Service'].astype(str).str.contains(risky_pattern, regex=True, na=False) & 
        (active_hit_df['Action'].astype(str).str.strip().str.lower() == 'allow')
    ]
    
    # Extract Undocumented Rules (NIST Check)
    if 'NIST Documented' in active_hit_df.columns:
        undocumented_df = active_hit_df[active_hit_df['NIST Documented'].astype(str).str.strip().str.lower() == 'no']
    else:
        undocumented_df = pd.DataFrame()
    
    source_any_df = active_hit_df[active_hit_df['Source Address'].astype(str).str.strip().str.lower() == 'any']
    dest_any_df = active_hit_df[
        (active_hit_df['Destination Address'].astype(str).str.strip().str.lower() == 'any') & 
        (active_hit_df['Application'].astype(str).str.strip().str.lower() == 'any') & 
        (active_hit_df['URL Category'].astype(str).str.strip().str.lower() == 'any')
    ]
    service_any_df = active_hit_df[
        (active_hit_df['Service'].astype(str).str.strip().str.lower().isin(['any', 'application-default'])) & 
        (active_hit_df['Application'].astype(str).str.strip().str.lower() == 'any') & 
        (active_hit_df['URL Category'].astype(str).str.strip().str.lower() == 'any')
    ]
    
    logs_none_df = active_hit_df[~active_hit_df['Options'].astype(str).str.contains('Log Forwarding Profile setting', case=False, na=False)]
    tags_none_df = active_hit_df[active_hit_df['Tags'].astype(str).str.strip().str.lower() == 'none']
    profile_none_df = active_hit_df[active_hit_df['Profile'].astype(str).str.strip().str.lower() == 'none']

    is_src_any = active_df['Source Address'].astype(str).str.strip().str.lower() == 'any'
    is_dst_any = (active_df['Destination Address'].astype(str).str.strip().str.lower() == 'any') & (active_df['Application'].astype(str).str.strip().str.lower() == 'any') & (active_df['URL Category'].astype(str).str.strip().str.lower() == 'any')
    is_srv_any = (active_df['Service'].astype(str).str.strip().str.lower().isin(['any', 'application-default'])) & (active_df['Application'].astype(str).str.strip().str.lower() == 'any') & (active_df['URL Category'].astype(str).str.strip().str.lower() == 'any')
    is_prof_none = active_df['Profile'].astype(str).str.strip().str.lower() == 'none'
    is_risky_port = active_df['Service'].astype(str).str.contains(risky_pattern, regex=True, na=False) & (active_df['Action'].astype(str).str.strip().str.lower() == 'allow')
    
    is_zero_hit = (active_df[hit_col].astype(str).str.strip().str.lower() == 'unused') | (active_df[hit_col] == 0) | (active_df[hit_col] == '0')
    is_log_none = ~active_df['Options'].astype(str).str.contains('Log Forwarding Profile setting', case=False, na=False)
    is_tag_none = active_df['Tags'].astype(str).str.strip().str.lower() == 'none'
    
    high_mask = is_src_any | is_dst_any | is_srv_any | is_prof_none | is_risky_port
    med_mask = (~high_mask) & (is_zero_hit | is_log_none | is_tag_none)
    low_mask = (~high_mask) & (~med_mask)

    metrics = {
        'total_rules': len(df), 'disabled_rules': len(disabled_df), 'active_rules': len(active_df),
        'zero_hit_rules': len(zero_hit_df), 'active_hit_rules': len(active_hit_df),
        'source_any': len(source_any_df), 'destination_any': len(dest_any_df),
        'service_any': len(service_any_df), 'profile_issue': len(profile_none_df),
        'logs_none': len(logs_none_df), 'tags_none': len(tags_none_df),
        'risky_ports': len(risky_ports_df),
        'undocumented_rules': len(undocumented_df),
        'high_risk': int(high_mask.sum()), 'medium_risk': int(med_mask.sum()), 'low_risk': int(low_mask.sum())
    }

    # BUGFIX: We are now explicitly passing undocumented_df AND nist_metrics to the Excel generator!
    generate_excel_report(output_path, site_name, metrics, df, disabled_df, active_df, zero_hit_df, active_hit_df, source_any_df, dest_any_df, service_any_df, profile_none_df, logs_none_df, tags_none_df, risky_ports_df, undocumented_df, nist_metrics)

    web_cols = ['Name', 'Source Zone', 'Source Address', 'Destination Zone', 'Destination Address', 'Application', 'Service', 'Action', 'NIST Documented']
    web_cols = [col for col in web_cols if col in df.columns] 
    
    web_data = {
        'total': df[web_cols].to_dict('records'),
        'disabled': disabled_df[web_cols].to_dict('records'),
        'active': active_df[web_cols].to_dict('records'),
        'high_risk': active_df[high_mask][web_cols].to_dict('records'),
        'med_risk': active_df[med_mask][web_cols].to_dict('records'),
        'low_risk': active_df[low_mask][web_cols].to_dict('records'),
        'zero_hit': zero_hit_df[web_cols].to_dict('records'),
        'active_hit': active_hit_df[web_cols].to_dict('records'),
        'source_any': source_any_df[web_cols].to_dict('records'),
        'dest_any': dest_any_df[web_cols].to_dict('records'),
        'service_any': service_any_df[web_cols].to_dict('records'),
        'profile_issue': profile_none_df[web_cols].to_dict('records'),
        'logs_none': logs_none_df[web_cols].to_dict('records'),
        'tags_none': tags_none_df[web_cols].to_dict('records'),
        'risky_ports': risky_ports_df[web_cols].to_dict('records'),
        'undocumented': undocumented_df[web_cols].to_dict('records') if not undocumented_df.empty else [],
        'nist': nist_metrics or {}
    }
    return metrics, web_data

# -------------------------------------------------------------------
# ENGINE 2: FORTINET PROCESSOR
# -------------------------------------------------------------------
def process_fortinet_rules(df, output_path, site_name):
    disabled_df = df[df['Status'].astype(str).str.strip().str.lower() == 'disabled']
    active_df = df[df['Status'].astype(str).str.strip().str.lower() == 'enabled']
    
    zero_hit_df = active_df[(active_df['Hit Count'] == 0) | (active_df['Hit Count'].astype(str).str.strip() == '0')]
    active_hit_df = active_df.drop(zero_hit_df.index)
    
    source_any_df = active_hit_df[active_hit_df['Source'].astype(str).str.strip().str.lower() == 'all']
    dest_any_df = active_hit_df[active_hit_df['Destination'].astype(str).str.strip().str.lower() == 'all']
    service_any_df = active_hit_df[active_hit_df['Service'].astype(str).str.strip().str.lower() == 'all']
    
    profile_none_df = active_hit_df[
        (active_hit_df['Action'].astype(str).str.strip().str.upper() == 'ACCEPT') & 
        ((active_hit_df['Security Profiles'] == '') | (active_hit_df['Security Profiles'].astype(str).str.contains('no-inspection', case=False)))
    ]
    
    logs_none_df = active_hit_df[
        (active_hit_df['Log'] == '') | 
        (active_hit_df['Log'].astype(str).str.strip().str.lower() == 'disabled') |
        (active_hit_df['Log'].astype(str).str.strip().str.lower() == 'utm')
    ]
    
    tags_none_df = pd.DataFrame(columns=df.columns)

    is_accept = active_df['Action'].astype(str).str.strip().str.upper() == 'ACCEPT'
    is_src_all = active_df['Source'].astype(str).str.strip().str.lower() == 'all'
    is_dst_all = active_df['Destination'].astype(str).str.strip().str.lower() == 'all'
    is_srv_all = active_df['Service'].astype(str).str.strip().str.lower() == 'all'
    is_prof_none = is_accept & ((active_df['Security Profiles'] == '') | (active_df['Security Profiles'].astype(str).str.contains('no-inspection', case=False)))
    is_zero_hit = (active_df['Hit Count'] == 0) | (active_df['Hit Count'].astype(str).str.strip() == '0')
    
    is_log_disabled = (
        (active_df['Log'] == '') | 
        (active_df['Log'].astype(str).str.strip().str.lower() == 'disabled') |
        (active_df['Log'].astype(str).str.strip().str.lower() == 'utm')
    )
    
    high_mask = is_accept & (is_src_all | is_dst_all | is_srv_all | is_prof_none)
    med_mask = (~high_mask) & (is_zero_hit | is_log_disabled)
    low_mask = (~high_mask) & (~med_mask)

    metrics = {
        'total_rules': len(df), 'disabled_rules': len(disabled_df), 'active_rules': len(active_df),
        'zero_hit_rules': len(zero_hit_df), 'active_hit_rules': len(active_hit_df),
        'source_any': len(source_any_df), 'destination_any': len(dest_any_df),
        'service_any': len(service_any_df), 'profile_issue': len(profile_none_df),
        'logs_none': len(logs_none_df), 'tags_none': 0,
        'high_risk': int(high_mask.sum()), 'medium_risk': int(med_mask.sum()), 'low_risk': int(low_mask.sum())
    }

    generate_excel_report(output_path, site_name, metrics, df, disabled_df, active_df, zero_hit_df, active_hit_df, source_any_df, dest_any_df, service_any_df, profile_none_df, logs_none_df, tags_none_df)

    web_df = df.copy()
    web_df['Name'] = web_df['Name'] if 'Name' in web_df.columns else web_df['Policy']
    web_df['Source Zone'] = web_df['From']
    web_df['Source Address'] = web_df['Source']
    web_df['Destination Zone'] = web_df['To']
    web_df['Destination Address'] = web_df['Destination']
    web_df['Application'] = 'N/A' 
    web_df['Service'] = web_df['Service']
    web_df['Action'] = web_df['Action']
    
    web_cols = ['Name', 'Source Zone', 'Source Address', 'Destination Zone', 'Destination Address', 'Application', 'Service', 'Action']
    
    # NEW: Expanded web_data to include all dashboard metrics
    web_data = {
        'total': web_df[web_cols].to_dict('records'),
        'disabled': web_df.loc[disabled_df.index][web_cols].to_dict('records'),
        'active': web_df.loc[active_df.index][web_cols].to_dict('records'),
        'high_risk': web_df.loc[active_df[high_mask].index][web_cols].to_dict('records'),
        'med_risk': web_df.loc[active_df[med_mask].index][web_cols].to_dict('records'),
        'low_risk': web_df.loc[active_df[low_mask].index][web_cols].to_dict('records'),
        'zero_hit': web_df.loc[zero_hit_df.index][web_cols].to_dict('records'),
        'active_hit': web_df.loc[active_hit_df.index][web_cols].to_dict('records'),
        'source_any': web_df.loc[source_any_df.index][web_cols].to_dict('records'),
        'dest_any': web_df.loc[dest_any_df.index][web_cols].to_dict('records'),
        'service_any': web_df.loc[service_any_df.index][web_cols].to_dict('records'),
        'profile_issue': web_df.loc[profile_none_df.index][web_cols].to_dict('records'),
        'logs_none': web_df.loc[logs_none_df.index][web_cols].to_dict('records'),
        'tags_none': web_df.loc[tags_none_df.index][web_cols].to_dict('records')
    }
    return metrics, web_data

# -------------------------------------------------------------------
# SHARED EXCEL GENERATOR
# -------------------------------------------------------------------
def generate_excel_report(output_path, site_name, metrics, df, disabled_df, active_df, zero_hit_df, active_hit_df, source_any_df, dest_any_df, service_any_df, profile_none_df, logs_none_df, tags_none_df, risky_ports_df=None, undocumented_df=None, nist_metrics=None):
    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        
        # Build Standard Dashboard Data
        dashboard_data = [
            [site_name.upper(), "", ""],
            ["Total Rules", "Disabled Rules", "Active Rules"],
            [metrics.get('total_rules', 0), metrics.get('disabled_rules', 0), metrics.get('active_rules', 0)],
            ["High Risk", "Medium Risk", "Low Risk"],
            [metrics.get('high_risk', 0), metrics.get('medium_risk', 0), metrics.get('low_risk', 0)],
            ["Active Rules", "Zero Hit Review", "Active Hit Rules"],
            [metrics.get('active_rules', 0), metrics.get('zero_hit_rules', 0), metrics.get('active_hit_rules', 0)],
            ["Active Hit Rules", "Source Any", "To be reviewed"],
            [metrics.get('active_hit_rules', 0), metrics.get('source_any', 0), metrics.get('source_any', 0)],
            ["Active Hit Rules", "Destination Any", "To be reviewed"],
            [metrics.get('active_hit_rules', 0), metrics.get('destination_any', 0), metrics.get('destination_any', 0)],
            ["Active Hit Rules", "Service Any", "To be reviewed"],
            [metrics.get('active_hit_rules', 0), metrics.get('service_any', 0), metrics.get('service_any', 0)],
            ["Active Hit Rules", "Risky Mgmt Ports", "To be reviewed"],
            [metrics.get('active_hit_rules', 0), metrics.get('risky_ports', 0), metrics.get('risky_ports', 0)],
            ["Active Hit Rules", "NIST Violations (Undoc)", "To be reviewed"],
            [metrics.get('active_hit_rules', 0), metrics.get('undocumented_rules', 0), metrics.get('undocumented_rules', 0)],
            ["Active Hit Rules", "Profile Issue", ""],
            [metrics.get('active_hit_rules', 0), metrics.get('profile_issue', 0), ""],
            ["Active Hit Rules", "Logs None", ""],
            [metrics.get('active_hit_rules', 0), metrics.get('logs_none', 0), ""],
            ["Active Hit Rules", "Tags None", ""],
            [metrics.get('active_hit_rules', 0), metrics.get('tags_none', 0), ""]
        ]

        # NEW: Append NIST Telemetry to the bottom of the Excel Dashboard if it exists
        if nist_metrics:
            dashboard_data.extend([
                ["", "", ""],
                ["NIST 800-41 TELEMETRY", "", ""],
                ["Firmware Version", nist_metrics.get('sw_version', 'N/A'), ""],
                ["Default Deny Enforced", "Yes" if nist_metrics.get('default_deny_enforced') else "No", ""]
            ])
            insecure = nist_metrics.get('insecure_mgt_profiles', [])
            if insecure:
                dashboard_data.append(["Insecure Mgmt Profiles", ", ".join(insecure), ""])
            else:
                dashboard_data.append(["Insecure Mgmt Profiles", "None (Secured)", ""])

        dashboard_df = pd.DataFrame(dashboard_data)
        dashboard_df.to_excel(writer, sheet_name='Dashboard', index=False, header=False)
        
        # Write Standard Sheets
        df.to_excel(writer, sheet_name='Master Sheet', index=False)
        disabled_df.to_excel(writer, sheet_name='Disabled Rules', index=False)
        active_df.to_excel(writer, sheet_name='Active Rules', index=False)
        zero_hit_df.to_excel(writer, sheet_name='Zero Hit Rules', index=False)
        active_hit_df.to_excel(writer, sheet_name='Active Hit Rules', index=False)
        
        if risky_ports_df is not None:
            risky_ports_df.to_excel(writer, sheet_name='Risky Ports', index=False)
            
        # NEW: Write the NIST Violations sheet
        if undocumented_df is not None:
            undocumented_df.to_excel(writer, sheet_name='NIST Violations', index=False)
            
        source_any_df.to_excel(writer, sheet_name='Source Any Rules', index=False)
        dest_any_df.to_excel(writer, sheet_name='Destination Any Rules', index=False)
        service_any_df.to_excel(writer, sheet_name='Service Any Rules', index=False)
        profile_none_df.to_excel(writer, sheet_name='Profile None', index=False)
        logs_none_df.to_excel(writer, sheet_name='Logs None', index=False)
        tags_none_df.to_excel(writer, sheet_name='Tags None', index=False)

        # Apply Dynamic Excel Styling
        workbook = writer.book
        ws = writer.sheets['Dashboard']
        header_fill = PatternFill(start_color="2A3F54", end_color="2A3F54", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        center_align = Alignment(horizontal="center", vertical="center")
        thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))
        
        ws.column_dimensions['A'].width = 30
        ws.column_dimensions['B'].width = 30
        ws.column_dimensions['C'].width = 30
        ws['A1'].font = Font(size=14, bold=True) 
        
        # Dynamically color the rows so we don't have to hardcode header numbers!
        for row_idx, row_data in enumerate(dashboard_data, start=1):
            if row_data[0] == "": # Skip spacing rows
                continue
                
            for col_idx, col_letter in enumerate(['A', 'B', 'C']):
                cell = ws[f"{col_letter}{row_idx}"]
                cell.alignment = center_align
                if row_idx > 1: # Don't put a tight border on the Site Name
                    cell.border = thin_border
                    
            # Color header rows (even rows up to 22, plus the NIST title)
            is_standard_header = (row_idx % 2 == 0 and row_idx <= 22)
            is_nist_title = (row_data[0] == "NIST 800-41 TELEMETRY")
            
            if is_standard_header or is_nist_title:
                for col_letter in ['A', 'B', 'C']:
                    ws[f"{col_letter}{row_idx}"].fill = header_fill
                    ws[f"{col_letter}{row_idx}"].font = header_font
                    
# -------------------------------------------------------------------
# ROUTING & AUTO-DETECTION
# -------------------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        site_name = request.form.get('site_name', 'UNSPECIFIED TARGET').strip()
        if 'file' not in request.files:
            flash('No file uploaded.')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file.')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            unique_id = str(uuid.uuid4())[:8]
            upload_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}_{filename}")
            file.save(upload_path)

            output_filename = f"Reviewed_{site_name.replace(' ', '_')}_{unique_id}.xlsx"
            output_path = os.path.join(OUTPUT_FOLDER, output_filename)
            
            try:
                # ---------------------------------------------------------
                # NEW DATA INGESTION ENGINE
                # ---------------------------------------------------------
                nist_metrics = None # Initialize empty for CSVs
                
                if upload_path.endswith('.txt'):
                    from cli_parser import PaloAltoCLIParser
                    with open(upload_path, 'r', encoding='utf-8', errors='ignore') as f:
                        raw_text = f.read()
                    
                    cli_engine = PaloAltoCLIParser(raw_text)
                    # BUGFIX: Catch both the Dataframe AND the new NIST dictionary
                    df, nist_metrics = cli_engine.parse() 
                else:
                    df = pd.read_csv(upload_path) if upload_path.endswith('.csv') else pd.read_excel(upload_path)
                
                df = df.fillna('')
                
                # ---------------------------------------------------------
                # VENDOR VALIDATION & PROCESSING (Unchanged)
                # ---------------------------------------------------------
                is_palo = any(col in df.columns for col in ['Rule Usage Hit Count', 'Rule Usage Rule Usage', 'URL Category', 'Source Zone', 'Last Hit Date'])
                is_forti = any(col in df.columns for col in ['Policy', 'Security Profiles', 'Hit Count', 'From'])
                
                if is_palo:
                    required_pa = ['Name', 'Source Zone', 'Source Address', 'Destination Zone', 'Destination Address', 'Application', 'Service', 'Action', 'Profile', 'Options', 'Tags']
                    missing = [col for col in required_pa if col not in df.columns]
                    
                    if 'Rule Usage Hit Count' not in df.columns and 'Rule Usage Rule Usage' not in df.columns:
                        missing.append('Rule Usage Hit Count')
                    
                    if missing:
                        flash(f"Palo Alto Export Error - You are missing the following required columns: {', '.join(missing)}")
                        return redirect(request.url)
                        
                    metrics, web_data = process_palo_alto_rules(df, output_path, site_name, nist_metrics=nist_metrics)

                elif is_forti:
                    required_ft = ['Status', 'From', 'Source', 'To', 'Destination', 'Service', 'Action', 'Security Profiles', 'Log', 'Hit Count']
                    missing = [col for col in required_ft if col not in df.columns]
                    
                    if 'Name' not in df.columns and 'Policy' not in df.columns:
                        missing.append('Name (or Policy)')
                        
                    if missing:
                        flash(f"Fortinet Export Error - You are missing the following required columns: {', '.join(missing)}")
                        return redirect(request.url)
                        
                    metrics, web_data = process_fortinet_rules(df, output_path, site_name)
                    
                else:
                    flash("Unrecognized Format. Could not detect standard Palo Alto or Fortinet headers.")
                    return redirect(request.url)
                
                return render_template('summary.html', metrics=metrics, output_filename=output_filename, site_name=site_name, web_data=web_data)
                
            except Exception as e:
                flash(f"Processing Error: {str(e)}")
                return redirect(request.url)

    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(OUTPUT_FOLDER, filename)
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)