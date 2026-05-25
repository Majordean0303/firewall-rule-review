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
def process_palo_alto_rules(df, output_path, site_name):
    disabled_df = df[df['Name'].astype(str).str.contains('Disabled', case=False, na=False)]
    active_df = df[~df['Name'].astype(str).str.contains('Disabled', case=False, na=False)]
    
    hit_col = 'Rule Usage Hit Count' if 'Rule Usage Hit Count' in df.columns else 'Rule Usage Rule Usage'
    zero_hit_df = active_df[
        (active_df[hit_col].astype(str).str.strip().str.lower() == 'unused') | 
        (active_df[hit_col] == 0) | (active_df[hit_col] == '0')
    ]
    
    active_hit_df = active_df.drop(zero_hit_df.index)
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
    
    is_zero_hit = (active_df[hit_col].astype(str).str.strip().str.lower() == 'unused') | (active_df[hit_col] == 0) | (active_df[hit_col] == '0')
    is_log_none = ~active_df['Options'].astype(str).str.contains('Log Forwarding Profile setting', case=False, na=False)
    is_tag_none = active_df['Tags'].astype(str).str.strip().str.lower() == 'none'
    
    high_mask = is_src_any | is_dst_any | is_srv_any | is_prof_none
    med_mask = (~high_mask) & (is_zero_hit | is_log_none | is_tag_none)
    low_mask = (~high_mask) & (~med_mask)

    metrics = {
        'total_rules': len(df), 'disabled_rules': len(disabled_df), 'active_rules': len(active_df),
        'zero_hit_rules': len(zero_hit_df), 'active_hit_rules': len(active_hit_df),
        'source_any': len(source_any_df), 'destination_any': len(dest_any_df),
        'service_any': len(service_any_df), 'profile_issue': len(profile_none_df),
        'logs_none': len(logs_none_df), 'tags_none': len(tags_none_df),
        'high_risk': int(high_mask.sum()), 'medium_risk': int(med_mask.sum()), 'low_risk': int(low_mask.sum())
    }

    generate_excel_report(output_path, site_name, metrics, df, disabled_df, active_df, zero_hit_df, active_hit_df, source_any_df, dest_any_df, service_any_df, profile_none_df, logs_none_df, tags_none_df)

    web_cols = ['Name', 'Source Zone', 'Source Address', 'Destination Zone', 'Destination Address', 'Application', 'Service', 'Action']
    web_cols = [col for col in web_cols if col in df.columns] 
    
    # NEW: Expanded web_data to include all dashboard metrics
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
        'tags_none': tags_none_df[web_cols].to_dict('records')
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
def generate_excel_report(output_path, site_name, metrics, df, disabled_df, active_df, zero_hit_df, active_hit_df, source_any_df, dest_any_df, service_any_df, profile_none_df, logs_none_df, tags_none_df):
    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        dashboard_data = [
            [site_name.upper(), "", ""],
            ["Total Rules", "Disabled Rules", "Active Rules"],
            [metrics['total_rules'], metrics['disabled_rules'], metrics['active_rules']],
            ["High Risk", "Medium Risk", "Low Risk"],
            [metrics['high_risk'], metrics['medium_risk'], metrics['low_risk']],
            ["Active Rules", "Zero Hit Review", "Active Hit Rules"],
            [metrics['active_rules'], metrics['zero_hit_rules'], metrics['active_hit_rules']],
            ["Active Hit Rules", "Source Any", "To be reviewed"],
            [metrics['active_hit_rules'], metrics['source_any'], metrics['source_any']],
            ["Active Hit Rules", "Destination Any", "To be reviewed"],
            [metrics['active_hit_rules'], metrics['destination_any'], metrics['destination_any']],
            ["Active Hit Rules", "Service Any", "To be reviewed"],
            [metrics['active_hit_rules'], metrics['service_any'], metrics['service_any']],
            ["Active Hit Rules", "Profile Issue", ""],
            [metrics['active_hit_rules'], metrics['profile_issue'], ""],
            ["Active Hit Rules", "Logs None", ""],
            [metrics['active_hit_rules'], metrics['logs_none'], ""],
            ["Active Hit Rules", "Tags None", ""],
            [metrics['active_hit_rules'], metrics['tags_none'], ""]
        ]
        dashboard_df = pd.DataFrame(dashboard_data)
        dashboard_df.to_excel(writer, sheet_name='Dashboard', index=False, header=False)
        
        df.to_excel(writer, sheet_name='Master Sheet', index=False)
        disabled_df.to_excel(writer, sheet_name='Disabled Rules', index=False)
        active_df.to_excel(writer, sheet_name='Active Rules', index=False)
        zero_hit_df.to_excel(writer, sheet_name='Zero Hit Rules', index=False)
        active_hit_df.to_excel(writer, sheet_name='Active Hit Rules', index=False)
        source_any_df.to_excel(writer, sheet_name='Source Any Rules', index=False)
        dest_any_df.to_excel(writer, sheet_name='Destination Any Rules', index=False)
        service_any_df.to_excel(writer, sheet_name='Service Any Rules', index=False)
        profile_none_df.to_excel(writer, sheet_name='Profile None', index=False)
        logs_none_df.to_excel(writer, sheet_name='Logs None', index=False)
        tags_none_df.to_excel(writer, sheet_name='Tags None', index=False)

        workbook = writer.book
        ws = writer.sheets['Dashboard']
        header_fill = PatternFill(start_color="2A3F54", end_color="2A3F54", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        center_align = Alignment(horizontal="center", vertical="center")
        thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))
        ws.column_dimensions['A'].width = 25
        ws.column_dimensions['B'].width = 25
        ws.column_dimensions['C'].width = 25
        ws['A1'].font = Font(size=14, bold=True) 
        
        header_rows = [2, 4, 6, 8, 10, 12, 14, 16, 18]
        for row in range(2, 20):
            for col in ['A', 'B', 'C']:
                cell = ws[f"{col}{row}"]
                cell.alignment = center_align
                cell.border = thin_border
                if row in header_rows:
                    cell.fill = header_fill
                    cell.font = header_font

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
                df = pd.read_csv(upload_path) if upload_path.endswith('.csv') else pd.read_excel(upload_path)
                df = df.fillna('')
                
                if 'Source Zone' in df.columns or 'Rule Usage Hit Count' in df.columns or 'Rule Usage Rule Usage' in df.columns:
                    metrics, web_data = process_palo_alto_rules(df, output_path, site_name)
                elif 'Policy' in df.columns or 'Hit Count' in df.columns and 'Action' in df.columns:
                    metrics, web_data = process_fortinet_rules(df, output_path, site_name)
                else:
                    raise ValueError("Unrecognized Firewall Dump Format. Cannot detect Palo Alto or Fortinet headers.")
                
                return render_template('summary.html', metrics=metrics, output_filename=output_filename, site_name=site_name, web_data=web_data)
                
            except Exception as e:
                flash(f"Error processing file: {str(e)}")
                return redirect(request.url)

    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(OUTPUT_FOLDER, filename)
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)