#!/usr/bin/env python3
import argparse
import sys
import os
import pandas as pd
import xlsxwriter
from lxml import etree
from datetime import datetime

# Configuration for severity levels
SEVERITY_MAP = {
    0: 'Info',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
}

COLORS = {
    'Critical': '#D20F0F',  # Red
    'High': '#FF8000',      # Orange
    'Medium': '#FFCC00',    # Yellow
    'Low': '#00CC00',       # Green
    'Info': '#0000FF'       # Blue
}

def parse_args():
    parser = argparse.ArgumentParser(description='Parse Nessus XML v2 files into an Excel report.')
    parser.add_argument('-f', '--file', required=True, help='Path to the .nessus XML file')
    parser.add_argument('-o', '--output', help='Output Excel filename (default: nessus_report_YYYYMMDDHHMMSS.xlsx)')
    return parser.parse_args()

def parse_nessus_xml(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        sys.exit(1)

    try:
        tree = etree.parse(file_path)
    except Exception as e:
        print(f"Error parsing XML: {e}")
        sys.exit(1)

    root = tree.getroot()
    
    hosts_data = []
    vulnerabilities = []
    compliance_items = []
    
    report = root.find('Report')
    if report is None:
        print("Error: Invalid Nessus file format (no Report tag).")
        sys.exit(1)
        
    for report_host in report.findall('ReportHost'):
        host_props = {}
        host_properties = report_host.find('HostProperties')
        if host_properties is not None:
            for tag in host_properties.findall('tag'):
                host_props[tag.attrib.get('name')] = tag.text

        ip = host_props.get('host-ip', 'N/A')
        fqdn = host_props.get('host-fqdn', 'N/A')
        os_name = host_props.get('operating-system', 'N/A')
        
        # Determine host status (count vulns)
        host_vuln_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}

        for item in report_host.findall('ReportItem'):
            plugin_id = item.attrib.get('pluginID')
            plugin_name = item.attrib.get('pluginName')
            plugin_family = item.attrib.get('pluginFamily')
            severity = int(item.attrib.get('severity'))
            port = item.attrib.get('port')
            protocol = item.attrib.get('protocol')
            svc_name = item.attrib.get('svc_name')
            
            # Compliance checks often have pluginFamily "Policy Compliance"
            if plugin_family == 'Policy Compliance':
                compliance_dict = {
                    'File': file_path,
                    'IP Address': ip,
                    'FQDN': fqdn,
                    'Plugin ID': plugin_id,
                    'Severity': severity,
                    'Plugin Name': plugin_name,
                    'Audit File': item.findtext('cm:compliance-audit-file'),
                    'Check Name': item.findtext('cm:compliance-check-name'),
                    'Result': item.findtext('cm:compliance-result'),
                    'Actual Value': item.findtext('cm:compliance-actual-value'),
                    'Policy Value': item.findtext('cm:compliance-policy-value'),
                    'Info': item.findtext('cm:compliance-info'),
                    'Solution': item.findtext('cm:compliance-solution'),
                    'See Also': item.findtext('cm:compliance-see-also'),
                }
                compliance_items.append(compliance_dict)
                continue # Skip adding to regular vuln list/counts if purely compliance (per original script logic roughly)

            # Update counts
            host_vuln_counts[severity] += 1
            
            # Extract common fields
            description = item.findtext('description')
            solution = item.findtext('solution')
            synopsis = item.findtext('synopsis')
            cvss_base = item.findtext('cvss_base_score')
            cvss_vector = item.findtext('cvss_vector')
            exploit_ease = item.findtext('exploitability_ease')
            
            vuln_dict = {
                'File': file_path,
                'IP Address': ip,
                'FQDN': fqdn,
                'Port': port,
                'Protocol': protocol,
                'Service': svc_name,
                'Plugin ID': plugin_id,
                'Plugin Name': plugin_name,
                'Plugin Family': plugin_family,
                'Severity': severity,
                'Severity Label': SEVERITY_MAP.get(severity, 'Unknown'),
                'CVSS Base Score': cvss_base,
                'CVSS Vector': cvss_vector,
                'Description': description,
                'Solution': solution,
                'Synopsis': synopsis,
                'Exploitability Ease': exploit_ease
            }
            vulnerabilities.append(vuln_dict)
            
        hosts_data.append({
            'IP Address': ip,
            'FQDN': fqdn,
            'Operating System': os_name,
            'Critical': host_vuln_counts[4],
            'High': host_vuln_counts[3],
            'Medium': host_vuln_counts[2],
            'Low': host_vuln_counts[1],
            'Info': host_vuln_counts[0],
            'Total': sum(host_vuln_counts.values())
        })

    return hosts_data, vulnerabilities, compliance_items

def create_dashboard_chart(workbook, worksheet, hosts_data, vulnerabilities):
    # Prepare data for charts
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for v in vulnerabilities:
        label = SEVERITY_MAP.get(v['Severity'])
        if label:
            severity_counts[label] += 1
            
    # Writes summarized data for chart reference (hidden or side)
    # We'll place it at A20 for now
    worksheet.write('A20', 'Severity')
    worksheet.write('B20', 'Count')
    row = 20
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        worksheet.write(row, 0, sev)
        worksheet.write(row, 1, severity_counts[sev])
        row += 1
        
    chart = workbook.add_chart({'type': 'column'})
    chart.add_series({
        'name': 'Vulnerabilities by Severity',
        'categories': '=Home!$A$21:$A$25',
        'values': '=Home!$B$21:$B$25',
        'points': [
            {'fill': {'color': COLORS['Critical']}},
            {'fill': {'color': COLORS['High']}},
            {'fill': {'color': COLORS['Medium']}},
            {'fill': {'color': COLORS['Low']}},
            {'fill': {'color': COLORS['Info']}},
        ]
    })
    chart.set_title({'name': 'Scan Summary'})
    chart.set_style(10)
    worksheet.insert_chart('D2', chart)

def write_excel(hosts_data, vulnerabilities, compliance_items, output_file):
    writer = pd.ExcelWriter(output_file, engine='xlsxwriter')
    workbook = writer.book
    
    # Formats
    header_format = workbook.add_format({'bold': True, 'align': 'center', 'bg_color': '#D3D3D3', 'border': 1})
    center_format = workbook.add_format({'align': 'center'})
    
    # --- Home Sheet ---
    home_df = pd.DataFrame([{
        'Scan Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'Total Hosts': len(hosts_data),
        'Total Vulnerabilities': len(vulnerabilities),
        'Total Compliance Checks': len(compliance_items)
    }])
    home_df.to_excel(writer, sheet_name='Home', index=False, startrow=0)
    worksheet = writer.sheets['Home']
    
    # Add summary stats
    row = 3
    worksheet.write(row, 0, "Host Summary", header_format)
    # We will insert a chart here in create_dashboard_chart
    create_dashboard_chart(workbook, worksheet, hosts_data, vulnerabilities)
    
    # --- Host Summary Sheet ---
    if hosts_data:
        df_hosts = pd.DataFrame(hosts_data)
        # Reorder columns
        cols = ['IP Address', 'FQDN', 'Operating System', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Total']
        df_hosts = df_hosts[cols]
        df_hosts.to_excel(writer, sheet_name='Host Summary', index=False)
        worksheet = writer.sheets['Host Summary']
        worksheet.set_column('A:B', 20)
        worksheet.set_column('C:C', 30)

    # --- Vulnerability Sheets (Split by Severity) ---
    if vulnerabilities:
        df_vulns = pd.DataFrame(vulnerabilities)
        
        # Columns to display
        disp_cols = ['IP Address', 'FQDN', 'Port', 'Protocol', 'Service', 'Plugin ID', 'Plugin Name', 'CVSS Base Score', 'Description', 'Solution']

        for severity_val in [4, 3, 2, 1, 0]:
            sev_label = SEVERITY_MAP[severity_val]
            # Rename Info/Low/etc to match user expectation if needed, but Sev Label is clear
            sheet_name = sev_label
            
            # Filter
            subset = df_vulns[df_vulns['Severity'] == severity_val]
            
            if not subset.empty:
                subset[disp_cols].to_excel(writer, sheet_name=sheet_name, index=False)
                ws = writer.sheets[sheet_name]
                ws.set_tab_color(COLORS[sev_label])
                ws.set_column('A:B', 18)  # IP/FQDN
                ws.set_column('G:G', 40)  # Plugin Name
                ws.set_column('I:J', 50)  # Desc/Sol

    # --- Compliance Sheet ---
    if compliance_items:
        df_comp = pd.DataFrame(compliance_items)
        df_comp.to_excel(writer, sheet_name='Compliance', index=False)
        ws = writer.sheets['Compliance']
        ws.set_tab_color('#800080') # Purple
        ws.set_column('A:D', 15)
        ws.set_column('H:K', 25)

    writer.close()
    print(f"Report generated: {output_file}")

def main():
    args = parse_args()
    
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        output_file = f"nessus_report_{timestamp}.xlsx"
        
    print(f"Parsing {args.file}...")
    hosts, vulns, compliance = parse_nessus_xml(args.file)
    print(f"Found {len(hosts)} hosts, {len(vulns)} vulnerabilities, {len(compliance)} compliance checks.")
    
    write_excel(hosts, vulns, compliance, output_file)

if __name__ == "__main__":
    main()
