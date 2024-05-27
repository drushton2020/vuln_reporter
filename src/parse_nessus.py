import xml.etree.ElementTree as ET
import pandas as pd

def parse_nessus_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    metadata = extract_metadata(root)
    assets = extract_assets(root)
    vulnerabilities = extract_vulnerabilities(root)
    
    return metadata, assets, vulnerabilities

def extract_metadata(root):
    report = root.find('.//Report')
    metadata = {
        "scan_name": report.attrib.get('name'),
        "scan_start": root.findtext('.//ReportHost/tag[@name="HOST_START"]'),
        "scan_end": root.findtext('.//ReportHost/tag[@name="HOST_END"]'),
        "scanner_engine": root.findtext('.//NessusClientData_v2/policyName')
    }
    return pd.DataFrame([metadata])

def extract_assets(root):
    assets = []
    for report_host in root.findall('.//ReportHost'):
        asset = {
            "asset_ip": report_host.attrib.get('name'),
            "hostname": report_host.findtext('HostProperties/tag[@name="netbios-name"]'),
            "os": report_host.findtext('HostProperties/tag[@name="operating-system"]'),
            "mac_address": report_host.findtext('HostProperties/tag[@name="mac-address"]'),
            "start_time": report_host.findtext('HostProperties/tag[@name="HOST_START"]'),
            "end_time": report_host.findtext('HostProperties/tag[@name="HOST_END"]'),
            "netbios_name": report_host.findtext('HostProperties/tag[@name="netbios-name"]'),
            "fqdn": report_host.findtext('HostProperties/tag[@name="host-fqdn"]'),
            "system_type": report_host.findtext('HostProperties/tag[@name="system-type"]'),
            "host_network": report_host.findtext('HostProperties/tag[@name="host-network"]')
        }
        assets.append(asset)
    return pd.DataFrame(assets)

def extract_vulnerabilities(root):
    vulnerabilities = []
    for report_host in root.findall('.//ReportHost'):
        asset_ip = report_host.attrib.get('name')
        for report_item in report_host.findall('.//ReportItem'):
            vulnerability = {
                "plugin_id": report_item.attrib.get('pluginID'),
                "plugin_name": report_item.attrib.get('pluginName'),
                "plugin_family": report_item.attrib.get('pluginFamily'),
                "severity": int(report_item.attrib.get('severity')),
                "description": report_item.findtext('description'),
                "solution": report_item.findtext('solution'),
                "risk_factor": report_item.findtext('risk_factor'),
                "cvss_base_score": report_item.findtext('cvss_base_score'),
                "cvss_temporal_score": report_item.findtext('cvss_temporal_score'),
                "cvss_vector": report_item.findtext('cvss_vector'),
                "exploit_available": report_item.findtext('exploit_available'),
                "exploit_framework_metasploit": report_item.findtext('exploit_framework_metasploit'),
                "exploit_framework_canvas": report_item.findtext('exploit_framework_canvas'),
                "exploit_framework_core": report_item.findtext('exploit_framework_core'),
                "vulnerability_publication_date": report_item.findtext('vuln_publication_date'),
                "patch_publication_date": report_item.findtext('patch_publication_date'),
                "plugin_publication_date": report_item.findtext('plugin_publication_date'),
                "plugin_modification_date": report_item.findtext('plugin_modification_date'),
                "cve": report_item.findtext('cve'),
                "bid": report_item.findtext('bid'),
                "osvdb": report_item.findtext('osvdb'),
                "asset_ip": asset_ip,
                "port": report_item.attrib.get('port'),
                "protocol": report_item.attrib.get('protocol'),
                "svc_name": report_item.attrib.get('svc_name'),
                "plugin_output": report_item.findtext('plugin_output')
            }
            vulnerabilities.append(vulnerability)
    return pd.DataFrame(vulnerabilities)

# Example usage
if __name__ == "__main__":
    nessus_file_path = '../exports/nessus_small.nessus'
    metadata_df, assets_df, vulnerabilities_df = parse_nessus_file(nessus_file_path)
    
    # Print DataFrames to verify
    print("Metadata:")
    print(metadata_df)
    print("\nAssets:")
    print(assets_df)
    print("\nVulnerabilities:")
    print(vulnerabilities_df)
    
    # Save DataFrames to CSV for validation
    metadata_df.to_csv('../parsed/metadata.csv', index=False)
    assets_df.to_csv('../parsed/assets.csv', index=False)
    vulnerabilities_df.to_csv('../parsed/vulnerabilities.csv', index=False)
