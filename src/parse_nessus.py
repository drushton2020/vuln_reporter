import pandas as pd
import xml.etree.ElementTree as ET

def parse_nessus_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    metadata = extract_metadata(root)
    assets = extract_assets(root)
    vulnerabilities = extract_vulnerabilities(root)
    
    return metadata, assets, vulnerabilities

def extract_metadata(root):
    # Extracting metadata from the Report section
    report = root.find('.//Report')
    metadata = {
        "scan_name": report.attrib.get('name'),
        "scan_start": root.findtext('.//ReportHost/tag[@name="HOST_START"]'),
        "scan_end": root.findtext('.//ReportHost/tag[@name="HOST_END"]')
    }
    return pd.DataFrame([metadata])

def extract_assets(root):
    # Extracting asset information from ReportHost section
    assets = []
    for report_host in root.findall('.//ReportHost'):
        asset = {
            "asset_ip": report_host.attrib.get('name'),
            "hostname": report_host.findtext('HostProperties/tag[@name="netbios-name"]'),
            "os": report_host.findtext('HostProperties/tag[@name="operating-system"]'),
            "mac_address": report_host.findtext('HostProperties/tag[@name="mac-address"]')
        }
        assets.append(asset)
    return pd.DataFrame(assets)

def extract_vulnerabilities(root):
    # Extracting vulnerability information from ReportItem section
    vulnerabilities = []
    for report_host in root.findall('.//ReportHost'):
        asset_ip = report_host.attrib.get('name')
        for report_item in report_host.findall('.//ReportItem'):
            vulnerability = {
                "plugin_id": report_item.attrib.get('pluginID'),
                "severity": report_item.attrib.get('severity'),
                "plugin_name": report_item.attrib.get('pluginName'),
                "description": report_item.findtext('description'),
                "solution": report_item.findtext('solution'),
                "asset_ip": asset_ip,
                "port": report_item.attrib.get('port'),
                "protocol": report_item.attrib.get('protocol')
            }
            vulnerabilities.append(vulnerability)
    return pd.DataFrame(vulnerabilities)

# Example usage
if __name__ == "__main__":
    nessus_file_path = '../exports/single_host.nessus'
    metadata_df, assets_df, vulnerabilities_df = parse_nessus_file(nessus_file_path)
    
    # Print DataFrames to verify
    print("Metadata:")
    print(metadata_df)
    print("\nAssets:")
    print(assets_df)
    print("\nVulnerabilities:")
    print(vulnerabilities_df)
    
    # Save DataFrames to CSV for further analysis
    metadata_df.to_csv('../parsed/metadata.csv', index=False)
    assets_df.to_csv('../parsed/assets.csv', index=False)
    vulnerabilities_df.to_csv('../parsed/vulnerabilities.csv', index=False)
