import xml.etree.ElementTree as ET
import pandas as pd
import logging
from datetime import datetime
import os

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_nessus_file(file_path):
    """
    Parses the Nessus file and extracts metadata, assets, vulnerabilities, and policy data.

    :param file_path: Path to the Nessus file
    :return: DataFrames containing metadata, assets, vulnerabilities, and policy data
    """
    try:
        logging.info(f"Starting to parse the Nessus file: {file_path}")
        tree = ET.parse(file_path)
        root = tree.getroot()

        metadata = extract_metadata(root)
        assets = extract_assets(root)
        vulnerabilities = extract_vulnerabilities(root)
        policy = extract_policy(root)

        logging.info("Finished parsing the Nessus file")
        return metadata, assets, vulnerabilities, policy
    except ET.ParseError as e:
        logging.error(f"Error parsing the Nessus file: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise

def extract_metadata(root):
    """
    Extracts metadata from the Nessus XML root.

    :param root: Root of the parsed Nessus XML
    :return: DataFrame containing metadata
    """
    try:
        report = root.find('.//Report')
        first_host = root.find('.//ReportHost')
        metadata = {
            "scan_name": report.attrib.get('name', 'N/A'),
            "scan_start": first_host.findtext('HostProperties/tag[@name="HOST_START"]', 'N/A'),
            "scan_end": first_host.findtext('HostProperties/tag[@name="HOST_END"]', 'N/A'),
            "scanner_engine": root.findtext('.//Policy/policyName', 'N/A')
        }
        logging.debug(f"Extracted metadata: {metadata}")
        return pd.DataFrame([metadata])
    except AttributeError as e:
        logging.error(f"Error extracting metadata: {e}")
        return pd.DataFrame()

def extract_assets(root):
    """
    Extracts asset information from the Nessus XML root.

    :param root: Root of the parsed Nessus XML
    :return: DataFrame containing asset information
    """
    assets = []
    try:
        for report_host in root.findall('.//ReportHost'):
            asset = {
                "asset_ip": report_host.attrib.get('name', 'N/A'),
                "hostname": report_host.findtext('HostProperties/tag[@name="netbios-name"]', 'N/A'),
                "os": report_host.findtext('HostProperties/tag[@name="operating-system"]', 'N/A'),
                "mac_address": report_host.findtext('HostProperties/tag[@name="mac-address"]', 'N/A'),
                "start_time": report_host.findtext('HostProperties/tag[@name="HOST_START"]', 'N/A'),
                "end_time": report_host.findtext('HostProperties/tag[@name="HOST_END"]', 'N/A'),
                "netbios_name": report_host.findtext('HostProperties/tag[@name="netbios-name"]', 'N/A'),
                "fqdn": report_host.findtext('HostProperties/tag[@name="host-fqdn"]', 'N/A'),
                "system_type": report_host.findtext('HostProperties/tag[@name="system-type"]', 'N/A'),
                "host_network": report_host.findtext('HostProperties/tag[@name="host-network"]', 'N/A')
            }
            assets.append(asset)
        logging.debug(f"Extracted {len(assets)} assets")
        return pd.DataFrame(assets)
    except AttributeError as e:
        logging.error(f"Error extracting assets: {e}")
        return pd.DataFrame()

def extract_vulnerabilities(root):
    """
    Extracts vulnerability information from the Nessus XML root.

    :param root: Root of the parsed Nessus XML
    :return: DataFrame containing vulnerability information
    """
    vulnerabilities = []
    try:
        for report_host in root.findall('.//ReportHost'):
            asset_ip = report_host.attrib.get('name', 'N/A')
            for report_item in report_host.findall('.//ReportItem'):
                vulnerability = {
                    "port": report_item.attrib.get('port', 'N/A'),
                    "svc_name": report_item.attrib.get('svc_name', 'N/A'),
                    "protocol": report_item.attrib.get('protocol', 'N/A'),
                    "severity": int(report_item.attrib.get('severity', 0)),
                    "pluginID": report_item.attrib.get('pluginID', 'N/A'),
                    "pluginName": report_item.attrib.get('pluginName', 'N/A'),
                    "pluginFamily": report_item.attrib.get('pluginFamily', 'N/A'),
                    "risk_factor": report_item.findtext('risk_factor', 'N/A'),
                    "synopsis": report_item.findtext('synopsis', 'N/A'),
                    "description": report_item.findtext('description', 'N/A'),
                    "solution": report_item.findtext('solution', 'N/A'),
                    "plugin_output": report_item.findtext('plugin_output', 'N/A'),
                    "see_also": report_item.findtext('see_also', 'N/A'),
                    "cve": report_item.findtext('cve', 'N/A'),
                    "bid": report_item.findtext('bid', 'N/A'),
                    "xref": report_item.findtext('xref', 'N/A'),
                    "plugin_modification_date": report_item.findtext('plugin_modification_date', 'N/A'),
                    "plugin_publication_date": report_item.findtext('plugin_publication_date', 'N/A'),
                    "patch_publication_date": report_item.findtext('patch_publication_date', 'N/A'),
                    "vuln_publication_date": report_item.findtext('vuln_publication_date', 'N/A'),
                    "exploitability_ease": report_item.findtext('exploitability_ease', 'N/A'),
                    "exploit_available": report_item.findtext('exploit_available', 'N/A'),
                    "exploit_framework_canvas": report_item.findtext('exploit_framework_canvas', 'N/A'),
                    "exploit_framework_metasploit": report_item.findtext('exploit_framework_metasploit', 'N/A'),
                    "exploit_framework_core": report_item.findtext('exploit_framework_core', 'N/A'),
                    "metasploit_name": report_item.findtext('metasploit_name', 'N/A'),
                    "canvas_package": report_item.findtext('canvas_package', 'N/A'),
                    "cvss_vector": report_item.findtext('cvss_vector', 'N/A'),
                    "cvss_base_score": report_item.findtext('cvss_base_score', 'N/A'),
                    "cvss_temporal_score": report_item.findtext('cvss_temporal_score', 'N/A'),
                    "plugin_type": report_item.findtext('plugin_type', 'N/A'),
                    "plugin_version": report_item.findtext('plugin_version', 'N/A'),
                    "cm:complianceinfo": report_item.findtext('cm:complianceinfo', 'N/A'),
                    "cm:complianceresult": report_item.findtext('cm:complianceresult', 'N/A'),
                    "cm:complianceactualvalue": report_item.findtext('cm:complianceactualvalue', 'N/A'),
                    "cm:compliancecheck-id": report_item.findtext('cm:compliancecheck-id', 'N/A'),
                    "asset_ip": asset_ip
                }
                vulnerabilities.append(vulnerability)
        logging.debug(f"Extracted {len(vulnerabilities)} vulnerabilities")
        return pd.DataFrame(vulnerabilities)
    except AttributeError as e:
        logging.error(f"Error extracting vulnerabilities: {e}")
        return pd.DataFrame()

def extract_policy(root):
    """
    Extracts policy information from the Nessus XML root.

    :param root: Root of the parsed Nessus XML
    :return: DataFrames containing policy data, server preferences, and plugins preferences
    """
    try:
        policy = root.find('.//Policy')
        if policy is not None:
            policy_data = {
                "policy_name": policy.findtext('policyName', 'N/A'),
                "policy_comment": policy.findtext('policyComment', 'N/A')
            }

            # Extract Server Preferences
            server_prefs = []
            for pref in policy.findall('.//ServerPreferences/preference'):
                server_prefs.append({
                    "name": pref.findtext('name', 'N/A'),
                    "value": pref.findtext('value', 'N/A')
                })

            # Extract Plugins Preferences
            plugins_prefs = []
            for item in policy.findall('.//PluginsPreferences/item'):
                plugins_prefs.append({
                    "plugin_name": item.findtext('pluginName', 'N/A'),
                    "plugin_id": item.findtext('pluginId', 'N/A'),
                    "full_name": item.findtext('fullName', 'N/A'),
                    "preference_name": item.findtext('preferenceName', 'N/A'),
                    "preference_type": item.findtext('preferenceType', 'N/A'),
                    "preference_values": item.findtext('preferenceValues', 'N/A'),
                    "selected_value": item.findtext('selectedValue', 'N/A')
                })

            # Convert to DataFrame
            policy_df = pd.DataFrame([policy_data])
            server_prefs_df = pd.DataFrame(server_prefs)
            plugins_prefs_df = pd.DataFrame(plugins_prefs)

            logging.debug("Extracted policy data")
            return policy_df, server_prefs_df, plugins_prefs_df

        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    except AttributeError as e:
        logging.error(f"Error extracting policy: {e}")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

def save_dataframe(df, filename):
    """
    Saves the DataFrame to a CSV file with the current timestamp in the filename.

    :param df: DataFrame to save
    :param filename: Base filename for the CSV file
    """
    try:
        current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_filename = f"{filename}_{current_time}.csv"

        # Remove old files with the same prefix
        for f in os.listdir('../parsed/'):
            if f.startswith(filename):
                os.remove(os.path.join('../parsed/', f))

        # Save the new file
        df.to_csv(os.path.join('../parsed/', new_filename), index=False)
        logging.info(f"Saved {filename} to {new_filename}")
    except Exception as e:
        logging.error(f"Error saving {filename}: {e}")

def validate_dataframes(metadata_df, assets_df, vulnerabilities_df, policy_df, server_prefs_df, plugins_prefs_df):
    """
    Validates the extracted data by checking for the existence of critical fields.

    :param metadata_df: DataFrame containing metadata
    :param assets_df: DataFrame containing asset information
    :param vulnerabilities_df: DataFrame containing vulnerability information
    :param policy_df: DataFrame containing policy information
    :param server_prefs_df: DataFrame containing server preferences
    :param plugins_prefs_df: DataFrame containing plugins preferences
    """
    logging.info("Validating dataframes")

    try:
        # Check metadata
        assert not metadata_df.empty, "Metadata dataframe is empty"
        assert 'scan_name' in metadata_df.columns, "scan_name not in metadata dataframe"
        assert 'scan_start' in metadata_df.columns, "scan_start not in metadata dataframe"
        assert 'scan_end' in metadata_df.columns, "scan_end not in metadata dataframe"

        # Check assets
        assert not assets_df.empty, "Assets dataframe is empty"
        assert 'asset_ip' in assets_df.columns, "asset_ip not in assets dataframe"

        # Check vulnerabilities
        assert not vulnerabilities_df.empty, "Vulnerabilities dataframe is empty"
        assert 'pluginID' in vulnerabilities_df.columns, "pluginID not in vulnerabilities dataframe"
        assert 'description' in vulnerabilities_df.columns, "description not in vulnerabilities dataframe"

        # Check policy
        assert not policy_df.empty, "Policy dataframe is empty"
        assert 'policy_name' in policy_df.columns, "policy_name not in policy dataframe"

        logging.info("All dataframes are valid")
    except AssertionError as e:
        logging.error(f"Validation error: {e}")
        raise

# Example usage
if __name__ == "__main__":
    try:
        nessus_file_path = '../exports/nessus_small.nessus'
        metadata_df, assets_df, vulnerabilities_df, policy = parse_nessus_file(nessus_file_path)

        # Unpack policy dataframes
        policy_df, server_prefs_df, plugins_prefs_df = policy

        # Save DataFrames to CSV for validation
        save_dataframe(metadata_df, 'metadata')
        save_dataframe(assets_df, 'assets')
        save_dataframe(vulnerabilities_df, 'vulnerabilities')
        save_dataframe(policy_df, 'policy')
        save_dataframe(server_prefs_df, 'server_preferences')
        save_dataframe(plugins_prefs_df, 'plugins_preferences')

        # Validate DataFrames
        validate_dataframes(metadata_df, assets_df, vulnerabilities_df, policy_df, server_prefs_df, plugins_prefs_df)
    except Exception as e:
        logging.error(f"Script execution failed: {e}")
