import pandas as pd
import logging
from parse_nessus import parse_nessus_file
from datetime import datetime
import os
import json

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_data(metadata_df, assets_df, vulnerabilities_df):
    """
    Analyze the parsed Nessus data to extract key metrics for reporting.
    
    :param metadata_df: DataFrame containing metadata information
    :param assets_df: DataFrame containing asset information
    :param vulnerabilities_df: DataFrame containing vulnerability information
    :return: Dictionary containing the calculated metrics
    """
    logging.info("Starting analysis of Nessus data")

    # Exclude informational severity ratings (assuming severity 0 is informational)
    vulnerabilities_df = vulnerabilities_df[vulnerabilities_df['severity'] > 0]

    # KPI 1: Total Vulnerabilities
    total_vulnerabilities = len(vulnerabilities_df)
    logging.debug(f"Total vulnerabilities: {total_vulnerabilities}")

    # KPI 2: Unique Critical Vulnerabilities
    unique_critical_vulnerabilities_df = vulnerabilities_df[vulnerabilities_df['severity'] == 4].drop_duplicates(subset=['pluginID', 'asset_ip'])
    unique_critical_vulnerabilities = len(unique_critical_vulnerabilities_df)
    logging.debug(f"Unique critical vulnerabilities: {unique_critical_vulnerabilities}")

    # KPI 3: Percentage of Critical Vulnerabilities
    critical_vulnerabilities = len(vulnerabilities_df[vulnerabilities_df['severity'] == 4])
    percentage_critical_vulnerabilities = (critical_vulnerabilities / total_vulnerabilities) * 100 if total_vulnerabilities > 0 else 0
    logging.debug(f"Percentage of critical vulnerabilities: {percentage_critical_vulnerabilities:.2f}%")

    # KPI 4: Number of Affected Assets
    affected_assets = vulnerabilities_df['asset_ip'].nunique()
    logging.debug(f"Number of affected assets: {affected_assets}")

    # KPI 5: High-Risk Assets
    high_risk_assets = vulnerabilities_df[vulnerabilities_df['severity'] == 4].groupby('asset_ip').size()
    high_risk_assets_count = len(high_risk_assets[high_risk_assets > 3])  # Assets with more than 3 critical vulnerabilities
    logging.debug(f"Number of high-risk assets: {high_risk_assets_count}")

    # Chart 1: Vulnerabilities by Severity
    severity_counts = vulnerabilities_df['severity'].value_counts().sort_index()
    logging.debug(f"Vulnerabilities by severity: {severity_counts.to_dict()}")

    # Chart 2: Vulnerabilities by Type
    vulnerabilities_by_type = vulnerabilities_df['pluginFamily'].value_counts().reset_index(name='count')
    logging.debug(f"Vulnerabilities by type: {vulnerabilities_by_type.to_dict(orient='records')}")

    # Table 1: Top 5 Affected Assets
    vulnerabilities_by_asset = vulnerabilities_df.groupby('asset_ip').size().reset_index(name='vuln_count')
    top_affected_assets = vulnerabilities_by_asset.nlargest(5, 'vuln_count')
    logging.debug(f"Top 5 affected assets: {top_affected_assets.to_dict(orient='records')}")

    # Table 2: Top 5 Common Vulnerabilities
    common_vulnerabilities = vulnerabilities_df['pluginName'].value_counts().nlargest(5).reset_index(name='count')
    logging.debug(f"Top 5 common vulnerabilities: {common_vulnerabilities.to_dict(orient='records')}")

    # Prepare Metrics for Report
    metrics = {
        "total_vulnerabilities": total_vulnerabilities,  # General statistic (raw count)
        "unique_critical_vulnerabilities": unique_critical_vulnerabilities,  # General statistic (deduplicated count)
        "percentage_critical_vulnerabilities": percentage_critical_vulnerabilities,  # Percentage
        "affected_assets": affected_assets,  # Number of assets with vulnerabilities
        "high_risk_assets_count": high_risk_assets_count,  # Number of high-risk assets
        "severity_counts": severity_counts.to_dict(),  # Bar chart
        "vulnerabilities_by_type": vulnerabilities_by_type.to_dict(orient='records'),  # Pie chart
        "top_affected_assets": top_affected_assets.to_dict(orient='records'),  # Table
        "common_vulnerabilities": common_vulnerabilities.to_dict(orient='records')  # Table
    }

    logging.info("Finished analysis of Nessus data")
    return metrics

def save_metrics(metrics, directory='../metrics'):
    """
    Save the metrics to a JSON file with a timestamp, ensuring old files are deleted.
    
    :param metrics: Dictionary containing the calculated metrics
    :param directory: Directory to save the metrics JSON file
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"metrics_{current_time}.json"
        file_path = os.path.join(directory, filename)

        # Remove old files in the directory
        for f in os.listdir(directory):
            if f.startswith('metrics_'):
                os.remove(os.path.join(directory, f))

        # Save the new file
        with open(file_path, 'w') as f:
            json.dump(metrics, f, indent=4)
        
        logging.info(f"Saved metrics to {file_path}")
    except Exception as e:
        logging.error(f"Error saving metrics: {e}")

# Example usage
if __name__ == "__main__":
    try:
        # Path to the Nessus file
        nessus_file_path = '../exports/nessus_medium.nessus'

        # Parse the Nessus file
        metadata_df, assets_df, vulnerabilities_df, policy = parse_nessus_file(nessus_file_path)

        # Validate parsed DataFrames
        if metadata_df.empty or assets_df.empty or vulnerabilities_df.empty:
            logging.error("One or more DataFrames are empty. Cannot proceed with analysis.")
            exit(1)
        
        # Analyze the parsed data
        metrics = analyze_data(metadata_df, assets_df, vulnerabilities_df)

        # Save metrics to a JSON file
        save_metrics(metrics)

    except Exception as e:
        logging.error(f"Script execution failed: {e}")
