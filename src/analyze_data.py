import pandas as pd
from parse_nessus import parse_nessus_file

def analyze_data(metadata_df, assets_df, vulnerabilities_df):
    # Exclude informational severity ratings (assuming severity 0 is informational)
    vulnerabilities_df = vulnerabilities_df[vulnerabilities_df['severity'] > 0]
    
    # Total Vulnerabilities: Count all entries (raw count)
    total_vulnerabilities = len(vulnerabilities_df)
    
    # Unique Vulnerabilities: Deduplicate by plugin_id and asset_ip
    unique_vulnerabilities_df = vulnerabilities_df.drop_duplicates(subset=['plugin_id', 'asset_ip'])
    unique_vulnerabilities = len(unique_vulnerabilities_df)
    
    # Key Metrics
    total_assets = len(assets_df)
    severity_counts = unique_vulnerabilities_df['severity'].value_counts().sort_index()
    
    # Vulnerabilities by Asset
    vulnerabilities_by_asset = unique_vulnerabilities_df.groupby('asset_ip').size().reset_index(name='vuln_count')
    top_vulnerable_assets = vulnerabilities_by_asset.nlargest(5, 'vuln_count')
    
    # Common Vulnerabilities
    common_vulnerabilities = unique_vulnerabilities_df['plugin_name'].value_counts().nlargest(5).reset_index(name='count')
    
    # Vulnerabilities by Type (e.g., Web Application, Network, etc. - based on plugin family)
    vulnerabilities_by_type = unique_vulnerabilities_df['plugin_family'].value_counts().reset_index(name='count')
    
    # Prepare Metrics for Report
    metrics = {
        "total_assets": total_assets,  # General statistic
        "total_vulnerabilities": total_vulnerabilities,  # General statistic (raw count)
        "unique_vulnerabilities": unique_vulnerabilities,  # General statistic (deduplicated count)
        "severity_counts": severity_counts.to_dict(),  # Bar chart
        "top_vulnerable_assets": top_vulnerable_assets.to_dict(orient='records'),  # Bar chart
        "common_vulnerabilities": common_vulnerabilities.to_dict(orient='records'),  # Bar chart
        "vulnerabilities_by_type": vulnerabilities_by_type.to_dict(orient='records')  # Pie chart or bar chart
    }
    
    return metrics

# Example usage
if __name__ == "__main__":
    # Path to the Nessus file
    nessus_file_path = '../exports/nessus_small.nessus'
    
    # Parse the Nessus file
    metadata_df, assets_df, vulnerabilities_df = parse_nessus_file(nessus_file_path)
    
    # Analyze the parsed data
    metrics = analyze_data(metadata_df, assets_df, vulnerabilities_df)
    
    # Print metrics for validation
    print("Metrics:")
    print(metrics)
    
    # Save metrics to a JSON file for further use
    import json
    with open('metrics.json', 'w') as f:
        json.dump(metrics, f, indent=4)
