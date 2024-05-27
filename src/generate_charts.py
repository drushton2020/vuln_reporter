import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json

def generate_charts(metrics):
    # Severity Counts Bar Chart
    print("Generating Severity Counts Bar Chart...")
    severity_counts = pd.Series(metrics['severity_counts'])
    print("Severity Counts Data:\n", severity_counts)
    plt.figure(figsize=(8, 5))
    sns.barplot(x=severity_counts.index, y=severity_counts.values, palette="viridis")
    plt.title('Vulnerabilities by Severity')
    plt.xlabel('Severity')
    plt.ylabel('Count')
    plt.savefig('severity_counts.png')
    plt.close()
    print("Severity Counts Bar Chart generated successfully.\n")
    
    # Top Vulnerable Assets Bar Chart
    print("Generating Top Vulnerable Assets Bar Chart...")
    top_vulnerable_assets = pd.DataFrame(metrics['top_vulnerable_assets'])
    print("Top Vulnerable Assets DataFrame columns:", top_vulnerable_assets.columns)
    print("Top Vulnerable Assets DataFrame head:\n", top_vulnerable_assets.head())
    plt.figure(figsize=(8, 5))
    sns.barplot(x='vuln_count', y='asset_ip', data=top_vulnerable_assets, palette="viridis")
    plt.title('Top 5 Vulnerable Assets')
    plt.xlabel('Number of Vulnerabilities')
    plt.ylabel('Asset IP')
    plt.savefig('top_vulnerable_assets.png')
    plt.close()
    print("Top Vulnerable Assets Bar Chart generated successfully.\n")
    
    # Common Vulnerabilities Bar Chart
    print("Generating Common Vulnerabilities Bar Chart...")
    common_vulnerabilities = pd.DataFrame(metrics['common_vulnerabilities'])
    print("Common Vulnerabilities DataFrame columns:", common_vulnerabilities.columns)
    print("Common Vulnerabilities DataFrame head:\n", common_vulnerabilities.head())
    common_vulnerabilities = common_vulnerabilities.rename(columns={'plugin_name': 'vulnerability'})
    print("Renamed Common Vulnerabilities DataFrame columns:", common_vulnerabilities.columns)
    print("Renamed Common Vulnerabilities DataFrame head:\n", common_vulnerabilities.head())
    plt.figure(figsize=(8, 5))
    sns.barplot(x='count', y='vulnerability', data=common_vulnerabilities, palette="viridis")
    plt.title('Top 5 Common Vulnerabilities')
    plt.xlabel('Count')
    plt.ylabel('Vulnerability')
    plt.savefig('common_vulnerabilities.png')
    plt.close()
    print("Common Vulnerabilities Bar Chart generated successfully.\n")
    
    # Vulnerabilities by Type Pie Chart
    print("Generating Vulnerabilities by Type Pie Chart...")
    vulnerabilities_by_type = pd.DataFrame(metrics['vulnerabilities_by_type'])
    print("Vulnerabilities by Type DataFrame columns:", vulnerabilities_by_type.columns)
    print("Vulnerabilities by Type DataFrame head:\n", vulnerabilities_by_type.head())
    plt.figure(figsize=(8, 5))
    plt.pie(vulnerabilities_by_type['count'], labels=vulnerabilities_by_type['plugin_family'], autopct='%1.1f%%', colors=sns.color_palette("viridis", len(vulnerabilities_by_type)))
    plt.title('Vulnerabilities by Type')
    plt.savefig('vulnerabilities_by_type.png')
    plt.close()
    print("Vulnerabilities by Type Pie Chart generated successfully.\n")

# Example usage
if __name__ == "__main__":
    print("Loading metrics from metrics.json...")
    with open('../metrics/metrics.json', 'r') as f:
        metrics = json.load(f)
    print("Metrics loaded successfully.\n")
    print("Metrics:\n", json.dumps(metrics, indent=4))
    
    generate_charts(metrics)
