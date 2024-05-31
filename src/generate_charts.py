import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_kpi_dashboard(metrics, charts_dir, current_time):
    """
    Generate a KPI dashboard image.
    
    :param metrics: Dictionary containing the calculated metrics
    :param charts_dir: Directory to save the charts
    :param current_time: Timestamp to append to the filename
    """
    logging.info("Generating KPI Dashboard...")
    
    fig, ax = plt.subplots(1, 1, figsize=(12, 8))
    ax.axis('off')
    ax.set_title('Health Dashboard', fontsize=16)
    
    kpis = [
        {"label": "Total Vulnerabilities", "value": metrics['total_vulnerabilities']},
        {"label": "Unique Critical Vulnerabilities", "value": metrics['unique_critical_vulnerabilities']},
        {"label": "Percentage of Critical Vulnerabilities", "value": f"{metrics['percentage_critical_vulnerabilities']:.2f}%"},
        {"label": "Affected Assets", "value": metrics['affected_assets']},
        {"label": "High-Risk Assets", "value": metrics['high_risk_assets_count']}
    ]
    
    for i, kpi in enumerate(kpis):
        ax.text(0.5, 1-(i+1)*0.1, f"{kpi['label']}: {kpi['value']}", ha='center', va='center', fontsize=12, bbox=dict(facecolor='white', alpha=0.5))
    
    dashboard_path = f"{charts_dir}/kpi_dashboard_{current_time}.png"
    fig.savefig(dashboard_path, bbox_inches='tight')
    plt.close(fig)
    logging.info(f"KPI Dashboard generated successfully at {dashboard_path}.")

def generate_common_vulnerabilities_table(metrics, charts_dir, current_time):
    """
    Generate the Top 5 Common Vulnerabilities table as an image.
    
    :param metrics: Dictionary containing the calculated metrics
    :param charts_dir: Directory to save the charts
    :param current_time: Timestamp to append to the filename
    """
    logging.info("Generating Common Vulnerabilities Table...")
    
    common_vulnerabilities = pd.DataFrame(metrics['common_vulnerabilities'])
    
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.axis('off')
    
    # Create table
    table = ax.table(cellText=common_vulnerabilities.values, colLabels=common_vulnerabilities.columns, cellLoc='center', loc='center')
    
    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(12)
    table.scale(1.5, 1.5)
    
    # Adjust header style
    for (i, j), cell in table.get_celld().items():
        if i == 0:  # Header
            cell.set_fontsize(14)
            cell.set_text_props(weight='bold', style='italic')
            cell.set_text_props(ha='center')
            cell.set_edgecolor('lightgrey')
        else:  # Data rows
            cell.set_fontsize(12)
            cell.set_edgecolor('lightgrey')
            cell.set_text_props(ha='left' if j == 0 else 'center')
            cell.set_text_props(weight='bold' if j == 1 else None)
            cell.set_facecolor('#f0f0f0' if i % 2 == 0 else '#ffffff')
            cell.PAD = 10  # Set padding
    
    # Adjust column widths (70:30 ratio)
    table.auto_set_column_width([0, 1])
    col_widths = {0: 0.7, 1: 0.3}
    for key, cell in table.get_celld().items():
        cell.width = col_widths[key[1]] if key[0] != 0 else cell.width

    # Remove outside borders
    for key, cell in table.get_celld().items():
        if key[0] == 0 or key[1] < len(common_vulnerabilities.columns):
            cell.set_linewidth(0.5)
        else:
            cell.visible_edges = 'open'
    
    # Set title
    fig.suptitle('Top 5 Common Vulnerabilities', fontsize=16, x=0.5, y=0.05)
    
    # Save the figure
    table_path = f"{charts_dir}/common_vulnerabilities_{current_time}.png"
    fig.savefig(table_path, bbox_inches='tight')
    plt.close(fig)
    
    logging.info(f"Common Vulnerabilities Table generated successfully at {table_path}.")

def generate_charts(metrics):
    """
    Generate charts based on the provided metrics and save them as PNG files.
    
    :param metrics: Dictionary containing the calculated metrics
    """
    # Ensure charts directory exists
    charts_dir = '../charts'
    if not os.path.exists(charts_dir):
        os.makedirs(charts_dir)
    
    # Generate a timestamp for the filenames
    current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Generate KPI Dashboard
    generate_kpi_dashboard(metrics, charts_dir, current_time)
    
    try:
        # Severity Counts Bar Chart
        logging.info("Generating Severity Counts Bar Chart...")
        severity_counts = pd.Series(metrics['severity_counts'])
        plt.figure(figsize=(8, 5))
        sns.barplot(x=severity_counts.index, y=severity_counts.values, palette="viridis")
        plt.title('Vulnerabilities by Severity')
        plt.xlabel('Severity')
        plt.ylabel('Count')
        plt.savefig(f'{charts_dir}/severity_counts_{current_time}.png')
        plt.close()
        logging.info("Severity Counts Bar Chart generated successfully.")
        
        # Vulnerabilities by Type Pie Chart
        logging.info("Generating Vulnerabilities by Type Pie Chart...")
        vulnerabilities_by_type = pd.DataFrame(metrics['vulnerabilities_by_type'])
        plt.figure(figsize=(8, 5))
        plt.pie(vulnerabilities_by_type['count'], labels=vulnerabilities_by_type['pluginFamily'], autopct='%1.1f%%', colors=sns.color_palette("viridis", len(vulnerabilities_by_type)))
        plt.title('Vulnerabilities by Type')
        plt.savefig(f'{charts_dir}/vulnerabilities_by_type_{current_time}.png')
        plt.close()
        logging.info("Vulnerabilities by Type Pie Chart generated successfully.")
        
        # Generate Common Vulnerabilities Table
        generate_common_vulnerabilities_table(metrics, charts_dir, current_time)
    
    except Exception as e:
        logging.error(f"Error generating charts: {e}")

# Example usage
if __name__ == "__main__":
    try:
        # Determine the absolute path to the metrics.json file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        metrics_path = os.path.join(script_dir, '../metrics/metrics_20240531_212149.json')

        logging.info(f"Loading metrics from {metrics_path}...")
        with open(metrics_path, 'r') as f:
            metrics = json.load(f)
        logging.info("Metrics loaded successfully.")
        
        logging.debug(f"Metrics:\n{json.dumps(metrics, indent=4)}")
        
        generate_charts(metrics)

    except Exception as e:
        logging.error(f"Script execution failed: {e}")
