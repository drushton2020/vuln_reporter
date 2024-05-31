import pandas as pd
import plotly.graph_objects as go
import json
import os
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_common_vulnerabilities_table(metrics, charts_dir, current_time):
    """
    Generate the Top 5 Common Vulnerabilities table as an image using Plotly.
    
    :param metrics: Dictionary containing the calculated metrics
    :param charts_dir: Directory to save the charts
    :param current_time: Timestamp to append to the filename
    """
    logging.info("Generating Common Vulnerabilities Table...")

    common_vulnerabilities = pd.DataFrame(metrics['common_vulnerabilities'])
    common_vulnerabilities.columns = ['Vulnerability', 'Count']  # Rename columns for better readability

    fig = go.Figure(data=[go.Table(
        header=dict(
            values=list(common_vulnerabilities.columns),
            fill_color='paleturquoise',
            align='center',
            font=dict(size=14, color='black'),
            height=40
        ),
        cells=dict(
            values=[common_vulnerabilities.Vulnerability, common_vulnerabilities.Count],
            fill_color=[['white', 'lightgrey'] * (len(common_vulnerabilities) // 2 + 1)],
            align=['left', 'center'],
            font=dict(size=12, color='black'),
            height=30
        ))
    ])

    fig.update_layout(
        title_text='Top 5 Common Vulnerabilities',
        title_x=0.5,
        title_font=dict(size=20),
        margin=dict(l=10, r=10, t=40, b=10)
    )

    table_path = f"{charts_dir}/common_vulnerabilities_{current_time}.png"
    fig.write_image(table_path)

    logging.info(f"Common Vulnerabilities Table generated successfully at {table_path}.")

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
        
        # Ensure charts directory exists
        charts_dir = os.path.join(script_dir, '../charts')
        if not os.path.exists(charts_dir):
            os.makedirs(charts_dir)
        
        # Generate a timestamp for the filenames
        current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate Common Vulnerabilities Table
        generate_common_vulnerabilities_table(metrics, charts_dir, current_time)

    except Exception as e:
        logging.error(f"Script execution failed: {e}")
