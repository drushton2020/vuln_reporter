from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
import json

def create_pdf_report(metrics):
    doc = SimpleDocTemplate("executive_report.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    title = Paragraph("Executive Vulnerability Assessment Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    # Key Metrics
    key_metrics = [
        ["Total Assets", metrics["total_assets"]],
        ["Total Vulnerabilities (excluding informational)", metrics["total_vulnerabilities"]],
        ["Unique Vulnerabilities", metrics["unique_vulnerabilities"]],
    ]
    table = Table(key_metrics)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))
    
    # Charts
    charts = [
        ('Severity Counts', 'severity_counts.png'),
        ('Top 5 Vulnerable Assets', 'top_vulnerable_assets.png'),
        ('Top 5 Common Vulnerabilities', 'common_vulnerabilities.png'),
        ('Vulnerabilities by Type', 'vulnerabilities_by_type.png')
    ]
    
    for title, chart in charts:
        elements.append(Spacer(1, 12))
        elements.append(Image(chart, width=400, height=200))
        elements.append(Spacer(1, 12))
    
    doc.build(elements)

# Example usage
if __name__ == "__main__":
    with open('../metrics/metrics.json', 'r') as f:
        metrics = json.load(f)
    create_pdf_report(metrics)
