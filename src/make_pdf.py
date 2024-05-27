import pandas as pd
import xml.etree.ElementTree as ET
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
import os

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
        "scan_end": root.findtext('.//ReportHost/tag[@name="HOST_END"]')
    }
    return pd.DataFrame([metadata])

def extract_assets(root):
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
    vulnerabilities = []
    for report_host in root.findall('.//ReportHost'):
        asset_ip = report_host.attrib.get('name')
        for report_item in report_host.findall('.//ReportItem'):
            vulnerability = {
                "plugin_id": report_item.attrib.get('pluginID'),
                "severity": int(report_item.attrib.get('severity')),
                "plugin_name": report_item.attrib.get('pluginName'),
                "description": report_item.findtext('description'),
                "solution": report_item.findtext('solution'),
                "asset_ip": asset_ip,
                "port": report_item.attrib.get('port'),
                "protocol": report_item.attrib.get('protocol')
            }
            vulnerabilities.append(vulnerability)
    return pd.DataFrame(vulnerabilities)

def generate_pdf_report(metadata, assets, vulnerabilities, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    body_style = styles['BodyText']

    # Title Page
    elements.append(Paragraph(metadata['scan_name'][0], title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Scan Start: {metadata['scan_start'][0]}", body_style))
    elements.append(Paragraph(f"Scan End: {metadata['scan_end'][0]}", body_style))
    elements.append(PageBreak())

    # Summary Section
    elements.append(Paragraph("Executive Summary", subtitle_style))
    elements.append(Spacer(1, 12))
    
    severity_counts = vulnerabilities['severity'].value_counts().sort_index()
    summary_data = [["Severity Level", "Count"]]
    summary_data.extend([[severity, count] for severity, count in severity_counts.items()])
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Vulnerability Severity Chart
    drawing = Drawing(400, 200)
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 50
    bc.height = 125
    bc.width = 300
    bc.data = [severity_counts.values]
    bc.strokeColor = colors.black
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(severity_counts) + 1
    bc.valueAxis.valueStep = 1
    bc.categoryAxis.labels.boxAnchor = 'ne'
    bc.categoryAxis.labels.dx = -8
    bc.categoryAxis.labels.dy = -2
    bc.categoryAxis.labels.angle = 30
    bc.categoryAxis.categoryNames = [str(i) for i in severity_counts.index]
    drawing.add(bc)
    elements.append(drawing)
    elements.append(PageBreak())

    # Detailed Sections
    elements.append(Paragraph("Detailed Report", subtitle_style))
    elements.append(Spacer(1, 12))

    # Assets Section
    elements.append(Paragraph("Assets Information", subtitle_style))
    assets_table_data = [["Asset IP", "Hostname", "Operating System", "MAC Address"]]
    assets_table_data.extend(assets.values.tolist())
    assets_table = Table(assets_table_data)
    assets_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(assets_table)
    elements.append(Spacer(1, 12))

    # Vulnerabilities Section
    elements.append(Paragraph("Vulnerability Details", subtitle_style))
    vulnerabilities_table_data = [["Plugin ID", "Severity", "Plugin Name", "Description", "Solution", "Asset IP", "Port", "Protocol"]]
    vulnerabilities_table_data.extend(vulnerabilities.values.tolist())
    vulnerabilities_table = Table(vulnerabilities_table_data, repeatRows=1)
    vulnerabilities_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(vulnerabilities_table)

    # Build the PDF
    doc.build(elements)

# Example usage
if __name__ == "__main__":
    nessus_file_path = '../exports/single_host.nessus'
    metadata_df, assets_df, vulnerabilities_df = parse_nessus_file(nessus_file_path)
    
    output_pdf_path = '../reports/executive_report.pdf'
    generate_pdf_report(metadata_df, assets_df, vulnerabilities_df, output_pdf_path)
    print(f"Executive report generated: {output_pdf_path}")
