import os
import logging
import json
import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from io import BytesIO
from flask import render_template_string
from opensearch_api import OpenSearchAPI
from config import Config

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.opensearch = OpenSearchAPI()
        self.env = Environment(loader=FileSystemLoader('templates/report_templates'))
        
    def generate_report(self, report_config, start_time=None, end_time=None, format="pdf"):
        """
        Generate a report based on configuration
        
        Args:
            report_config: ReportConfig object or dict with report settings
            start_time: Override start time (ISO format)
            end_time: Override end time (ISO format)
            format: 'pdf' or 'html'
            
        Returns:
            BytesIO object with the report or HTML string
        """
        # Set default time range if not provided
        if not end_time:
            end_time = datetime.datetime.utcnow().isoformat()
        
        if not start_time:
            # Default to 24 hours if not specified
            start_time = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()
        
        # Get severity levels from config
        if hasattr(report_config, 'get_severity_levels'):
            severity_levels = report_config.get_severity_levels()
        else:
            severity_levels = report_config.get('severity_levels', ['critical', 'high', 'medium', 'low'])
        
        # Fetch alerts from OpenSearch
        alerts_data = self.opensearch.search_alerts(
            severity_levels=severity_levels,
            start_time=start_time,
            end_time=end_time,
            limit=1000  # Increase limit for reports
        )
        
        if 'error' in alerts_data:
            logger.error(f"Error fetching alerts for report: {alerts_data['error']}")
            return None
        
        # Get alert count by severity
        alert_counts = self.opensearch.get_alert_count_by_severity(
            start_time=start_time,
            end_time=end_time
        )
        
        # Prepare data for the report
        report_data = {
            'title': f"Security Alert Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
            'generated_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'period': {
                'start': start_time,
                'end': end_time
            },
            'alerts': alerts_data.get('results', []),
            'alert_counts': alert_counts,
            'severity_levels': severity_levels,
            'total_alerts': alerts_data.get('total', 0)
        }
        
        # Generate the report in requested format
        if format.lower() == 'pdf':
            return self._generate_pdf_report(report_data)
        else:
            return self._generate_html_report(report_data)
    
    def _generate_html_report(self, report_data):
        """Generate HTML report"""
        try:
            template = self.env.get_template('html_report.html')
            html_content = template.render(**report_data)
            return html_content
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            return f"<h1>Error generating report</h1><p>{str(e)}</p>"
    
    def _generate_pdf_report(self, report_data):
        """Generate PDF report"""
        try:
            # Get HTML content first
            html_content = self._generate_html_report(report_data)
            
            # Convert HTML to PDF
            pdf_file = BytesIO()
            HTML(string=html_content).write_pdf(pdf_file)
            
            # Reset file pointer to beginning
            pdf_file.seek(0)
            
            return pdf_file
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            return None
