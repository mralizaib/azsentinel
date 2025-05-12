import os
import logging
import smtplib
import hashlib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from config import Config
from opensearch_api import OpenSearchAPI
from report_generator import ReportGenerator
import datetime
from models import SentAlert, SystemConfig, db

logger = logging.getLogger(__name__)

class EmailAlerts:
    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.smtp_username = Config.SMTP_USERNAME
        self.smtp_password = Config.SMTP_PASSWORD
        self.smtp_use_tls = Config.SMTP_USE_TLS
        self.opensearch = OpenSearchAPI()
        self.report_generator = ReportGenerator()
        
    def _generate_alert_identifier(self, alert_data):
        """
        Generate a unique identifier for an alert based on specified fields
        to prevent duplicate notifications
        
        Args:
            alert_data: The alert data from OpenSearch
            
        Returns:
            String hash representing the unique alert
        """
        # Extract key fields for deduplication
        source = alert_data.get('source', {})
        
        # Get the fields that should be used to identify unique alerts
        fields = {
            'timestamp': source.get('@timestamp', ''),
            'rule_id': source.get('rule', {}).get('id', ''),
            'rule_description': source.get('rule', {}).get('description', ''),
            'agent_ip': source.get('agent', {}).get('ip', ''),
            'agent_name': source.get('agent', {}).get('name', ''),
            'location': source.get('agent', {}).get('labels', {}).get('location.set', '')
        }
        
        # Create a string representation and hash it
        identifier_str = json.dumps(fields, sort_keys=True)
        return hashlib.md5(identifier_str.encode()).hexdigest()
    
    def _is_alert_already_sent(self, alert_config_id, alert_identifier):
        """
        Check if an alert with this identifier has already been sent for this config
        
        Args:
            alert_config_id: ID of the alert configuration
            alert_identifier: Hash of the alert's unique identifiers
            
        Returns:
            Boolean indicating if the alert was already sent
        """
        # Get duplicate prevention window from system config or use 24 hours as default
        duplicate_window = int(SystemConfig.get_value('alert_duplicate_window', '24'))
        cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=duplicate_window)
        
        # Query for existing alerts
        existing_alert = SentAlert.query.filter(
            SentAlert.alert_config_id == alert_config_id,
            SentAlert.alert_identifier == alert_identifier,
            SentAlert.timestamp >= cutoff_time
        ).first()
        
        return existing_alert is not None
        
    def _record_sent_alert(self, alert_config_id, alert_identifier):
        """
        Record that an alert has been sent to prevent duplicates
        
        Args:
            alert_config_id: ID of the alert configuration
            alert_identifier: Hash of the alert's unique identifiers
        """
        sent_alert = SentAlert(
            alert_config_id=alert_config_id,
            alert_identifier=alert_identifier
        )
        db.session.add(sent_alert)
        db.session.commit()
    
    def send_alert_email(self, recipient, subject, message, attachments=None):
        """
        Send alert email
        
        Args:
            recipient: Email recipient address
            subject: Email subject
            message: Email body (HTML)
            attachments: List of dicts with 'content' (BytesIO), 'filename', and 'mime_type'
            
        Returns:
            Boolean indicating success or failure
        """
        if not self.smtp_username or not self.smtp_password:
            logger.error("SMTP credentials not configured")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            # Set sender name to "Wazuh" with the SMTP username as the email address
            msg['From'] = f"Wazuh <{self.smtp_username}>"
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # Attach HTML body
            msg.attach(MIMEText(message, 'html'))
            
            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    part = MIMEApplication(
                        attachment['content'].read(),
                        Name=attachment['filename']
                    )
                    part['Content-Disposition'] = f'attachment; filename="{attachment["filename"]}"'
                    msg.attach(part)
            
            # Connect to SMTP server and send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Alert email sent to {recipient}")
            return True
        except Exception as e:
            logger.error(f"Failed to send alert email: {str(e)}")
            return False
    
    def send_severity_alert(self, alert_config, alerts_data=None):
        """
        Send an alert email based on severity configuration
        
        Args:
            alert_config: AlertConfig object
            alerts_data: Optional pre-fetched alerts data
            
        Returns:
            Boolean indicating success or failure
        """
        try:
            # Get severity levels from config
            if hasattr(alert_config, 'get_alert_levels'):
                severity_levels = alert_config.get_alert_levels()
            else:
                severity_levels = alert_config.get('alert_levels', ['critical', 'high'])
            
            recipient = alert_config.email_recipient if hasattr(alert_config, 'email_recipient') else alert_config.get('email_recipient')
            
            if not recipient:
                logger.error("No recipient specified for alert")
                return False
            
            # Set time range for alerts
            # Get the alert check interval from system config or use 60 minutes as default
            alert_check_interval = int(SystemConfig.get_value('alert_check_interval', '60'))
            current_time_utc = datetime.datetime.utcnow()
            end_time = current_time_utc.isoformat()
            start_time = (current_time_utc - datetime.timedelta(minutes=alert_check_interval)).isoformat()
            
            # If alerts data not provided, fetch it
            if not alerts_data:
                alerts_data = self.opensearch.search_alerts(
                    severity_levels=severity_levels,
                    start_time=start_time,
                    end_time=end_time,
                    limit=100
                )
            
            if 'error' in alerts_data:
                logger.error(f"Error fetching alerts for email: {alerts_data['error']}")
                return False
            
            # Check if there are any alerts to send
            if not alerts_data.get('results', []) and not alerts_data.get('manual_test', False):
                logger.info(f"No alerts to send for levels: {', '.join(severity_levels)}")
                return True  # Return success as there's nothing to send
                
            # If this is a manual test with no alerts, create a test message
            if alerts_data.get('manual_test', False) and not alerts_data.get('results', []):
                logger.info("Creating test alert email for manual trigger")
                subject = f"WAZUH Security Alert: Test Alert (Manual)"
                message = f"""
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; }}
                        .alert-summary {{ margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 5px solid #28a745; }}
                    </style>
                </head>
                <body>
                    <h1>Test Security Alert</h1>
                    <div class="alert-summary">
                        <p>This is a test alert triggered manually from the Scheduler Management interface.</p>
                        <p>No actual alerts were found matching your configuration criteria.</p>
                        <p>Alert levels: {', '.join(severity_levels)}</p>
                        <p>Search time range: {start_time.replace('T', ' ').split('.')[0]} to {end_time.replace('T', ' ').split('.')[0]} (UTC)</p>
                    </div>
                    <p>This email confirms that your alert notification system is working correctly.</p>
                </body>
                </html>
                """
                return self.send_alert_email(recipient, subject, message)
                
            # Filter out alerts that have already been sent
            if hasattr(alert_config, 'id'):
                new_alerts = []
                for alert in alerts_data.get('results', []):
                    alert_identifier = self._generate_alert_identifier(alert)
                    if not self._is_alert_already_sent(alert_config.id, alert_identifier):
                        new_alerts.append(alert)
                        # Record that we're sending this alert
                        self._record_sent_alert(alert_config.id, alert_identifier)
                
                # Replace the results with only new alerts
                if not new_alerts:
                    logger.info(f"All alerts have already been sent for config {alert_config.id}")
                    return True  # Return success as all alerts were already sent
                
                total_new = len(new_alerts)
                logger.info(f"Sending {total_new} new alerts (filtered {len(alerts_data.get('results', [])) - total_new} duplicates)")
                alerts_data['results'] = new_alerts
                alerts_data['total'] = total_new
            
            # Get alert count by severity
            alert_counts = self.opensearch.get_alert_count_by_severity(
                start_time=start_time,
                end_time=end_time
            )
            
            # Generate report as attachment
            report = self.report_generator.generate_report({
                'severity_levels': severity_levels
            }, start_time, end_time, format='pdf')
            
            if not report:
                logger.error("Failed to generate report for email attachment")
                # Continue anyway to send the alert email
            
            # Build email subject
            total_alerts = alerts_data.get('total', 0)
            subject = f"Security Alert: {total_alerts} new alerts detected"
            
            # Get the include_fields if available
            include_fields = []
            if hasattr(alert_config, 'get_include_fields') and callable(getattr(alert_config, 'get_include_fields')):
                include_fields = alert_config.get_include_fields()
            else:
                include_fields = ["@timestamp", "agent.ip", "agent.labels.location.set", "agent.name", "rule.description", "rule.id"]
            
            # Build email body
            body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .alert-summary {{ margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 5px solid #dc3545; }}
                    .alert-count {{ font-weight: bold; color: #dc3545; }}
                    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                    .critical {{ color: #dc3545; font-weight: bold; }}
                    .high {{ color: #fd7e14; font-weight: bold; }}
                    .medium {{ color: #ffc107; }}
                    .low {{ color: #6c757d; }}
                    .table-container {{ margin-top: 20px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <h1>Security Alert Notification</h1>
                
                <div class="alert-summary">
                    <p>A total of <span class="alert-count">{total_alerts}</span> alerts have been detected in the last {alert_check_interval} minutes matching your alert configuration.</p>
                    <p>Alert levels: {', '.join(severity_levels)}</p>
                    <p>Time range: {start_time.replace('T', ' ').split('.')[0]} to {end_time.replace('T', ' ').split('.')[0]} (UTC)</p>
                </div>
                
                <h2>Alert Summary by Severity</h2>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
            """
            
            # Add count rows
            for severity, count in alert_counts.items():
                if severity == "none" or count == 0:
                    continue
                body += f"""
                    <tr>
                        <td class="{severity}">{severity.capitalize()}</td>
                        <td>{count}</td>
                    </tr>
                """
            
            body += """
                </table>
                
                <h2>Recent Security Alerts</h2>
                <div class="table-container">
                <table>
                    <tr>
            """
            
            # Create table headers based on include_fields
            field_headers = {
                "@timestamp": "Timestamp",
                "agent.ip": "Agent IP",
                "agent.labels.location.set": "Location",
                "agent.name": "Agent Name",
                "rule.description": "Description",
                "rule.id": "Rule ID",
                "rule.level": "Severity Level",
                "decoder.name": "Decoder",
                "full_log": "Full Log"
            }
            
            # Add headers for each included field
            for field in include_fields:
                header = field_headers.get(field, field.split('.')[-1].capitalize())
                body += f"<th>{header}</th>"
            
            body += "</tr>"
            
            # Add recent alerts with the specified fields
            for alert in alerts_data.get('results', [])[:10]:  # Only show top 10
                source = alert.get('source', {})
                
                # Determine severity level
                level = source.get('rule', {}).get('level', 0)
                severity_class = "low"
                if level >= 15:
                    severity_class = "critical"
                elif level >= 12:
                    severity_class = "high"
                elif level >= 7:
                    severity_class = "medium"
                
                body += f'<tr class="{severity_class}">'
                
                # Add data for each field
                for field in include_fields:
                    value = "N/A"
                    
                    # Handle nested fields with dot notation
                    if '.' in field:
                        parts = field.split('.')
                        current = source.copy()
                        
                        # Special handling for agent.labels.location.set
                        if field == "agent.labels.location.set":
                            if 'agent' in current and 'labels' in current['agent'] and 'location' in current['agent']['labels']:
                                value = current['agent']['labels']['location'].get('set', 'N/A')
                        else:
                            # General handling for nested fields
                            for part in parts:
                                if isinstance(current, dict) and part in current:
                                    current = current.get(part)
                                else:
                                    current = "N/A"
                                    break
                            
                            if current not in ["N/A", None]:
                                value = current
                    else:
                        value = source.get(field, "N/A")
                    
                    # Format timestamp nicely if it's a timestamp field
                    if field == "@timestamp" and value != "N/A" and isinstance(value, str):
                        try:
                            # Extract date part for cleaner display
                            if 'T' in value:
                                date_parts = value.split('T')
                                if len(date_parts) > 1 and '.' in date_parts[1]:
                                    time_parts = date_parts[1].split('.')
                                    value = f"{date_parts[0]} {time_parts[0]}"
                                else:
                                    value = f"{date_parts[0]} {date_parts[1]}"
                        except Exception:
                            # If formatting fails, just use the original value
                            pass
                    
                    # Truncate very long values
                    if isinstance(value, str) and len(value) > 100:
                        value = value[:97] + "..."
                    
                    body += f"<td>{value}</td>"
                
                body += "</tr>"
            
            body += """
                </table>
                </div>
                
                <p>This is an automated alert from AZ Sentinel X. A detailed report is attached.</p>
            </body>
            </html>
            """
            
            # Prepare attachment if report was generated
            attachments = None
            if report:
                attachments = [{
                    'content': report,
                    'filename': f"security_alert_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    'mime_type': 'application/pdf'
                }]
            
            # Send the email
            return self.send_alert_email(recipient, subject, body, attachments)
        
        except Exception as e:
            logger.error(f"Error sending severity alert: {str(e)}")
            return False
