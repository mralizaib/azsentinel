import logging
from datetime import datetime, timedelta
import json
import re
from flask_apscheduler import APScheduler
from models import AlertConfig, ReportConfig, SystemConfig, db
from email_alerts import EmailAlerts
from report_generator import ReportGenerator


def normalize_time(time_str):
    """
    Normalize various time formats to HH:MM format
    
    Args:
        time_str: Time string in various formats (HH:MM, H:MM, or HH:MM:SS)
        
    Returns:
        Normalized time string in HH:MM format
    """
    if not time_str:
        return None
    
    original_time = time_str    
    try:
        # Handle string formats with colons (HH:MM, H:MM, or HH:MM:SS)
        if ':' in time_str:
            # Use regex to extract hours and minutes
            match = re.match(r'(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?', time_str)
            if match:
                hour = int(match.group(1))
                minute = int(match.group(2))
                normalized = f"{hour:02d}:{minute:02d}"
                logger.debug(f"Time normalization: '{original_time}' → '{normalized}' (colon format)")
                return normalized
            else:
                logger.warning(f"Time format not recognized (has colon but didn't match pattern): {time_str}")
                return time_str
        else:
            # Handle non-standard formats by attempting to parse as a timestamp
            try:
                # Try to parse as a numeric timestamp
                timestamp = int(time_str)
                hour = (timestamp // 3600) % 24
                minute = (timestamp % 3600) // 60
                normalized = f"{hour:02d}:{minute:02d}"
                logger.debug(f"Time normalization: '{original_time}' → '{normalized}' (numeric format)")
                return normalized
            except (ValueError, TypeError):
                # If all else fails, return as is
                logger.warning(f"Time format not recognized (couldn't parse as number): {time_str}")
                return time_str
    except Exception as e:
        logger.error(f"Error normalizing time '{time_str}': {str(e)}")
        return time_str

logger = logging.getLogger(__name__)

# Initialize the scheduler
scheduler = APScheduler()

# Define the jobs to be run
def check_and_send_alerts():
    """
    Check for alerts that need to be sent based on alert configurations
    This job will run at the interval defined in system config
    """
    logger.info("Running scheduled alert check job")
    
    if not scheduler.app:
        logger.error("Scheduler app is not initialized")
        return
        
    try:
        # Use the application context from the scheduler
        with scheduler.app.app_context():
            # Get all enabled alert configs
            alert_configs = AlertConfig.query.filter_by(enabled=True).all()
            if not alert_configs:
                logger.info("No enabled alert configurations found")
                return
            
            logger.info(f"Found {len(alert_configs)} enabled alert configurations")
            email_alerts = EmailAlerts()
            
            # Process each alert configuration
            for alert_config in alert_configs:
                try:
                    # If notify_time is set, check if it's time to send the alert
                    if alert_config.notify_time:
                        # Get current time in 24-hour format
                        now = datetime.utcnow()
                        # Format current time and then normalize it to ensure consistent formatting
                        current_time = now.strftime('%H:%M')
                        normalized_current_time = normalize_time(current_time)
                        
                        # Normalize the scheduled notify time using the helper function
                        normalized_scheduled_time = normalize_time(alert_config.notify_time)
                        
                        logger.debug(f"Alert check time - Scheduled: {normalized_scheduled_time}, Current: {normalized_current_time}")
                        
                        if normalized_current_time != normalized_scheduled_time:
                            logger.debug(f"Skipping alert config {alert_config.id} - scheduled for {normalized_scheduled_time}, current time is {normalized_current_time}")
                            continue
                    
                    # Send the alert
                    logger.info(f"Sending alert for config ID {alert_config.id}")
                    result = email_alerts.send_severity_alert(alert_config)
                    if result:
                        logger.info(f"Successfully sent alert for config ID {alert_config.id}")
                    else:
                        logger.error(f"Failed to send alert for config ID {alert_config.id}")
                
                except Exception as e:
                    logger.error(f"Error processing alert config {alert_config.id}: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error in check_and_send_alerts job: {str(e)}")


def generate_and_send_reports():
    """
    Generate and send reports based on report configurations
    This job will run daily and check if any reports need to be sent
    """
    logger.info("Running scheduled report generation job")
    
    if not scheduler.app:
        logger.error("Scheduler app is not initialized")
        return

    try:
        # Use the application context from the scheduler
        with scheduler.app.app_context():
            # Get all enabled report configs
            report_configs = ReportConfig.query.filter_by(enabled=True).all()
            if not report_configs:
                logger.info("No enabled report configurations found")
                return
            
            logger.info(f"Found {len(report_configs)} enabled report configurations")
            report_generator = ReportGenerator()
            email_alerts = EmailAlerts()
            
            now = datetime.utcnow()
            current_time = now.strftime('%H:%M')
            current_day = now.strftime('%A').lower()
            
            logger.debug(f"Current time: {current_time}, Current day: {current_day}")
            
            # Process each report configuration
            for report_config in report_configs:
                try:
                    should_run = False
                    
                    # Log detailed schedule information
                    logger.debug(f"Report {report_config.id} schedule: {report_config.schedule}, time: {report_config.schedule_time}")
                    
                    # Normalize the time formats to ensure consistent comparison
                    # Sometimes the time is stored with seconds or without leading zeros
                    scheduled_time = report_config.schedule_time
                    
                    # Parse and normalize the scheduled time using the helper function
                    normalized_scheduled_time = normalize_time(scheduled_time)
                        
                    # Get current time and normalize it for consistent comparison
                    normalized_current_time = normalize_time(current_time)
                    
                    logger.debug(f"Normalized times - Scheduled: {normalized_scheduled_time}, Current: {normalized_current_time}")
                        
                    # Check if it's time to run this report using normalized times
                    if report_config.schedule == 'daily':
                        scheduled_time_match = normalized_scheduled_time == normalized_current_time
                        logger.debug(f"Daily report check - Scheduled: {normalized_scheduled_time}, Current: {normalized_current_time}, Match: {scheduled_time_match}")
                        if scheduled_time_match:
                            should_run = True
                            
                    elif report_config.schedule == 'weekly' and current_day == 'monday':
                        scheduled_time_match = normalized_scheduled_time == normalized_current_time
                        logger.debug(f"Weekly report check - Day match: True, Scheduled: {normalized_scheduled_time}, Current: {normalized_current_time}, Match: {scheduled_time_match}")
                        if scheduled_time_match:
                            should_run = True
                            
                    elif report_config.schedule == 'monthly' and now.day == 1:
                        scheduled_time_match = normalized_scheduled_time == normalized_current_time
                        logger.debug(f"Monthly report check - Day match: True, Scheduled: {normalized_scheduled_time}, Current: {normalized_current_time}, Match: {scheduled_time_match}")
                        if scheduled_time_match:
                            should_run = True
                    
                    if should_run:
                        logger.info(f"Scheduled report {report_config.id} ({report_config.name}) will run now")
                    
                    if not should_run:
                        logger.debug(f"Skipping report {report_config.id} - not scheduled for current time")
                        continue
                    
                    # Generate the report
                    logger.info(f"Generating report for config ID {report_config.id}")
                    
                    # Set time range for the report
                    if report_config.schedule == 'daily':
                        start_time = (now - timedelta(days=1)).isoformat()
                    elif report_config.schedule == 'weekly':
                        start_time = (now - timedelta(days=7)).isoformat()
                    elif report_config.schedule == 'monthly':
                        start_time = (now - timedelta(days=30)).isoformat()
                    else:
                        start_time = (now - timedelta(days=1)).isoformat()
                    
                    end_time = now.isoformat()
                    
                    # Generate report
                    report = report_generator.generate_report(
                        report_config=report_config,
                        start_time=start_time,
                        end_time=end_time,
                        format=report_config.format
                    )
                    
                    # If report generation was successful, send it via email
                    if report:
                        # Get recipients
                        recipients = report_config.get_recipients()
                        if not recipients:
                            logger.error(f"No recipients specified for report config {report_config.id}")
                            continue
                        
                        # Send to each recipient
                        for recipient in recipients:
                            subject = f"Security Report: {report_config.name} - {now.strftime('%Y-%m-%d')}"
                            message = f"Attached is your scheduled security report: {report_config.name}"
                            
                            # Prepare attachment
                            filename = f"security_report_{report_config.name.replace(' ', '_')}_{now.strftime('%Y%m%d')}"
                            if report_config.format == 'pdf':
                                mime_type = 'application/pdf'
                                filename += '.pdf'
                            else:
                                mime_type = 'text/html'
                                filename += '.html'
                            
                            attachments = [{
                                'content': report,
                                'filename': filename,
                                'mime_type': mime_type
                            }]
                            
                            # Send email with attachment
                            result = email_alerts.send_alert_email(
                                recipient=recipient,
                                subject=subject,
                                message=message,
                                attachments=attachments
                            )
                            
                            if result:
                                logger.info(f"Successfully sent report to {recipient}")
                            else:
                                logger.error(f"Failed to send report to {recipient}")
                
                except Exception as e:
                    logger.error(f"Error processing report config {report_config.id}: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error in generate_and_send_reports job: {str(e)}")


def update_scheduler_jobs():
    """
    Update scheduler jobs based on system configuration
    """
    logger.info("Updating scheduler jobs")
    
    if not scheduler.app:
        logger.error("Scheduler app is not initialized")
        return
        
    try:
        # Use the application context from the scheduler
        with scheduler.app.app_context():
            # Get alert check interval from system config or use default (15 minutes)
            interval_value = SystemConfig.get_value('alert_check_interval', '15')
            alert_check_interval = 15  # Default fallback
            
            if interval_value:
                try:
                    alert_check_interval = int(interval_value)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid alert_check_interval value: {interval_value}, using default 15")
            else:
                logger.warning("No alert_check_interval value found, using default 15")
            
            # Remove existing jobs (if any)
            try:
                scheduler.remove_job('check_alerts')
            except Exception:
                pass  # Job might not exist yet
                
            try:
                scheduler.remove_job('generate_reports')
            except Exception:
                pass  # Job might not exist yet
            
            # Add the alert check job
            scheduler.add_job(
                id='check_alerts',
                func=check_and_send_alerts,
                trigger='interval',
                minutes=alert_check_interval
            )
            
            # Add the report generation job 
            # This runs every minute to check if any reports need to be sent
            scheduler.add_job(
                id='generate_reports',
                func=generate_and_send_reports,
                trigger='interval',
                minutes=1
            )
            
            logger.info(f"Scheduler jobs updated. Alert check interval: {alert_check_interval} minutes")
    
    except Exception as e:
        logger.error(f"Error updating scheduler jobs: {str(e)}")


def init_app(app):
    """
    Initialize the scheduler with the Flask app
    """
    # Set up the APScheduler
    scheduler.init_app(app)
    scheduler.app = app
    
    # Start the scheduler
    scheduler.start()
    logger.info("APScheduler started")
    
    # Set up the initial jobs
    with app.app_context():
        # Create default alert_check_interval if it doesn't exist
        if not SystemConfig.get_value('alert_check_interval'):
            SystemConfig.set_value(
                'alert_check_interval',
                '15',
                'Interval in minutes between alert checks'
            )
            db.session.commit()
            logger.info("Created default alert_check_interval system config")
        
        # Update the scheduler jobs
        update_scheduler_jobs()