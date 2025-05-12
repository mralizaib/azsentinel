from app import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='agent')  # 'admin' or 'agent'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with other models
    alert_configs = db.relationship('AlertConfig', backref='user', lazy='dynamic')
    report_configs = db.relationship('ReportConfig', backref='user', lazy='dynamic')
    ai_templates = db.relationship('AiInsightTemplate', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_import_agent(self):
        return self.role == 'import_agent'
    
    def can_edit_settings(self):
        """Check if the user has permission to edit settings"""
        return self.is_admin() or (self.role == 'agent' and not self.is_import_agent())
    
    def __repr__(self):
        return f'<User {self.username}>'

class AlertConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    alert_levels = db.Column(db.String(100), nullable=False)  # JSON string of levels: ['critical', 'high', etc.]
    email_recipient = db.Column(db.String(120), nullable=False)
    notify_time = db.Column(db.String(50))  # Time of day for notification
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    include_fields = db.Column(db.String(500))  # JSON string of fields to include in the alert
    
    def get_alert_levels(self):
        if self.alert_levels:
            return json.loads(self.alert_levels)
        return []
    
    def set_alert_levels(self, levels):
        self.alert_levels = json.dumps(levels)
        
    def get_include_fields(self):
        if self.include_fields:
            return json.loads(self.include_fields)
        return ["@timestamp", "agent.ip", "agent.labels.location.set", "agent.name", "rule.description", "rule.id"]
    
    def set_include_fields(self, fields):
        self.include_fields = json.dumps(fields)
    
    def __repr__(self):
        return f'<AlertConfig {self.name}>'

class ReportConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    severity_levels = db.Column(db.String(100), nullable=False)  # JSON string
    format = db.Column(db.String(10), default='pdf')  # 'pdf' or 'html'
    schedule = db.Column(db.String(50))  # 'daily', 'weekly', etc.
    schedule_time = db.Column(db.String(50))  # Time of day
    recipients = db.Column(db.String(500))  # JSON string of email addresses
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_severity_levels(self):
        return json.loads(self.severity_levels)
    
    def set_severity_levels(self, levels):
        self.severity_levels = json.dumps(levels)
    
    def get_recipients(self):
        return json.loads(self.recipients)
    
    def set_recipients(self, recipients):
        self.recipients = json.dumps(recipients)
    
    def __repr__(self):
        return f'<ReportConfig {self.name}>'

class AiInsightTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    fields = db.Column(db.Text)  # JSON string of fields to analyze
    model_type = db.Column(db.String(50), default='openai')  # 'openai', 'deepseek', 'ollama'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_fields(self):
        return json.loads(self.fields)
    
    def set_fields(self, fields):
        self.fields = json.dumps(fields)
    
    def __repr__(self):
        return f'<AiInsightTemplate {self.name}>'

class AiInsightResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('ai_insight_template.id'), nullable=False)
    data_source = db.Column(db.Text)  # Source data used for analysis
    result = db.Column(db.Text)  # AI analysis result
    rating = db.Column(db.Float)  # User-provided rating
    follow_up_questions = db.Column(db.Text)  # JSON string of follow-up questions and answers
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    template = db.relationship('AiInsightTemplate', backref='results')
    
    def get_follow_up_questions(self):
        if self.follow_up_questions:
            return json.loads(self.follow_up_questions)
        return []
    
    def add_follow_up(self, question, answer):
        follow_ups = self.get_follow_up_questions()
        follow_ups.append({'question': question, 'answer': answer, 'timestamp': datetime.utcnow().isoformat()})
        self.follow_up_questions = json.dumps(follow_ups)
    
    def __repr__(self):
        return f'<AiInsightResult for template {self.template_id}>'


class RetentionPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    # Data Source
    source_type = db.Column(db.String(20), nullable=False)  # 'wazuh', 'opensearch', 'database'
    
    # Retention settings
    retention_days = db.Column(db.Integer, nullable=False)  # Number of days to retain data
    
    # Data filtering
    severity_levels = db.Column(db.String(100))  # JSON string ['critical', 'high', etc.]
    rule_ids = db.Column(db.Text)  # JSON string of rule IDs to include
    
    # Schedule
    cron_schedule = db.Column(db.String(100))  # Cron expression for scheduling
    last_run = db.Column(db.DateTime)  # Last execution timestamp
    
    # Status
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship back to user
    user = db.relationship('User', backref='retention_policies')
    
    def get_severity_levels(self):
        if self.severity_levels:
            return json.loads(self.severity_levels)
        return []
    
    def set_severity_levels(self, levels):
        self.severity_levels = json.dumps(levels)
    
    def get_rule_ids(self):
        if self.rule_ids:
            return json.loads(self.rule_ids)
        return []
    
    def set_rule_ids(self, rule_ids):
        self.rule_ids = json.dumps(rule_ids)
    
    def __repr__(self):
        return f'<RetentionPolicy {self.name} for {self.source_type}>'


class SentAlert(db.Model):
    """Track already sent alerts to prevent duplicates"""
    id = db.Column(db.Integer, primary_key=True)
    alert_config_id = db.Column(db.Integer, db.ForeignKey('alert_config.id'), nullable=False)
    alert_identifier = db.Column(db.String(500), nullable=False)  # Hash of unique alert identifiers
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define relationship to AlertConfig
    alert_config = db.relationship('AlertConfig', backref='sent_alerts')
    
    def __repr__(self):
        return f'<SentAlert {self.alert_identifier[:10]}... for config {self.alert_config_id}>'


class SystemConfig(db.Model):
    """
    Store global system configuration settings
    
    This model stores key-value pairs for system-wide configuration settings
    like refresh intervals, default values, and other app settings.
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_value(key, default=None):
        """Get a configuration value by key with an optional default"""
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            return config.value
        return default
    
    @staticmethod
    def set_value(key, value, description=None):
        """Set a configuration value, creating it if it doesn't exist"""
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            config.value = value
            config.updated_at = datetime.utcnow()
        else:
            config = SystemConfig(key=key, value=value, description=description)
            db.session.add(config)
        db.session.commit()
        return config
    
    def __repr__(self):
        return f'<SystemConfig {self.key}={self.value}>'
