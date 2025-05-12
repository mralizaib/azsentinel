import os
import logging
from datetime import timedelta
from flask import Flask, g, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, current_user

# Configure more detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# Set specific loggers to DEBUG level
for logger_name in ['scheduler', 'email_alerts', 'routes.admin', 'opensearch_api', 'report_generator']:
    logging.getLogger(logger_name).setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the Base class
db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
database_url = os.environ.get("DATABASE_URL")
logger.info(f"Database URL (redacted): {'Found' if database_url else 'Not found'}")

# Ensure we have a database URL
if not database_url:
    logger.error("DATABASE_URL environment variable is not set")
    database_url = "sqlite:///sentinel.db"  # Fallback for development
    logger.info("Using fallback SQLite database")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Set the permanent session lifetime
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# Initialize the database
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"
login_manager.login_message_category = "danger"

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Import routes after db initialization to avoid circular imports
with app.app_context():
    # Create tables
    from models import User, AlertConfig, ReportConfig, AiInsightTemplate, AiInsightResult, RetentionPolicy, SentAlert, SystemConfig
    db.create_all()
    
    # Create default admin user if no users exist
    if User.query.count() == 0:
        default_admin = User(
            username="admin",
            email="admin@example.com",
            role="admin"
        )
        default_admin.set_password("admin123")
        db.session.add(default_admin)
        db.session.commit()
        logger.info("Created default admin user")
    
    # Import and register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.reports import reports_bp
    from routes.alerts import alerts_bp
    from routes.insights import insights_bp
    from routes.users import users_bp
    from routes.retention import retention_bp
    from routes.config import config_bp
    from routes.admin import admin_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(insights_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(retention_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(admin_bp)
    
    # Initialize the scheduler for background tasks
    import scheduler
    scheduler.init_app(app)

@app.before_request
def before_request():
    g.user = current_user
    # Check if user is authenticated and accessing a non-auth route
    if current_user.is_authenticated:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)
        session.modified = True

@app.route('/')
def index():
    return redirect(url_for('dashboard.index'))

# Error handlers
@app.errorhandler(404)
def page_not_found(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return "Internal server error", 500
