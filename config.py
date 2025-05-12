import os

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-secret-key')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True') == 'True'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Wazuh API configuration
    WAZUH_API_URL = os.environ.get('WAZUH_API_URL', 'https://wazuh.rebiz.com:55000')
    WAZUH_API_USER = os.environ.get('WAZUH_API_USER', 'wazuh-wui')
    WAZUH_API_PASSWORD = os.environ.get('WAZUH_API_PASSWORD', 'Jbbp1P*9ydI*EP7.Wa2MCLsKM?lcz+iH')
    WAZUH_VERIFY_SSL = os.environ.get('WAZUH_VERIFY_SSL', 'False') == 'True'
    
    # OpenSearch configuration
    OPENSEARCH_URL = os.environ.get('OPENSEARCH_URL', 'https://wazuh.rebiz.com:9200')
    OPENSEARCH_USER = os.environ.get('OPENSEARCH_USER', 'admin')
    OPENSEARCH_PASSWORD = os.environ.get('OPENSEARCH_PASSWORD', 'W@zuh0pen1*')
    OPENSEARCH_VERIFY_SSL = os.environ.get('OPENSEARCH_VERIFY_SSL', 'False') == 'True'
    OPENSEARCH_INDEX_PATTERN = os.environ.get('OPENSEARCH_INDEX_PATTERN', 'wazuh-alerts-*')
    
    # AI Model configuration
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY')
    OLLAMA_API_URL = os.environ.get('OLLAMA_API_URL', 'http://localhost:11434')
    
    # Email configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', 'thewazuhalerts@gmail.com')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'blbynewyahfwbhnf')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True') == 'True'
    SMTP_SENDER_NAME = os.environ.get('SMTP_SENDER_NAME', 'WAZUH Alerts')
    # Alert severity levels mapping
    SEVERITY_LEVELS = {
        'critical': 15,                  # Level 15
        'high': list(range(12, 14)),     # Levels 12-14
        'medium': list(range(7, 11)),    # Levels 7-11
        'low': list(range(1, 6))         # Levels 1-6
    }
