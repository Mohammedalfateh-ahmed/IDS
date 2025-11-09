"""
Configuration module for AI-Powered IDS
"""

import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent

# Load YAML configuration
CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"

def load_config():
    """Load configuration from YAML file"""
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

# Global config object
CONFIG = load_config()

# Environment variables with defaults
class Config:
    """Configuration class combining YAML and environment variables"""

    # Email settings
    EMAIL_ENABLED = os.getenv('EMAIL_ENABLED', 'false').lower() == 'true'
    EMAIL_SMTP_SERVER = os.getenv('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
    EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', '587'))
    EMAIL_SENDER = os.getenv('EMAIL_SENDER', '')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
    EMAIL_RECIPIENT = os.getenv('EMAIL_RECIPIENT', '')

    # Database paths
    DB_PATH = os.getenv('DB_PATH', str(PROJECT_ROOT / 'data' / 'ids_database.db'))
    LOG_PATH = os.getenv('LOG_PATH', str(PROJECT_ROOT / 'logs' / 'ids.log'))

    # Model paths
    MODEL_PATH = os.getenv('MODEL_PATH', str(PROJECT_ROOT / 'models' / 'xgboost_ids.pkl'))
    PREPROCESSOR_PATH = os.getenv('PREPROCESSOR_PATH', str(PROJECT_ROOT / 'models' / 'preprocessor.pkl'))
    MODEL_THRESHOLD = float(os.getenv('MODEL_THRESHOLD', '0.7'))

    # Detection settings
    ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', '5'))
    ALERT_TIME_WINDOW = int(os.getenv('ALERT_TIME_WINDOW', '10'))
    AUTO_BLOCK_ENABLED = os.getenv('AUTO_BLOCK_ENABLED', 'false').lower() == 'true'
    AUTO_RECOMMEND_ENABLED = os.getenv('AUTO_RECOMMEND_ENABLED', 'true').lower() == 'true'

    # Monitoring settings
    MONITOR_INTERVAL = int(os.getenv('MONITOR_INTERVAL', '1'))
    MAX_PACKETS_PER_BATCH = int(os.getenv('MAX_PACKETS_PER_BATCH', '100'))
    ENABLE_LIVE_CAPTURE = os.getenv('ENABLE_LIVE_CAPTURE', 'false').lower() == 'true'
    PCAP_INTERFACE = os.getenv('PCAP_INTERFACE', 'eth0')

    # Dashboard settings
    DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', '8501'))
    DASHBOARD_HOST = os.getenv('DASHBOARD_HOST', 'localhost')
    DASHBOARD_TITLE = os.getenv('DASHBOARD_TITLE', 'AI-Powered IDS Dashboard')

    # Logging settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_MAX_SIZE = int(os.getenv('LOG_MAX_SIZE', '10485760'))
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))

    # Security settings
    REQUIRE_SUDO = os.getenv('REQUIRE_SUDO', 'true').lower() == 'true'
    SAFE_MODE = os.getenv('SAFE_MODE', 'true').lower() == 'true'
    WHITELIST_IPS = os.getenv('WHITELIST_IPS', '127.0.0.1,localhost').split(',')

    # Dataset paths
    NSL_KDD_TRAIN = os.getenv('NSL_KDD_TRAIN', str(PROJECT_ROOT / 'data' / 'raw' / 'KDDTrain+.txt'))
    NSL_KDD_TEST = os.getenv('NSL_KDD_TEST', str(PROJECT_ROOT / 'data' / 'raw' / 'KDDTest+.txt'))
    CIC_IDS_PATH = os.getenv('CIC_IDS_PATH', str(PROJECT_ROOT / 'data' / 'raw' / 'cic_ids_2017'))
    CSIC_PATH = os.getenv('CSIC_PATH', str(PROJECT_ROOT / 'data' / 'raw' / 'csic_2010'))

    # API keys
    IP_API_KEY = os.getenv('IP_API_KEY', '')
    IP_API_ENDPOINT = os.getenv('IP_API_ENDPOINT', 'http://ip-api.com/json/')
    IPAPI_KEY = os.getenv('IPAPI_KEY', '')
    ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY', '')

    @classmethod
    def get_yaml_config(cls):
        """Get YAML configuration"""
        return CONFIG

    @classmethod
    def validate(cls):
        """Validate critical configuration"""
        errors = []

        if cls.EMAIL_ENABLED and not cls.EMAIL_SENDER:
            errors.append("EMAIL_SENDER is required when EMAIL_ENABLED=true")

        if cls.EMAIL_ENABLED and not cls.EMAIL_PASSWORD:
            errors.append("EMAIL_PASSWORD is required when EMAIL_ENABLED=true")

        # Create necessary directories
        os.makedirs(os.path.dirname(cls.DB_PATH), exist_ok=True)
        os.makedirs(os.path.dirname(cls.LOG_PATH), exist_ok=True)
        os.makedirs(os.path.dirname(cls.MODEL_PATH), exist_ok=True)

        return errors

# Validate configuration on import
config_errors = Config.validate()
if config_errors:
    print("⚠️  Configuration warnings:")
    for error in config_errors:
        print(f"   - {error}")
