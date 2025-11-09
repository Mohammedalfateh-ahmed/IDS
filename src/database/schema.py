"""
Database Schema for AI-Powered IDS
This module defines the SQLite database schema for storing attack logs,
IP statistics, and system events.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)


class DatabaseSchema:
    """Manages database schema and initialization"""

    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DB_PATH
        self._ensure_db_directory()

    def _ensure_db_directory(self):
        """Create database directory if it doesn't exist"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn

    def create_tables(self):
        """Create all database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            # Attack Logs Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    attack_type TEXT NOT NULL,
                    attack_subtype TEXT,
                    confidence REAL NOT NULL,
                    protocol TEXT,
                    service TEXT,
                    flags TEXT,
                    src_bytes INTEGER,
                    dst_bytes INTEGER,
                    duration REAL,
                    packet_count INTEGER,

                    -- Threat Intelligence
                    country TEXT,
                    city TEXT,
                    region TEXT,
                    latitude REAL,
                    longitude REAL,
                    asn TEXT,
                    organization TEXT,
                    is_vpn INTEGER DEFAULT 0,
                    vpn_probability REAL DEFAULT 0.0,
                    threat_score REAL DEFAULT 0.0,

                    -- Additional metadata
                    raw_features TEXT,
                    model_version TEXT,
                    detection_method TEXT,
                    severity TEXT,

                    -- Status
                    is_blocked INTEGER DEFAULT 0,
                    is_alerted INTEGER DEFAULT 0,
                    notes TEXT
                )
            ''')

            # IP Statistics Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_statistics (
                    ip_address TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,

                    -- Attack counts by type
                    total_attacks INTEGER DEFAULT 0,
                    dos_attacks INTEGER DEFAULT 0,
                    probe_attacks INTEGER DEFAULT 0,
                    r2l_attacks INTEGER DEFAULT 0,
                    u2r_attacks INTEGER DEFAULT 0,

                    -- Traffic statistics
                    total_connections INTEGER DEFAULT 0,
                    total_bytes_sent INTEGER DEFAULT 0,
                    total_bytes_received INTEGER DEFAULT 0,
                    unique_ports_targeted INTEGER DEFAULT 0,
                    unique_destinations INTEGER DEFAULT 0,

                    -- Threat intelligence
                    country TEXT,
                    city TEXT,
                    asn TEXT,
                    organization TEXT,
                    is_vpn INTEGER DEFAULT 0,
                    vpn_probability REAL DEFAULT 0.0,
                    threat_score REAL DEFAULT 0.0,
                    reputation_score REAL DEFAULT 50.0,

                    -- Status
                    is_whitelisted INTEGER DEFAULT 0,
                    is_blacklisted INTEGER DEFAULT 0,
                    is_currently_blocked INTEGER DEFAULT 0,
                    block_expiry TEXT,

                    updated_at TEXT NOT NULL
                )
            ''')

            # Port Statistics Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS port_statistics (
                    port INTEGER PRIMARY KEY,
                    service_name TEXT,
                    first_attacked TEXT,
                    last_attacked TEXT,

                    -- Attack counts
                    total_attacks INTEGER DEFAULT 0,
                    dos_attacks INTEGER DEFAULT 0,
                    probe_attacks INTEGER DEFAULT 0,
                    r2l_attacks INTEGER DEFAULT 0,
                    u2r_attacks INTEGER DEFAULT 0,

                    -- Attackers
                    unique_attackers INTEGER DEFAULT 0,

                    -- Status
                    is_open INTEGER DEFAULT 1,
                    is_critical INTEGER DEFAULT 0,
                    risk_level TEXT,

                    -- Recommendations
                    last_recommendation TEXT,

                    updated_at TEXT NOT NULL
                )
            ''')

            # Alerts Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,

                    -- Alert content
                    source_ip TEXT,
                    attack_type TEXT,
                    affected_port INTEGER,
                    attack_count INTEGER,

                    -- Alert details
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    recommendations TEXT,

                    -- Status
                    is_sent INTEGER DEFAULT 0,
                    sent_at TEXT,
                    delivery_method TEXT,

                    -- Related data
                    related_attack_ids TEXT,

                    error_message TEXT
                )
            ''')

            # Recommendations Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    recommendation_type TEXT NOT NULL,
                    priority TEXT NOT NULL,

                    -- Recommendation details
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    action_required TEXT,
                    affected_resource TEXT,

                    -- Context
                    trigger_ip TEXT,
                    trigger_port INTEGER,
                    attack_type TEXT,
                    attack_count INTEGER,

                    -- Implementation
                    is_implemented INTEGER DEFAULT 0,
                    implemented_at TEXT,
                    implementation_method TEXT,

                    -- Status
                    is_active INTEGER DEFAULT 1,
                    is_dismissed INTEGER DEFAULT 0,
                    dismissed_reason TEXT,

                    expires_at TEXT
                )
            ''')

            # Blocked IPs Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip_address TEXT PRIMARY KEY,
                    blocked_at TEXT NOT NULL,
                    block_expires_at TEXT,

                    -- Reason
                    reason TEXT NOT NULL,
                    attack_type TEXT,
                    attack_count INTEGER,

                    -- Block details
                    block_method TEXT,
                    block_level TEXT,

                    -- Status
                    is_active INTEGER DEFAULT 1,
                    unblocked_at TEXT,
                    unblock_reason TEXT,

                    -- Automatic unblock
                    auto_unblock INTEGER DEFAULT 1
                )
            ''')

            # System Events Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,

                    -- Event details
                    component TEXT,
                    action TEXT,
                    description TEXT,

                    -- Status
                    status TEXT,
                    error_message TEXT,

                    -- Additional data
                    metadata TEXT
                )
            ''')

            # Model Training History Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS model_training_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    model_version TEXT NOT NULL,

                    -- Training details
                    dataset_name TEXT,
                    dataset_size INTEGER,
                    training_duration REAL,

                    -- Performance metrics
                    accuracy REAL,
                    precision REAL,
                    recall REAL,
                    f1_score REAL,

                    -- Per-class metrics (JSON)
                    class_metrics TEXT,

                    -- Hyperparameters (JSON)
                    hyperparameters TEXT,

                    -- Model path
                    model_path TEXT,
                    preprocessor_path TEXT,

                    -- Status
                    is_active INTEGER DEFAULT 0,
                    notes TEXT
                )
            ''')

            # Create indexes for better query performance
            self._create_indexes(cursor)

            conn.commit()
            logger.info(f" Database schema created successfully at {self.db_path}")

        except Exception as e:
            conn.rollback()
            logger.error(f" Error creating database schema: {e}")
            raise
        finally:
            conn.close()

    def _create_indexes(self, cursor):
        """Create database indexes for optimized queries"""

        # Attack Logs indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attack_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attack_logs(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_type ON attack_logs(attack_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_dest_port ON attack_logs(destination_port)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_confidence ON attack_logs(confidence)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_severity ON attack_logs(severity)')

        # IP Statistics indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_last_seen ON ip_statistics(last_seen)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_threat_score ON ip_statistics(threat_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_total_attacks ON ip_statistics(total_attacks)')

        # Port Statistics indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_port_stats_risk ON port_statistics(risk_level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_port_stats_attacks ON port_statistics(total_attacks)')

        # Alerts indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_sent ON alerts(is_sent)')

        # Recommendations indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_recommendations_timestamp ON recommendations(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_recommendations_active ON recommendations(is_active)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_recommendations_priority ON recommendations(priority)')

        # Blocked IPs indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(is_active)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips(block_expires_at)')

        # System Events indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type)')

        logger.info(" Database indexes created successfully")

    def drop_tables(self):
        """Drop all tables (use with caution!)"""
        conn = self.get_connection()
        cursor = conn.cursor()

        tables = [
            'attack_logs',
            'ip_statistics',
            'port_statistics',
            'alerts',
            'recommendations',
            'blocked_ips',
            'system_events',
            'model_training_history'
        ]

        try:
            for table in tables:
                cursor.execute(f'DROP TABLE IF EXISTS {table}')

            conn.commit()
            logger.info(" All tables dropped successfully")
        except Exception as e:
            conn.rollback()
            logger.error(f" Error dropping tables: {e}")
            raise
        finally:
            conn.close()

    def reset_database(self):
        """Reset database (drop and recreate tables)"""
        logger.warning("   Resetting database - all data will be lost!")
        self.drop_tables()
        self.create_tables()
        logger.info(" Database reset complete")

    def get_table_info(self):
        """Get information about all tables"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table'
            ORDER BY name
        """)

        tables = cursor.fetchall()
        table_info = {}

        for table in tables:
            table_name = table[0]
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()

            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            row_count = cursor.fetchone()[0]

            table_info[table_name] = {
                'columns': [col[1] for col in columns],
                'row_count': row_count
            }

        conn.close()
        return table_info

    def vacuum(self):
        """Optimize database (VACUUM)"""
        conn = self.get_connection()
        conn.execute('VACUUM')
        conn.close()
        logger.info(" Database optimized successfully")


def initialize_database(db_path=None):
    """Initialize database with schema"""
    schema = DatabaseSchema(db_path)
    schema.create_tables()
    return schema


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize database
    print("Initializing AI-Powered IDS Database...")
    schema = initialize_database()

    # Display table information
    print("\n=Ê Database Information:")
    table_info = schema.get_table_info()

    for table_name, info in table_info.items():
        print(f"\n  Table: {table_name}")
        print(f"  Rows: {info['row_count']}")
        print(f"  Columns: {len(info['columns'])}")

    print("\n Database initialization complete!")
