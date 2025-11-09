# -*- coding: utf-8 -*-
"""
Database Statistics for AI-Powered IDS
Handles querying and analyzing attack statistics.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from config import Config
from src.database.schema import DatabaseSchema

logger = logging.getLogger(__name__)


class DatabaseStatistics:
    """Query and analyze attack statistics"""

    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DB_PATH
        self.schema = DatabaseSchema(self.db_path)

    def _get_connection(self):
        return self.schema.get_connection()

    def get_recent_attacks(self, limit=100, hours=24):
        """Get recent attacks"""
        conn = self._get_connection()
        cursor = conn.cursor()

        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        cursor.execute('''
            SELECT * FROM attack_logs
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (since, limit))

        attacks = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return attacks

    def get_top_attackers(self, limit=20, hours=24):
        """Get top attacking IPs"""
        conn = self._get_connection()
        cursor = conn.cursor()

        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        cursor.execute('''
            SELECT source_ip, COUNT(*) as attack_count,
                   MAX(attack_type) as primary_attack_type,
                   MAX(country) as country,
                   MAX(threat_score) as threat_score
            FROM attack_logs
            WHERE timestamp >= ?
            GROUP BY source_ip
            ORDER BY attack_count DESC
            LIMIT ?
        ''', (since, limit))

        attackers = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return attackers

    def get_attack_distribution(self, hours=24):
        """Get attack type distribution"""
        conn = self._get_connection()
        cursor = conn.cursor()

        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        cursor.execute('''
            SELECT attack_type, COUNT(*) as count
            FROM attack_logs
            WHERE timestamp >= ?
            GROUP BY attack_type
            ORDER BY count DESC
        ''', (since,))

        distribution = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return distribution

    def get_port_statistics(self, limit=20):
        """Get most attacked ports"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT port, service_name, total_attacks, risk_level
            FROM port_statistics
            ORDER BY total_attacks DESC
            LIMIT ?
        ''', (limit,))

        ports = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return ports

    def get_ip_details(self, ip_address):
        """Get detailed statistics for an IP"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM ip_statistics WHERE ip_address = ?', (ip_address,))
        stats = cursor.fetchone()

        result = dict(stats) if stats else None
        conn.close()
        return result

    def get_attack_timeline(self, hours=24, interval_minutes=60):
        """Get attack counts over time"""
        conn = self._get_connection()
        cursor = conn.cursor()

        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        cursor.execute('''
            SELECT 
                datetime((strftime('%s', timestamp) / ?) * ?, 'unixepoch') as time_bucket,
                COUNT(*) as attack_count
            FROM attack_logs
            WHERE timestamp >= ?
            GROUP BY time_bucket
            ORDER BY time_bucket
        ''', (interval_minutes * 60, interval_minutes * 60, since))

        timeline = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return timeline
