# -*- coding: utf-8 -*-
"""
Database Logger for AI-Powered IDS
Handles logging of attacks, events, and statistics to the database.
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from config import Config
from src.database.schema import DatabaseSchema

logger = logging.getLogger(__name__)


class DatabaseLogger:
    """Logs attacks, events, and statistics to the database"""

    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DB_PATH
        self.schema = DatabaseSchema(self.db_path)

    def _get_connection(self):
        """Get database connection"""
        return self.schema.get_connection()

    def log_attack(self, attack_data: Dict[str, Any]) -> int:
        """Log an attack to the database"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            severity = self._determine_severity(attack_data.get('attack_type', ''))

            cursor.execute('''
                INSERT INTO attack_logs (
                    timestamp, source_ip, destination_ip, destination_port,
                    attack_type, attack_subtype, confidence,
                    protocol, service, flags, src_bytes, dst_bytes, duration, packet_count,
                    country, city, region, latitude, longitude,
                    asn, organization, is_vpn, vpn_probability, threat_score,
                    raw_features, model_version, detection_method, severity,
                    is_blocked, is_alerted, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_data.get('timestamp', datetime.now().isoformat()),
                attack_data['source_ip'],
                attack_data.get('destination_ip'),
                attack_data.get('destination_port'),
                attack_data['attack_type'],
                attack_data.get('attack_subtype'),
                attack_data['confidence'],
                attack_data.get('protocol'),
                attack_data.get('service'),
                attack_data.get('flags'),
                attack_data.get('src_bytes'),
                attack_data.get('dst_bytes'),
                attack_data.get('duration'),
                attack_data.get('packet_count'),
                attack_data.get('country'),
                attack_data.get('city'),
                attack_data.get('region'),
                attack_data.get('latitude'),
                attack_data.get('longitude'),
                attack_data.get('asn'),
                attack_data.get('organization'),
                attack_data.get('is_vpn', 0),
                attack_data.get('vpn_probability', 0.0),
                attack_data.get('threat_score', 0.0),
                json.dumps(attack_data.get('raw_features')) if attack_data.get('raw_features') else None,
                attack_data.get('model_version', '1.0.0'),
                attack_data.get('detection_method', 'xgboost'),
                severity,
                attack_data.get('is_blocked', 0),
                attack_data.get('is_alerted', 0),
                attack_data.get('notes')
            ))

            attack_id = cursor.lastrowid
            conn.commit()
            logger.debug(f"Attack logged: ID={attack_id}")
            return attack_id

        except Exception as e:
            conn.rollback()
            logger.error(f"Error logging attack: {e}")
            raise
        finally:
            conn.close()

    def update_ip_statistics(self, ip_address: str, attack_data: Dict[str, Any]):
        """Update statistics for an IP address"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT * FROM ip_statistics WHERE ip_address = ?', (ip_address,))
            existing = cursor.fetchone()

            attack_type = attack_data.get('attack_type', 'unknown').lower()
            timestamp = attack_data.get('timestamp', datetime.now().isoformat())

            if existing:
                cursor.execute('''
                    UPDATE ip_statistics SET
                        last_seen = ?, total_attacks = total_attacks + 1,
                        dos_attacks = dos_attacks + ?, probe_attacks = probe_attacks + ?,
                        r2l_attacks = r2l_attacks + ?, u2r_attacks = u2r_attacks + ?,
                        total_connections = total_connections + 1,
                        total_bytes_sent = total_bytes_sent + ?,
                        total_bytes_received = total_bytes_received + ?,
                        country = ?, city = ?, asn = ?, organization = ?,
                        is_vpn = ?, vpn_probability = ?, threat_score = ?, updated_at = ?
                    WHERE ip_address = ?
                ''', (
                    timestamp,
                    1 if attack_type == 'dos' else 0, 1 if attack_type == 'probe' else 0,
                    1 if attack_type == 'r2l' else 0, 1 if attack_type == 'u2r' else 0,
                    attack_data.get('src_bytes', 0), attack_data.get('dst_bytes', 0),
                    attack_data.get('country'), attack_data.get('city'),
                    attack_data.get('asn'), attack_data.get('organization'),
                    attack_data.get('is_vpn', 0), attack_data.get('vpn_probability', 0.0),
                    attack_data.get('threat_score', 0.0), timestamp, ip_address
                ))
            else:
                cursor.execute('''
                    INSERT INTO ip_statistics (
                        ip_address, first_seen, last_seen, total_attacks,
                        dos_attacks, probe_attacks, r2l_attacks, u2r_attacks,
                        total_connections, total_bytes_sent, total_bytes_received,
                        country, city, asn, organization, is_vpn, vpn_probability,
                        threat_score, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ip_address, timestamp, timestamp, 1,
                    1 if attack_type == 'dos' else 0, 1 if attack_type == 'probe' else 0,
                    1 if attack_type == 'r2l' else 0, 1 if attack_type == 'u2r' else 0,
                    1, attack_data.get('src_bytes', 0), attack_data.get('dst_bytes', 0),
                    attack_data.get('country'), attack_data.get('city'),
                    attack_data.get('asn'), attack_data.get('organization'),
                    attack_data.get('is_vpn', 0), attack_data.get('vpn_probability', 0.0),
                    attack_data.get('threat_score', 0.0), timestamp
                ))

            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating IP statistics: {e}")
            raise
        finally:
            conn.close()

    def _determine_severity(self, attack_type: str) -> str:
        """Determine attack severity"""
        attack_type = attack_type.lower()
        if attack_type in ['u2r', 'dos']:
            return 'critical'
        elif attack_type in ['r2l']:
            return 'high'
        elif attack_type in ['probe']:
            return 'medium'
        return 'low'
