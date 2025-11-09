"""
Real-time Intrusion Detector
Monitors traffic and detects attacks using the trained ML model.
"""

import logging
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional
from config import Config, CONFIG

from src.models.predictor import IDSPredictor
from src.database.logger import DatabaseLogger
from src.database.statistics import DatabaseStatistics
from src.intelligence.ip_enrichment import IPEnricher
from src.intelligence.vpn_detector import VPNDetector
from src.intelligence.threat_scoring import ThreatScorer

logger = logging.getLogger(__name__)


class IntrusionDetector:
    """Real-time intrusion detection system"""

    def __init__(self):
        self.config = CONFIG
        self.predictor = IDSPredictor()
        self.db_logger = DatabaseLogger()
        self.db_stats = DatabaseStatistics()
        self.ip_enricher = IPEnricher()
        self.vpn_detector = VPNDetector()
        self.threat_scorer = ThreatScorer()

        # Detection settings
        self.threshold = self.config['detection']['threshold']
        self.thresholds = self.config['detection']['thresholds']

        # Load model
        try:
            self.predictor.load()
            logger.info("IDS Detector initialized successfully")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise

    def detect(self, traffic_data: Dict) -> Optional[Dict]:
        """
        Detect if traffic is an attack

        Args:
            traffic_data: Dictionary with traffic features

        Returns:
            Detection result if attack detected, None otherwise
        """
        try:
            # Make prediction
            prediction = self.predictor.predict_single(traffic_data)

            predicted_class = prediction['predicted_class']
            confidence = prediction['confidence']

            # Check if attack detected
            if predicted_class == 'normal':
                return None

            # Check confidence threshold
            attack_threshold = self.thresholds.get(predicted_class, self.threshold)

            if confidence < attack_threshold:
                logger.debug(f"Low confidence detection: {predicted_class} ({confidence:.2f})")
                return None

            # Attack detected! Enrich with intelligence
            source_ip = traffic_data.get('source_ip', 'unknown')

            logger.warning(f"ATTACK DETECTED: {predicted_class} from {source_ip} (confidence: {confidence:.2f})")

            # Enrich IP information
            ip_info = self.ip_enricher.enrich(source_ip)

            # Detect VPN
            vpn_info = self.vpn_detector.detect(source_ip, ip_info)

            # Calculate threat score
            threat_score = self.threat_scorer.calculate_score(
                attack_type=predicted_class,
                confidence=confidence,
                ip_info=ip_info,
                vpn_probability=vpn_info.get('probability', 0.0)
            )

            # Create attack record
            attack_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'destination_ip': traffic_data.get('destination_ip'),
                'destination_port': traffic_data.get('destination_port'),
                'attack_type': predicted_class,
                'confidence': confidence,
                'protocol': traffic_data.get('protocol'),
                'service': traffic_data.get('service'),
                'flags': traffic_data.get('flags'),
                'src_bytes': traffic_data.get('src_bytes', 0),
                'dst_bytes': traffic_data.get('dst_bytes', 0),
                'duration': traffic_data.get('duration', 0),

                # IP Intelligence
                'country': ip_info.get('country'),
                'city': ip_info.get('city'),
                'region': ip_info.get('region'),
                'latitude': ip_info.get('latitude'),
                'longitude': ip_info.get('longitude'),
                'asn': ip_info.get('asn'),
                'organization': ip_info.get('org'),

                # VPN Detection
                'is_vpn': vpn_info.get('is_vpn', 0),
                'vpn_probability': vpn_info.get('probability', 0.0),

                # Threat Score
                'threat_score': threat_score,

                # Model info
                'model_version': '1.0.0',
                'raw_features': traffic_data
            }

            # Log to database
            attack_id = self.db_logger.log_attack(attack_data)
            self.db_logger.update_ip_statistics(source_ip, attack_data)

            if traffic_data.get('destination_port'):
                self.db_logger.update_port_statistics(traffic_data['destination_port'], attack_data)

            attack_data['attack_id'] = attack_id

            return attack_data

        except Exception as e:
            logger.error(f"Error during detection: {e}", exc_info=True)
            return None

    def detect_batch(self, traffic_batch: List[Dict]) -> List[Dict]:
        """
        Detect attacks in a batch of traffic

        Args:
            traffic_batch: List of traffic dictionaries

        Returns:
            List of detected attacks
        """
        detected_attacks = []

        for traffic in traffic_batch:
            attack = self.detect(traffic)
            if attack:
                detected_attacks.append(attack)

        return detected_attacks

    def get_recent_attacks(self, hours=24, limit=100) -> List[Dict]:
        """Get recent attacks from database"""
        return self.db_stats.get_recent_attacks(limit=limit, hours=hours)

    def get_top_attackers(self, hours=24, limit=20) -> List[Dict]:
        """Get top attacking IPs"""
        return self.db_stats.get_top_attackers(limit=limit, hours=hours)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Test detector
    detector = IntrusionDetector()

    # Sample attack traffic
    sample_traffic = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'destination_port': 80,
        'protocol': 'tcp',
        'service': 'http',
        'flags': 'SF',
        'src_bytes': 500,
        'dst_bytes': 200,
        'duration': 1.5
    }

    print("\nTesting IDS Detector...")
    result = detector.detect(sample_traffic)

    if result:
        print(f"\nAttack Detected!")
        print(f"  Type: {result['attack_type']}")
        print(f"  Confidence: {result['confidence']:.2f}")
        print(f"  Source: {result['source_ip']}")
        print(f"  Location: {result.get('city')}, {result.get('country')}")
        print(f"  VPN Probability: {result['vpn_probability']:.2f}")
        print(f"  Threat Score: {result['threat_score']:.2f}")
    else:
        print("\nNo attack detected (normal traffic)")
