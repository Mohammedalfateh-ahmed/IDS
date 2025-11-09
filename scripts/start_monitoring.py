#!/usr/bin/env python3
"""
Start IDS Monitoring
Real-time intrusion detection and monitoring.
"""

import sys
import time
import logging
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detection.detector import IntrusionDetector
from src.alerting.email_sender import EmailSender
from src.recommendations.rule_engine import RecommendationEngine
from config import Config

logger = logging.getLogger(__name__)


def simulate_traffic():
    """Simulate network traffic for testing"""
    import random

    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'ftp', 'smtp', 'ssh', 'other']
    flags = ['SF', 'S0', 'REJ', 'RSTR']

    while True:
        traffic = {
            'source_ip': f"192.168.1.{random.randint(1, 254)}",
            'destination_ip': '10.0.0.1',
            'destination_port': random.choice([22, 80, 443, 3306, 3389]),
            'protocol': random.choice(protocols),
            'service': random.choice(services),
            'flags': random.choice(flags),
            'src_bytes': random.randint(0, 10000),
            'dst_bytes': random.randint(0, 5000),
            'duration': random.uniform(0, 10)
        }
        yield traffic
        time.sleep(1)


def main():
    """Main monitoring function"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/monitoring.log')
        ]
    )

    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     AI-Powered IDS - Real-Time Monitoring Active         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        # Initialize components
        print("Initializing IDS components...")
        detector = IntrusionDetector()
        email_sender = EmailSender()
        recommender = RecommendationEngine()

        print("✓ IDS initialized successfully")
        print(f"✓ Email alerts: {'Enabled' if email_sender.enabled else 'Disabled'}")
        print(f"✓ Detection threshold: {detector.threshold}")
        print("\nMonitoring for attacks... (Press Ctrl+C to stop)\n")

        # Start monitoring (simulated for now)
        attack_count = 0

        for traffic in simulate_traffic():
            # Detect attacks
            attack = detector.detect(traffic)

            if attack:
                attack_count += 1

                print(f"\n🚨 ATTACK DETECTED #{attack_count}")
                print(f"   Type: {attack['attack_type'].upper()}")
                print(f"   Source: {attack['source_ip']}")
                print(f"   Confidence: {attack['confidence']:.2f}")
                print(f"   Threat Score: {attack['threat_score']:.1f}/100")

                # Generate recommendations
                recommendations = recommender.generate_recommendations(attack)

                # Send email alert
                if Config.EMAIL_ENABLED and attack_count % Config.ALERT_THRESHOLD == 0:
                    print(f"   📧 Sending email alert...")
                    email_sender.send_attack_alert(attack, recommendations)

    except KeyboardInterrupt:
        print("\n\n✓ Monitoring stopped by user")

    except FileNotFoundError:
        print("\n❌ Error: Trained model not found!")
        print("Please train the model first:")
        print("  python scripts/train_model.py")
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ Monitoring failed: {e}")
        logging.error("Monitoring failed", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
