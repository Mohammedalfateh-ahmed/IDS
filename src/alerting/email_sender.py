"""
Email Alert Sender
Sends email notifications when attacks are detected.
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List
from config import Config

logger = logging.getLogger(__name__)


class EmailSender:
    """Sends email alerts for detected attacks"""

    def __init__(self):
        self.enabled = Config.EMAIL_ENABLED
        self.smtp_server = Config.EMAIL_SMTP_SERVER
        self.smtp_port = Config.EMAIL_SMTP_PORT
        self.sender = Config.EMAIL_SENDER
        self.password = Config.EMAIL_PASSWORD
        self.recipient = Config.EMAIL_RECIPIENT

        if self.enabled and not self.sender:
            logger.warning("Email alerting enabled but credentials not configured")
            self.enabled = False

    def send_attack_alert(self, attack_data: Dict, recommendations: List[str] = None) -> bool:
        """
        Send email alert for detected attack

        Args:
            attack_data: Attack information
            recommendations: List of security recommendations

        Returns:
            True if sent successfully
        """
        if not self.enabled:
            logger.info("Email alerting is disabled")
            return False

        try:
            subject = f"🚨 SECURITY ALERT: {attack_data['attack_type'].upper()} Attack Detected"

            body = self._format_attack_email(attack_data, recommendations)

            return self._send_email(subject, body)

        except Exception as e:
            logger.error(f"Failed to send attack alert: {e}")
            return False

    def _format_attack_email(self, attack_data: Dict, recommendations: List[str]) -> str:
        """Format attack alert email"""

        email_body = f"""
AI-Powered Intrusion Detection System Alert
============================================

An attack has been detected on your system.

ATTACK DETAILS:
--------------
• Type: {attack_data.get('attack_type', 'Unknown').upper()}
• Confidence: {attack_data.get('confidence', 0)*100:.1f}%
• Threat Score: {attack_data.get('threat_score', 0):.1f}/100
• Time: {attack_data.get('timestamp', datetime.now().isoformat())}

SOURCE INFORMATION:
------------------
• IP Address: {attack_data.get('source_ip', 'Unknown')}
• Location: {attack_data.get('city', 'Unknown')}, {attack_data.get('country', 'Unknown')}
• Organization: {attack_data.get('organization', 'Unknown')}
• ASN: {attack_data.get('asn', 'Unknown')}
• VPN Probability: {attack_data.get('vpn_probability', 0)*100:.1f}%

TARGET INFORMATION:
------------------
• Destination IP: {attack_data.get('destination_ip', 'Unknown')}
• Destination Port: {attack_data.get('destination_port', 'Unknown')}
• Protocol: {attack_data.get('protocol', 'Unknown')}
• Service: {attack_data.get('service', 'Unknown')}

TRAFFIC DETAILS:
---------------
• Bytes Sent: {attack_data.get('src_bytes', 0):,}
• Bytes Received: {attack_data.get('dst_bytes', 0):,}
• Duration: {attack_data.get('duration', 0):.2f}s
"""

        if recommendations:
            email_body += "\n\nRECOMMENDATIONS:\n" + "-" * 16 + "\n"
            for i, rec in enumerate(recommendations, 1):
                email_body += f"{i}. {rec}\n"

        email_body += """

NOTE: This is an automated alert from your AI-Powered IDS.
Please investigate this incident immediately.

---
AI-Powered IDS v1.0
"""

        return email_body

    def _send_email(self, subject: str, body: str) -> bool:
        """Send email via SMTP"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender
            msg['To'] = self.recipient
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender, self.password)
                server.send_message(msg)

            logger.info(f"Email alert sent to {self.recipient}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sender = EmailSender()

    # Test alert
    test_attack = {
        'attack_type': 'dos',
        'confidence': 0.95,
        'threat_score': 85.5,
        'timestamp': datetime.now().isoformat(),
        'source_ip': '192.168.1.100',
        'city': 'New York',
        'country': 'USA',
        'organization': 'Test Corp',
        'asn': 'AS12345',
        'vpn_probability': 0.3,
        'destination_ip': '10.0.0.1',
        'destination_port': 80,
        'protocol': 'tcp',
        'service': 'http',
        'src_bytes': 50000,
        'dst_bytes': 1000,
        'duration': 5.2
    }

    recommendations = [
        "Close or restrict access to port 80",
        "Enable rate limiting on the affected service",
        "Block the attacking IP address: 192.168.1.100",
        "Review firewall rules for port 80"
    ]

    if sender.enabled:
        sender.send_attack_alert(test_attack, recommendations)
    else:
        print("\nEmail not configured. Set EMAIL_* variables in .env file")
        print("\nEmail preview:")
        print(sender._format_attack_email(test_attack, recommendations))
