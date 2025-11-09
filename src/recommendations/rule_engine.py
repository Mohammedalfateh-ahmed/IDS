"""
Security Recommendations Rule Engine
Generates actionable security recommendations based on detected attacks.
"""

import logging
from typing import Dict, List
from config import CONFIG

logger = logging.getLogger(__name__)


class RecommendationEngine:
    """Generates security recommendations"""

    def __init__(self):
        self.config = CONFIG
        self.port_rules = self.config['recommendations']['port_rules']

    def generate_recommendations(self, attack_data: Dict) -> List[str]:
        """
        Generate security recommendations for an attack

        Args:
            attack_data: Attack information

        Returns:
            List of recommendation strings
        """
        recommendations = []

        attack_type = attack_data.get('attack_type', '').lower()
        source_ip = attack_data.get('source_ip')
        dest_port = attack_data.get('destination_port')
        confidence = attack_data.get('confidence', 0)

        # High-confidence attack recommendations
        if confidence > 0.8:
            recommendations.append(
                f"⚠️  HIGH CONFIDENCE ATTACK: Immediate action recommended"
            )

        # IP-based recommendations
        if source_ip:
            recommendations.append(
                f"Block IP address {source_ip} using firewall rules"
            )

            if attack_data.get('vpn_probability', 0) > 0.5:
                recommendations.append(
                    "Source appears to be using VPN/Proxy - consider geo-blocking"
                )

        # Attack-type specific recommendations
        if attack_type == 'dos':
            recommendations.extend(self._get_dos_recommendations(attack_data))
        elif attack_type == 'probe':
            recommendations.extend(self._get_probe_recommendations(attack_data))
        elif attack_type == 'r2l':
            recommendations.extend(self._get_r2l_recommendations(attack_data))
        elif attack_type == 'u2r':
            recommendations.extend(self._get_u2r_recommendations(attack_data))

        # Port-based recommendations
        if dest_port:
            recommendations.extend(self._get_port_recommendations(dest_port))

        return recommendations

    def _get_dos_recommendations(self, attack_data: Dict) -> List[str]:
        """Recommendations for DoS attacks"""
        return [
            "Enable rate limiting on the targeted service",
            "Implement connection throttling",
            "Consider using a DDoS mitigation service",
            "Monitor bandwidth usage closely"
        ]

    def _get_probe_recommendations(self, attack_data: Dict) -> List[str]:
        """Recommendations for probe/scan attacks"""
        return [
            "Enable port scan detection",
            "Close unnecessary open ports",
            "Implement stricter firewall rules",
            "Monitor for further escalation attempts"
        ]

    def _get_r2l_recommendations(self, attack_data: Dict) -> List[str]:
        """Recommendations for R2L attacks"""
        return [
            "Review authentication logs for failed attempts",
            "Implement multi-factor authentication (MFA)",
            "Enable account lockout policies",
            "Audit user access permissions"
        ]

    def _get_u2r_recommendations(self, attack_data: Dict) -> List[str]:
        """Recommendations for U2R attacks"""
        return [
            "🚨 CRITICAL: Conduct immediate security audit",
            "Check for unauthorized privilege escalation",
            "Review system logs for suspicious activity",
            "Patch all system vulnerabilities immediately",
            "Consider isolating affected systems"
        ]

    def _get_port_recommendations(self, port: int) -> List[str]:
        """Port-specific recommendations"""
        recs = []

        high_risk_ports = self.port_rules.get('close_if_unused', [])
        harden_ports = self.port_rules.get('always_harden', [])

        if port in high_risk_ports:
            recs.append(
                f"⚠️  Port {port} is high-risk - close if not required"
            )

        if port in harden_ports:
            recs.append(
                f"Harden security on port {port} with strict access controls"
            )

        # Port-specific recommendations
        port_specific = {
            21: "Disable FTP, use SFTP instead",
            22: "Use key-based SSH authentication only",
            23: "Disable Telnet, use SSH instead",
            80: "Redirect HTTP to HTTPS",
            443: "Ensure TLS 1.2+ is enforced",
            3389: "Restrict RDP access to specific IPs only",
            3306: "Restrict MySQL to localhost only",
            5432: "Restrict PostgreSQL to localhost only",
        }

        if port in port_specific:
            recs.append(port_specific[port])

        return recs


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = RecommendationEngine()

    test_attack = {
        'attack_type': 'dos',
        'confidence': 0.95,
        'source_ip': '192.168.1.100',
        'destination_port': 80,
        'vpn_probability': 0.7
    }

    recommendations = engine.generate_recommendations(test_attack)

    print("\nSecurity Recommendations:")
    print("=" * 50)
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec}")
