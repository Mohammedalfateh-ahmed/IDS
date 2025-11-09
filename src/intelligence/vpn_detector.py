"""
VPN/Proxy Detection Module
Detects if an IP address is likely using a VPN or proxy.
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


class VPNDetector:
    """Detects VPN/Proxy usage"""

    def __init__(self):
        # Known VPN/Proxy indicators
        self.vpn_keywords = [
            'vpn', 'proxy', 'hosting', 'datacenter', 'cloud',
            'amazon', 'google', 'microsoft', 'digital ocean',
            'linode', 'ovh', 'hetzner'
        ]

        self.vpn_asn_prefixes = ['AS16509', 'AS15169', 'AS8075', 'AS14061']

    def detect(self, ip_address: str, ip_info: Dict) -> Dict:
        """
        Detect if IP is using VPN/Proxy

        Args:
            ip_address: IP address
            ip_info: IP enrichment data

        Returns:
            Dictionary with VPN detection results
        """
        indicators = []
        score = 0.0

        org = (ip_info.get('org', '') or '').lower()
        isp = (ip_info.get('isp', '') or '').lower()
        asn = (ip_info.get('asn', '') or '').lower()

        # Check organization name
        for keyword in self.vpn_keywords:
            if keyword in org or keyword in isp:
                indicators.append(f"VPN keyword in org: {keyword}")
                score += 0.3

        # Check ASN
        for asn_prefix in self.vpn_asn_prefixes:
            if asn_prefix.lower() in asn:
                indicators.append(f"Known cloud provider ASN: {asn}")
                score += 0.4

        # Calculate probability
        probability = min(score, 1.0)
        is_vpn = probability > 0.5

        return {
            'is_vpn': 1 if is_vpn else 0,
            'probability': probability,
            'indicators': indicators,
            'method': 'heuristic'
        }


if __name__ == "__main__":
    from src.intelligence.ip_enrichment import IPEnricher

    enricher = IPEnricher()
    detector = VPNDetector()

    test_ip = '8.8.8.8'
    ip_info = enricher.enrich(test_ip)
    vpn_info = detector.detect(test_ip, ip_info)

    print(f"\nVPN Detection for {test_ip}:")
    print(f"  Is VPN: {vpn_info['is_vpn']}")
    print(f"  Probability: {vpn_info['probability']:.2f}")
    print(f"  Indicators: {vpn_info['indicators']}")
