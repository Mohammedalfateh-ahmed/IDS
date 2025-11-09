# -*- coding: utf-8 -*-
"""
IP Enrichment Module
Enriches IP addresses with geolocation and organization data.
"""

import requests
import logging
import time
from typing import Dict, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


class IPEnricher:
    """Enriches IP addresses with threat intelligence"""

    def __init__(self):
        self.api_endpoint = "http://ip-api.com/json/"
        self.cache = {}
        self.rate_limit_delay = 0.2  # 5 requests per second for free tier

    @lru_cache(maxsize=1000)
    def enrich(self, ip_address: str) -> Dict:
        """
        Enrich IP with geolocation and organization data

        Args:
            ip_address: IP address to enrich

        Returns:
            Dictionary with IP intelligence
        """
        if ip_address in ['127.0.0.1', 'localhost', '0.0.0.0']:
            return self._get_localhost_info()

        try:
            # Rate limiting
            time.sleep(self.rate_limit_delay)

            # Query IP-API
            url = f"{self.api_endpoint}{ip_address}"
            params = {
                'fields': 'status,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query'
            }

            response = requests.get(url, params=params, timeout=5)

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    return {
                        'ip': data.get('query'),
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'asn': data.get('as'),
                    }

            logger.warning(f"Failed to enrich IP {ip_address}")
            return self._get_unknown_info(ip_address)

        except Exception as e:
            logger.error(f"Error enriching IP {ip_address}: {e}")
            return self._get_unknown_info(ip_address)

    def _get_localhost_info(self) -> Dict:
        """Return info for localhost"""
        return {
            'ip': '127.0.0.1',
            'country': 'Local',
            'city': 'Localhost',
            'latitude': 0.0,
            'longitude': 0.0,
            'isp': 'Local',
            'org': 'Local',
            'asn': 'AS0'
        }

    def _get_unknown_info(self, ip: str) -> Dict:
        """Return default info for unknown IPs"""
        return {
            'ip': ip,
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': None,
            'longitude': None,
            'isp': 'Unknown',
            'org': 'Unknown',
            'asn': 'Unknown'
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    enricher = IPEnricher()

    # Test IPs
    test_ips = ['8.8.8.8', '1.1.1.1', '127.0.0.1']

    for ip in test_ips:
        print(f"\nEnriching {ip}...")
        info = enricher.enrich(ip)
        print(f"  Country: {info.get('country')}")
        print(f"  City: {info.get('city')}")
        print(f"  Organization: {info.get('org')}")
        print(f"  ASN: {info.get('asn')}")
