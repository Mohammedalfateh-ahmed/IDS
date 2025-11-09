# -*- coding: utf-8 -*-
"""
Threat Scoring Module
Calculates comprehensive threat scores for attacks.
"""

import logging
from typing import Dict
from config import CONFIG

logger = logging.getLogger(__name__)


class ThreatScorer:
    """Calculates threat scores"""

    def __init__(self):
        self.config = CONFIG
        self.weights = self.config['intelligence']['threat_scoring']['weights']

        # Attack severity weights
        self.severity_weights = {
            'normal': 0.0,
            'probe': 0.3,
            'dos': 0.8,
            'r2l': 0.7,
            'u2r': 1.0
        }

    def calculate_score(self, attack_type: str, confidence: float,
                       ip_info: Dict, vpn_probability: float = 0.0) -> float:
        """
        Calculate comprehensive threat score

        Args:
            attack_type: Type of attack
            confidence: Model confidence
            ip_info: IP enrichment data
            vpn_probability: VPN probability

        Returns:
            Threat score (0-100)
        """
        # Base severity
        severity = self.severity_weights.get(attack_type.lower(), 0.5)

        # Weighted components
        confidence_score = confidence * self.weights['attack_confidence']
        severity_score = severity * self.weights['attack_severity']
        vpn_score = vpn_probability * self.weights['vpn_probability']

        # Calculate final score
        total_score = (confidence_score + severity_score + vpn_score) * 100

        return min(max(total_score, 0), 100)


if __name__ == "__main__":
    scorer = ThreatScorer()

    result = scorer.calculate_score(
        attack_type='dos',
        confidence=0.95,
        ip_info={},
        vpn_probability=0.7
    )

    print(f"Threat Score: {result:.2f}/100")
