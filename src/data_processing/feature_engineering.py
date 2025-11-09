"""
Feature Engineering for AI-Powered IDS
Creates and transforms features for ML model.
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, List
from scipy.stats import entropy

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Engineers features for intrusion detection"""

    def __init__(self):
        pass

    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply feature engineering to dataset

        Args:
            df: Input dataframe

        Returns:
            DataFrame with engineered features
        """
        df = df.copy()

        logger.info("Engineering features...")

        # Create rate-based features
        df = self._create_rate_features(df)

        # Create flag-based features
        df = self._create_flag_features(df)

        # Create service-based features
        df = self._create_service_features(df)

        logger.info(f"Feature engineering complete. Total features: {len(df.columns)}")

        return df

    def _create_rate_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create rate-based features"""

        # Connection rate (connections per second)
        if 'duration' in df.columns and 'count' in df.columns:
            df['connection_rate'] = df.apply(
                lambda row: row['count'] / max(row['duration'], 1), 
                axis=1
            )

        # Byte transfer rate
        if 'duration' in df.columns:
            if 'src_bytes' in df.columns:
                df['src_byte_rate'] = df['src_bytes'] / (df['duration'] + 1)
            if 'dst_bytes' in df.columns:
                df['dst_byte_rate'] = df['dst_bytes'] / (df['duration'] + 1)

        # Byte ratio
        if 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
            total_bytes = df['src_bytes'] + df['dst_bytes'] + 1
            df['src_byte_ratio'] = df['src_bytes'] / total_bytes
            df['dst_byte_ratio'] = df['dst_bytes'] / total_bytes

        return df

    def _create_flag_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create binary features from flags"""

        if 'flag' in df.columns:
            # One-hot encode common flags
            flag_dummies = pd.get_dummies(df['flag'], prefix='flag')

            # Ensure we have common flags
            common_flags = ['SF', 'S0', 'REJ', 'RSTR', 'SH']
            for flag in common_flags:
                col_name = f'flag_{flag}'
                if col_name not in flag_dummies.columns:
                    flag_dummies[col_name] = 0

            # Add to dataframe
            df = pd.concat([df, flag_dummies], axis=1)

        return df

    def _create_service_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create service-based features"""

        if 'service' in df.columns:
            # Flag for high-risk services
            high_risk_services = ['ftp', 'telnet', 'smtp', 'ftp_data']
            df['is_high_risk_service'] = df['service'].isin(high_risk_services).astype(int)

            # Flag for web services
            web_services = ['http', 'https', 'http_443']
            df['is_web_service'] = df['service'].isin(web_services).astype(int)

        return df

    def create_http_features(self, http_data: Dict) -> Dict:
        """
        Create HTTP-specific features for web attack detection

        Args:
            http_data: Dictionary with HTTP request data

        Returns:
            Dictionary with engineered HTTP features
        """
        features = {}

        # Path features
        if 'path' in http_data:
            path = http_data['path']
            features['path_length'] = len(path)
            features['path_depth'] = path.count('/')
            features['has_query'] = 1 if '?' in path else 0
            features['special_char_count'] = sum(1 for c in path if not c.isalnum() and c not in '/?&=')

        # Query parameter features
        if 'query' in http_data:
            query = http_data['query']
            features['param_count'] = query.count('&') + 1 if query else 0
            features['query_length'] = len(query) if query else 0

            # Calculate entropy of query string
            if query:
                features['query_entropy'] = self._calculate_entropy(query)

            # Special characters in query
            if query:
                features['percent_encoding_ratio'] = query.count('%') / max(len(query), 1)
                features['special_char_ratio'] = sum(1 for c in query if not c.isalnum()) / max(len(query), 1)

        # Body features
        if 'body' in http_data:
            body = http_data['body']
            features['body_length'] = len(body) if body else 0

        # Method features
        if 'method' in http_data:
            method = http_data['method'].upper()
            features['method_get'] = 1 if method == 'GET' else 0
            features['method_post'] = 1 if method == 'POST' else 0
            features['method_put'] = 1 if method == 'PUT' else 0

        # User agent features
        if 'user_agent' in http_data:
            ua = http_data['user_agent']
            features['has_user_agent'] = 1 if ua else 0
            features['ua_length'] = len(ua) if ua else 0

        return features

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in s:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate probabilities
        length = len(s)
        probabilities = [count / length for count in char_counts.values()]

        # Calculate entropy
        return entropy(probabilities, base=2)

    def extract_traffic_features(self, packet_data: Dict) -> Dict:
        """
        Extract features from network packet data

        Args:
            packet_data: Dictionary with packet information

        Returns:
            Dictionary with extracted features
        """
        features = {
            'duration': packet_data.get('duration', 0),
            'protocol_type': packet_data.get('protocol', 'tcp'),
            'service': packet_data.get('service', 'other'),
            'flag': packet_data.get('flags', 'SF'),
            'src_bytes': packet_data.get('src_bytes', 0),
            'dst_bytes': packet_data.get('dst_bytes', 0),
            'land': 1 if packet_data.get('src_ip') == packet_data.get('dst_ip') else 0,
            'wrong_fragment': packet_data.get('wrong_fragment', 0),
            'urgent': packet_data.get('urgent', 0),
        }

        return features


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test HTTP feature engineering
    engineer = FeatureEngineer()

    sample_http = {
        'method': 'GET',
        'path': '/admin/login.php?user=admin&pass=123',
        'query': 'user=admin&pass=123',
        'user_agent': 'Mozilla/5.0'
    }

    features = engineer.create_http_features(sample_http)
    print("HTTP Features:")
    for key, value in features.items():
        print(f"  {key}: {value}")
