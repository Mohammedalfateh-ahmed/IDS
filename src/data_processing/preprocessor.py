# -*- coding: utf-8 -*-
"""
Data Preprocessor for AI-Powered IDS
Handles encoding, scaling, and transformation of features.
"""

import pandas as pd
import numpy as np
import joblib
import logging
from pathlib import Path
from typing import Tuple, Optional
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from config import Config, CONFIG

logger = logging.getLogger(__name__)


class IDSPreprocessor:
    """Preprocesses data for IDS model"""

    def __init__(self):
        self.config = CONFIG
        self.label_encoders = {}
        self.feature_scaler = None
        self.label_encoder = None
        self.feature_columns = None
        self.categorical_columns = None
        self.numerical_columns = None
        self.is_fitted = False

    def fit(self, X: pd.DataFrame, y: pd.Series = None):
        """
        Fit preprocessor on training data

        Args:
            X: Feature dataframe
            y: Target labels (optional)
        """
        logger.info("Fitting preprocessor...")

        self.feature_columns = list(X.columns)

        # Identify categorical and numerical columns
        self.categorical_columns = [col for col in X.columns if X[col].dtype == 'object']
        self.numerical_columns = [col for col in X.columns if col not in self.categorical_columns]

        logger.info(f"Categorical columns: {len(self.categorical_columns)}")
        logger.info(f"Numerical columns: {len(self.numerical_columns)}")

        # Encode categorical features
        for col in self.categorical_columns:
            le = LabelEncoder()
            # Fit on all unique values including NaN
            unique_values = X[col].unique()
            le.fit(unique_values)
            self.label_encoders[col] = le

        # Fit scaler on numerical features
        if self.numerical_columns:
            self.feature_scaler = StandardScaler()
            # Create a copy with encoded categoricals
            X_encoded = self._encode_features(X)
            self.feature_scaler.fit(X_encoded[self.numerical_columns])

        # Fit label encoder for target
        if y is not None:
            self.label_encoder = LabelEncoder()
            self.label_encoder.fit(y)
            logger.info(f"Classes: {self.label_encoder.classes_}")

        self.is_fitted = True
        logger.info("Preprocessor fitted successfully")

    def transform(self, X: pd.DataFrame, y: pd.Series = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Transform data

        Args:
            X: Feature dataframe
            y: Target labels (optional)

        Returns:
            Tuple of (transformed_X, transformed_y)
        """
        if not self.is_fitted:
            raise ValueError("Preprocessor must be fitted before transform")

        # Encode categorical features
        X_encoded = self._encode_features(X)

        # Scale numerical features
        if self.feature_scaler and self.numerical_columns:
            X_encoded[self.numerical_columns] = self.feature_scaler.transform(X_encoded[self.numerical_columns])

        # Transform labels
        y_encoded = None
        if y is not None and self.label_encoder:
            y_encoded = self.label_encoder.transform(y)

        return X_encoded.values, y_encoded

    def fit_transform(self, X: pd.DataFrame, y: pd.Series = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fit and transform in one step"""
        self.fit(X, y)
        return self.transform(X, y)

    def _encode_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical features"""
        X_encoded = X.copy()

        for col in self.categorical_columns:
            if col in X_encoded.columns:
                try:
                    X_encoded[col] = self.label_encoders[col].transform(X_encoded[col])
                except ValueError as e:
                    # Handle unseen categories
                    logger.warning(f"Unseen categories in {col}, using default encoding")
                    # Encode unknown values as -1
                    def safe_transform(val):
                        try:
                            return self.label_encoders[col].transform([val])[0]
                        except:
                            return -1
                    X_encoded[col] = X_encoded[col].apply(safe_transform)

        return X_encoded

    def inverse_transform_labels(self, y_encoded: np.ndarray) -> np.ndarray:
        """Convert encoded labels back to original"""
        if self.label_encoder:
            return self.label_encoder.inverse_transform(y_encoded)
        return y_encoded

    def get_label_mapping(self) -> dict:
        """Get mapping of label names to encoded values"""
        if self.label_encoder:
            return {label: idx for idx, label in enumerate(self.label_encoder.classes_)}
        return {}

    def save(self, path: str = None):
        """Save preprocessor to disk"""
        path = path or Config.PREPROCESSOR_PATH

        Path(path).parent.mkdir(parents=True, exist_ok=True)

        joblib.dump({
            'label_encoders': self.label_encoders,
            'feature_scaler': self.feature_scaler,
            'label_encoder': self.label_encoder,
            'feature_columns': self.feature_columns,
            'categorical_columns': self.categorical_columns,
            'numerical_columns': self.numerical_columns,
            'is_fitted': self.is_fitted
        }, path)

        logger.info(f"Preprocessor saved to {path}")

    def load(self, path: str = None):
        """Load preprocessor from disk"""
        path = path or Config.PREPROCESSOR_PATH

        if not Path(path).exists():
            raise FileNotFoundError(f"Preprocessor not found at {path}")

        data = joblib.load(path)

        self.label_encoders = data['label_encoders']
        self.feature_scaler = data['feature_scaler']
        self.label_encoder = data['label_encoder']
        self.feature_columns = data['feature_columns']
        self.categorical_columns = data['categorical_columns']
        self.numerical_columns = data['numerical_columns']
        self.is_fitted = data['is_fitted']

        logger.info(f"Preprocessor loaded from {path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test preprocessor
    from src.data_processing.data_loader import DataLoader

    loader = DataLoader()

    try:
        # Load data
        train_df = loader.load_nsl_kdd(train=True)
        X, y = loader.prepare_for_training(train_df)

        # Take a small sample for testing
        X_sample = X.head(1000)
        y_sample = y.head(1000)

        # Create and fit preprocessor
        preprocessor = IDSPreprocessor()
        X_transformed, y_transformed = preprocessor.fit_transform(X_sample, y_sample)

        print(f"\nOriginal shape: {X_sample.shape}")
        print(f"Transformed shape: {X_transformed.shape}")
        print(f"\nLabel mapping: {preprocessor.get_label_mapping()}")

        # Save preprocessor
        preprocessor.save()
        print("\nPreprocessor saved successfully")

    except FileNotFoundError:
        print("NSL-KDD dataset not found. Please download it first.")
