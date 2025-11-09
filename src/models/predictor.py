# -*- coding: utf-8 -*-
"""
Model Predictor for AI-Powered IDS
Makes predictions on new network traffic data.
"""

import joblib
import numpy as np
import pandas as pd
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from config import Config

logger = logging.getLogger(__name__)


class IDSPredictor:
    """Makes predictions using trained IDS model"""

    def __init__(self, model_path=None, preprocessor_path=None):
        self.model_path = model_path or Config.MODEL_PATH
        self.preprocessor_path = preprocessor_path or Config.PREPROCESSOR_PATH
        self.model = None
        self.preprocessor = None
        self.class_names = ['normal', 'dos', 'probe', 'r2l', 'u2r']

    def load(self):
        """Load model and preprocessor"""
        if not Path(self.model_path).exists():
            raise FileNotFoundError(f"Model not found at {self.model_path}")

        logger.info(f"Loading model from {self.model_path}")
        self.model = joblib.load(self.model_path)

        if Path(self.preprocessor_path).exists():
            logger.info(f"Loading preprocessor from {self.preprocessor_path}")
            preprocessor_data = joblib.load(self.preprocessor_path)

            # Reconstruct preprocessor
            from src.data_processing.preprocessor import IDSPreprocessor
            self.preprocessor = IDSPreprocessor()
            self.preprocessor.label_encoders = preprocessor_data['label_encoders']
            self.preprocessor.feature_scaler = preprocessor_data['feature_scaler']
            self.preprocessor.label_encoder = preprocessor_data['label_encoder']
            self.preprocessor.feature_columns = preprocessor_data['feature_columns']
            self.preprocessor.categorical_columns = preprocessor_data['categorical_columns']
            self.preprocessor.numerical_columns = preprocessor_data['numerical_columns']
            self.preprocessor.is_fitted = preprocessor_data['is_fitted']

            if self.preprocessor.label_encoder:
                self.class_names = list(self.preprocessor.label_encoder.classes_)

        logger.info("Model and preprocessor loaded successfully")

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions

        Args:
            X: Feature dataframe

        Returns:
            Tuple of (predicted_classes, probabilities)
        """
        if self.model is None:
            self.load()

        # Preprocess
        if self.preprocessor:
            X_processed, _ = self.preprocessor.transform(X)
        else:
            X_processed = X.values

        # Predict
        predictions = self.model.predict(X_processed)
        probabilities = self.model.predict_proba(X_processed)

        # Convert to class names
        if self.preprocessor and self.preprocessor.label_encoder:
            predictions = self.preprocessor.label_encoder.inverse_transform(predictions)

        return predictions, probabilities

    def predict_single(self, features: Dict) -> Dict:
        """
        Predict single traffic sample

        Args:
            features: Dictionary of feature values

        Returns:
            Dictionary with prediction results
        """
        # Convert to DataFrame
        df = pd.DataFrame([features])

        # Predict
        predictions, probabilities = self.predict(df)

        # Get prediction details
        predicted_class = predictions[0]
        confidence = np.max(probabilities[0])
        class_probabilities = {
            class_name: float(prob)
            for class_name, prob in zip(self.class_names, probabilities[0])
        }

        result = {
            'predicted_class': predicted_class,
            'confidence': float(confidence),
            'is_attack': predicted_class != 'normal',
            'class_probabilities': class_probabilities,
            'all_probabilities': probabilities[0].tolist()
        }

        return result

    def predict_batch(self, features_list: List[Dict]) -> List[Dict]:
        """
        Predict batch of traffic samples

        Args:
            features_list: List of feature dictionaries

        Returns:
            List of prediction result dictionaries
        """
        # Convert to DataFrame
        df = pd.DataFrame(features_list)

        # Predict
        predictions, probabilities = self.predict(df)

        # Format results
        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            result = {
                'predicted_class': pred,
                'confidence': float(np.max(probs)),
                'is_attack': pred != 'normal',
                'class_probabilities': {
                    class_name: float(prob)
                    for class_name, prob in zip(self.class_names, probs)
                }
            }
            results.append(result)

        return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    predictor = IDSPredictor()

    try:
        predictor.load()

        # Test prediction
        sample_features = {
            'duration': 0,
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': 100,
            'dst_bytes': 200,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0
        }

        result = predictor.predict_single(sample_features)

        print("\nPrediction Result:")
        print(f"  Class: {result['predicted_class']}")
        print(f"  Confidence: {result['confidence']:.4f}")
        print(f"  Is Attack: {result['is_attack']}")
        print(f"\nClass Probabilities:")
        for class_name, prob in result['class_probabilities'].items():
            print(f"  {class_name}: {prob:.4f}")

    except FileNotFoundError as e:
        print(f"\nError: {e}")
        print("Please train the model first using: python scripts/train_model.py")
