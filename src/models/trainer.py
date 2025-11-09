"""
XGBoost Model Trainer for AI-Powered IDS
Trains the machine learning model for intrusion detection.
"""

import xgboost as xgb
import joblib
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
import pandas as pd
import numpy as np

from config import Config, CONFIG
from src.data_processing.data_loader import DataLoader
from src.data_processing.feature_engineering import FeatureEngineer
from src.data_processing.preprocessor import IDSPreprocessor

logger = logging.getLogger(__name__)


class XGBoostIDSTrainer:
    """Trains XGBoost model for intrusion detection"""

    def __init__(self):
        self.config = CONFIG
        self.model = None
        self.preprocessor = None
        self.training_history = {}

    def train(self, X_train, y_train, X_val=None, y_val=None):
        """
        Train XGBoost model

        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
        """
        logger.info("=" * 60)
        logger.info("Starting XGBoost Model Training")
        logger.info("=" * 60)

        start_time = datetime.now()

        # Get model parameters from config
        model_params = self.config['model']['params'].copy()
        training_params = self.config['model']['training']

        logger.info(f"\nTraining samples: {len(X_train)}")
        logger.info(f"Features: {X_train.shape[1]}")
        logger.info(f"Classes: {len(np.unique(y_train))}")

        # Create XGBoost classifier
        self.model = xgb.XGBClassifier(**model_params)

        # Prepare evaluation set if validation data provided
        eval_set = None
        if X_val is not None and y_val is not None:
            eval_set = [(X_train, y_train), (X_val, y_val)]
            logger.info(f"Validation samples: {len(X_val)}")

        # Train model
        logger.info("\nTraining model...")

        self.model.fit(
            X_train, y_train,
            eval_set=eval_set,
            early_stopping_rounds=training_params.get('early_stopping_rounds'),
            verbose=training_params.get('verbose', True)
        )

        training_time = (datetime.now() - start_time).total_seconds()

        logger.info(f"\nTraining completed in {training_time:.2f} seconds")

        # Store training history
        self.training_history = {
            'training_samples': len(X_train),
            'validation_samples': len(X_val) if X_val is not None else 0,
            'features': X_train.shape[1],
            'classes': len(np.unique(y_train)),
            'training_time': training_time,
            'timestamp': datetime.now().isoformat(),
            'model_params': model_params
        }

        return self.model

    def evaluate(self, X_test, y_test) -> Dict:
        """
        Evaluate model performance

        Args:
            X_test: Test features
            y_test: Test labels

        Returns:
            Dictionary with evaluation metrics
        """
        if self.model is None:
            raise ValueError("Model must be trained first")

        logger.info("\n" + "=" * 60)
        logger.info("Evaluating Model Performance")
        logger.info("=" * 60)

        # Make predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)

        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')

        logger.info(f"\nOverall Accuracy: {accuracy:.4f}")
        logger.info(f"Weighted F1-Score: {f1:.4f}")

        # Classification report
        logger.info("\nClassification Report:")
        report = classification_report(y_test, y_pred, 
                                       target_names=self.preprocessor.label_encoder.classes_ if self.preprocessor else None,
                                       output_dict=True)
        print(classification_report(y_test, y_pred))

        # Confusion matrix
        logger.info("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)

        metrics = {
            'accuracy': accuracy,
            'f1_score': f1,
            'classification_report': report,
            'confusion_matrix': cm.tolist()
        }

        return metrics

    def save_model(self, model_path=None, preprocessor_path=None):
        """Save trained model and preprocessor"""
        model_path = model_path or Config.MODEL_PATH
        preprocessor_path = preprocessor_path or Config.PREPROCESSOR_PATH

        # Create directories
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)

        # Save model
        joblib.dump(self.model, model_path)
        logger.info(f"Model saved to {model_path}")

        # Save preprocessor
        if self.preprocessor:
            self.preprocessor.save(preprocessor_path)

        # Save training history
        history_path = Path(model_path).parent / "training_history.json"
        with open(history_path, 'w') as f:
            json.dump(self.training_history, f, indent=2)

        logger.info(f"Training history saved to {history_path}")

    def load_model(self, model_path=None):
        """Load trained model"""
        model_path = model_path or Config.MODEL_PATH

        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model not found at {model_path}")

        self.model = joblib.load(model_path)
        logger.info(f"Model loaded from {model_path}")

        return self.model

    def get_feature_importance(self, top_n=20) -> pd.DataFrame:
        """Get top N most important features"""
        if self.model is None:
            raise ValueError("Model must be trained first")

        importance = self.model.feature_importances_

        if self.preprocessor and self.preprocessor.feature_columns:
            feature_names = self.preprocessor.feature_columns
        else:
            feature_names = [f"feature_{i}" for i in range(len(importance))]

        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importance
        }).sort_values('importance', ascending=False).head(top_n)

        logger.info(f"\nTop {top_n} Most Important Features:")
        print(importance_df.to_string(index=False))

        return importance_df


def train_full_pipeline():
    """Complete training pipeline from data loading to model saving"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Starting Full Training Pipeline")

    try:
        # Load data
        logger.info("\n1. Loading NSL-KDD dataset...")
        loader = DataLoader()
        train_df, test_df = loader.load_train_test_split()

        # Prepare features
        logger.info("\n2. Preparing features...")
        X_train, y_train = loader.prepare_for_training(train_df)
        X_test, y_test = loader.prepare_for_training(test_df)

        # Feature engineering
        logger.info("\n3. Engineering features...")
        engineer = FeatureEngineer()
        X_train = engineer.engineer_features(X_train)
        X_test = engineer.engineer_features(X_test)

        # Preprocess
        logger.info("\n4. Preprocessing data...")
        preprocessor = IDSPreprocessor()
        X_train_processed, y_train_processed = preprocessor.fit_transform(X_train, y_train)
        X_test_processed, y_test_processed = preprocessor.transform(X_test, y_test)

        # Split train into train and validation
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_train_processed, y_train_processed,
            test_size=0.1,
            stratify=y_train_processed,
            random_state=42
        )

        # Train model
        logger.info("\n5. Training XGBoost model...")
        trainer = XGBoostIDSTrainer()
        trainer.preprocessor = preprocessor
        trainer.train(X_tr, y_tr, X_val, y_val)

        # Evaluate
        logger.info("\n6. Evaluating model...")
        metrics = trainer.evaluate(X_test_processed, y_test_processed)

        # Feature importance
        logger.info("\n7. Analyzing feature importance...")
        trainer.get_feature_importance()

        # Save model
        logger.info("\n8. Saving model...")
        trainer.save_model()

        logger.info("\n" + "=" * 60)
        logger.info("Training Pipeline Completed Successfully!")
        logger.info("=" * 60)

        return trainer, metrics

    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    train_full_pipeline()
