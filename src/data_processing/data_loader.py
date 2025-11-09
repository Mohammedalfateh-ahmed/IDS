# -*- coding: utf-8 -*-
"""
Data Loader for AI-Powered IDS
Loads and prepares datasets (NSL-KDD, CIC-IDS, CSIC) for training and testing.
"""

import pandas as pd
import numpy as np
import logging
from pathlib import Path
from typing import Tuple, Optional
from config import Config, CONFIG

logger = logging.getLogger(__name__)


class DataLoader:
    """Loads and prepares IDS datasets"""

    def __init__(self):
        self.config = CONFIG

    def load_nsl_kdd(self, train=True) -> pd.DataFrame:
        """
        Load NSL-KDD dataset

        Args:
            train: If True, load training set; else load test set

        Returns:
            DataFrame with NSL-KDD data
        """
        file_path = Config.NSL_KDD_TRAIN if train else Config.NSL_KDD_TEST

        logger.info(f"Loading NSL-KDD {'training' if train else 'test'} set from {file_path}")

        try:
            # Get column names from config
            column_names = self.config['datasets']['nsl_kdd']['column_names']

            # Load data
            df = pd.read_csv(file_path, header=None, names=column_names)

            logger.info(f"Loaded {len(df)} samples with {len(df.columns)} features")

            # Clean labels (remove difficulty level if present)
            df['label'] = df['label'].str.lower().str.strip()

            # Map attack types to categories
            df['attack_category'] = df['label'].apply(self._map_attack_to_category)

            return df

        except FileNotFoundError:
            logger.error(f"NSL-KDD dataset not found at {file_path}")
            logger.info("Please download NSL-KDD from: https://www.unb.ca/cic/datasets/nsl.html")
            raise

        except Exception as e:
            logger.error(f"Error loading NSL-KDD: {e}")
            raise

    def _map_attack_to_category(self, label: str) -> str:
        """Map specific attack type to general category"""
        label = label.lower().strip()

        if label == 'normal':
            return 'normal'

        # Get attack mapping from config
        attack_mapping = self.config['attack_classes']['mapping']

        # Find category for this attack
        for attack_name, category in attack_mapping.items():
            if attack_name in label:
                return category

        # Default to r2l for unknown attacks
        logger.warning(f"Unknown attack type: {label}, mapping to r2l")
        return 'r2l'

    def load_train_test_split(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Load both training and test sets

        Returns:
            Tuple of (train_df, test_df)
        """
        logger.info("Loading NSL-KDD train/test split")

        train_df = self.load_nsl_kdd(train=True)
        test_df = self.load_nsl_kdd(train=False)

        logger.info(f"Train set: {len(train_df)} samples")
        logger.info(f"Test set: {len(test_df)} samples")

        return train_df, test_df

    def get_feature_columns(self) -> list:
        """Get list of feature columns (excluding label and difficulty)"""
        column_names = self.config['datasets']['nsl_kdd']['column_names']
        # Exclude label and difficulty
        return [col for col in column_names if col not in ['label', 'difficulty']]

    def get_categorical_columns(self) -> list:
        """Get list of categorical columns"""
        all_categorical = self.config['features']['categorical']
        feature_cols = self.get_feature_columns()
        # Only return categorical columns that exist in the dataset
        return [col for col in all_categorical if col in feature_cols]

    def get_numerical_columns(self) -> list:
        """Get list of numerical columns"""
        categorical = self.get_categorical_columns()
        feature_cols = self.get_feature_columns()
        # All non-categorical features are numerical
        return [col for col in feature_cols if col not in categorical]

    def get_class_distribution(self, df: pd.DataFrame) -> dict:
        """Get distribution of attack categories"""
        distribution = df['attack_category'].value_counts().to_dict()
        logger.info(f"Class distribution: {distribution}")
        return distribution

    def prepare_for_training(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Prepare dataframe for training

        Args:
            df: Input dataframe

        Returns:
            Tuple of (X, y) where X is features and y is labels
        """
        # Get feature columns
        feature_cols = self.get_feature_columns()

        # Separate features and labels
        X = df[feature_cols].copy()
        y = df['attack_category'].copy()

        logger.info(f"Prepared {len(X)} samples with {len(feature_cols)} features")

        return X, y

    def create_sample_data(self, n_samples=100) -> pd.DataFrame:
        """
        Create sample data for testing (when real dataset is not available)

        Args:
            n_samples: Number of samples to generate

        Returns:
            Sample DataFrame with NSL-KDD structure
        """
        logger.warning("Creating synthetic sample data - use real NSL-KDD for actual training!")

        column_names = self.config['datasets']['nsl_kdd']['column_names']
        
        # Create random data
        data = {}
        
        # Numerical features
        numerical_cols = self.get_numerical_columns()
        for col in numerical_cols:
            if col in column_names:
                data[col] = np.random.randint(0, 1000, n_samples)
        
        # Categorical features
        data['protocol_type'] = np.random.choice(['tcp', 'udp', 'icmp'], n_samples)
        data['service'] = np.random.choice(['http', 'ftp', 'smtp', 'ssh'], n_samples)
        data['flag'] = np.random.choice(['SF', 'S0', 'REJ'], n_samples)
        
        # Labels
        attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r']
        data['label'] = np.random.choice(attack_types, n_samples)
        data['difficulty'] = np.random.randint(0, 22, n_samples)
        
        df = pd.DataFrame(data)
        df['attack_category'] = df['label']
        
        return df


def download_nsl_kdd():
    """Helper function to guide users on downloading NSL-KDD"""
    print("""
    To download the NSL-KDD dataset:
    
    1. Visit: https://www.unb.ca/cic/datasets/nsl.html
    2. Download: NSL-KDD dataset
    3. Extract the files:
       - KDDTrain+.txt
       - KDDTest+.txt
    4. Place them in: {}/data/raw/
    
    The files should be named:
       - KDDTrain+.txt (training set)
       - KDDTest+.txt (test set)
    """.format(Path(__file__).parent.parent.parent))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    loader = DataLoader()
    
    try:
        train_df, test_df = loader.load_train_test_split()
        print(f"\nSuccessfully loaded NSL-KDD dataset!")
        print(f"Training samples: {len(train_df)}")
        print(f"Test samples: {len(test_df)}")
        
        distribution = loader.get_class_distribution(train_df)
        print(f"\nAttack distribution:")
        for category, count in distribution.items():
            print(f"  {category}: {count}")
            
    except FileNotFoundError:
        download_nsl_kdd()
