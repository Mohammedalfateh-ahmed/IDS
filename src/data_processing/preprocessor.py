"""
Data Preprocessing Module
Loads, cleans, and prepares NSL-KDD dataset for training
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
import os
import json
import logging

# Setup logging
logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataPreprocessor:
    """Handles data loading, cleaning, and preprocessing"""
    
    def __init__(self):
        self.attack_mapping = self._create_attack_mapping()
        self.label_encoder = LabelEncoder()
        
    def _create_attack_mapping(self):
        """Map specific attacks to general categories"""
        return {
            # DoS Attacks
            'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
            'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
            'processtable': 'DoS', 'mailbomb': 'DoS',
            
            # Probe Attacks  
            'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
            'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
            
            # R2L (Remote to Local) Attacks
            'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L',
            'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L',
            'warezmaster': 'R2L', 'sendmail': 'R2L', 'named': 'R2L',
            'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L',
            'xsnoop': 'R2L', 'worm': 'R2L',
            
            # U2R (User to Root) Attacks
            'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R',
            'rootkit': 'U2R', 'httptunnel': 'U2R', 'ps': 'U2R', 
            'sqlattack': 'U2R', 'xterm': 'U2R',
            
            # Normal Traffic
            'normal': 'Normal'
        }
    
    def load_nsl_kdd(self, train_path='data/raw/KDDTrain+.txt', 
                     test_path='data/raw/KDDTest+.txt'):
        """
        Load NSL-KDD dataset
        
        Args:
            train_path: Path to training data
            test_path: Path to test data
            
        Returns:
            df_train, df_test: Pandas DataFrames
        """
        logger.info("Loading NSL-KDD datasets...")
        
        # Define column names
        column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        
        # Load data
        df_train = pd.read_csv(train_path, names=column_names)
        df_test = pd.read_csv(test_path, names=column_names)
        
        logger.info(f"Train samples: {len(df_train)}")
        logger.info(f"Test samples: {len(df_test)}")
        
        return df_train, df_test
    
    def map_attack_categories(self, df):
        """Map specific attacks to general categories"""
        df['attack_category'] = df['label'].map(self.attack_mapping)
        
        # Handle unmapped attacks (if any)
        unmapped = df['attack_category'].isnull().sum()
        if unmapped > 0:
            logger.warning(f"Found {unmapped} unmapped attack types")
            # Set unmapped to their original label
            df.loc[df['attack_category'].isnull(), 'attack_category'] = df['label']
        
        return df
    
    def clean_data(self, df):
        """Clean dataset"""
        logger.info("Cleaning data...")
        
        # Remove duplicates
        before = len(df)
        df = df.drop_duplicates()
        removed = before - len(df)
        if removed > 0:
            logger.info(f"Removed {removed} duplicate rows")
        
        # Check missing values
        missing = df.isnull().sum().sum()
        if missing > 0:
            logger.warning(f"Found {missing} missing values, filling with 0")
            df = df.fillna(0)
        
        # Replace infinity (just in case)
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        # Drop difficulty column (not needed for training)
        if 'difficulty' in df.columns:
            df = df.drop('difficulty', axis=1)
        
        return df
    
    def save_processed_data(self, df_train, df_test, output_dir='data/processed'):
        """Save preprocessed datasets"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save CSVs
        train_path = os.path.join(output_dir, 'train_processed.csv')
        test_path = os.path.join(output_dir, 'test_processed.csv')
        
        df_train.to_csv(train_path, index=False)
        df_test.to_csv(test_path, index=False)
        
        logger.info(f"Saved train data: {train_path}")
        logger.info(f"Saved test data: {test_path}")
        
        # Save metadata
        feature_names = [col for col in df_train.columns 
                        if col not in ['label', 'attack_category']]
        
        categorical_features = df_train.select_dtypes(include=['object']).columns.tolist()
        if 'label' in categorical_features:
            categorical_features.remove('label')
        if 'attack_category' in categorical_features:
            categorical_features.remove('attack_category')
        
        numerical_features = df_train.select_dtypes(include=[np.number]).columns.tolist()
        
        metadata = {
            'feature_names': feature_names,
            'categorical_features': categorical_features,
            'numerical_features': numerical_features,
            'attack_categories': sorted(df_train['attack_category'].unique().tolist()),
            'total_features': len(feature_names),
            'train_samples': len(df_train),
            'test_samples': len(df_test)
        }
        
        metadata_path = os.path.join(output_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Saved metadata: {metadata_path}")
        
        # Print summary
        print("\n" + "=" * 60)
        print("PREPROCESSING SUMMARY")
        print("=" * 60)
        print(f"✓ Train samples: {len(df_train):,}")
        print(f"✓ Test samples: {len(df_test):,}")
        print(f"✓ Features: {len(feature_names)}")
        print(f"✓ Attack categories: {len(metadata['attack_categories'])}")
        print(f"  → {', '.join(metadata['attack_categories'])}")
        print(f"\n✓ Saved to: {output_dir}/")
        print("=" * 60)

def main():
    """Main preprocessing pipeline"""
    print("Starting data preprocessing...")
    
    # Initialize preprocessor
    preprocessor = DataPreprocessor()
    
    # Load data
    df_train, df_test = preprocessor.load_nsl_kdd()
    
    # Map attack categories
    df_train = preprocessor.map_attack_categories(df_train)
    df_test = preprocessor.map_attack_categories(df_test)
    
    # Clean data
    df_train = preprocessor.clean_data(df_train)
    df_test = preprocessor.clean_data(df_test)
    
    # Save processed data
    preprocessor.save_processed_data(df_train, df_test)
    
    print("\n✅ Preprocessing complete!")
    

if __name__ == '__main__':
    main()