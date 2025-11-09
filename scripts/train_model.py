#!/usr/bin/env python3
"""
Train XGBoost IDS Model
This script trains the intrusion detection model on NSL-KDD dataset.
"""

import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models.trainer import train_full_pipeline

def main():
    """Main training function"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/training.log')
        ]
    )

    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        AI-Powered IDS - Model Training Script            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        trainer, metrics = train_full_pipeline()

        print("\n" + "=" * 60)
        print("✅ MODEL TRAINING COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print(f"\nAccuracy: {metrics['accuracy']:.4f}")
        print(f"F1-Score: {metrics['f1_score']:.4f}")
        print("\nModel saved and ready for deployment!")

    except FileNotFoundError as e:
        print("\n❌ Error: NSL-KDD dataset not found!")
        print("\nTo download the dataset:")
        print("1. Visit: https://www.unb.ca/cic/datasets/nsl.html")
        print("2. Download KDDTrain+.txt and KDDTest+.txt")
        print("3. Place them in: data/raw/")
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        logging.error(f"Training failed", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
