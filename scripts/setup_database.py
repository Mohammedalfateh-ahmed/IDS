#!/usr/bin/env python3
"""
Setup IDS Database
Initializes the SQLite database with required tables.
"""

import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.schema import initialize_database

def main():
    """Main setup function"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║          AI-Powered IDS - Database Setup                 ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)

    try:
        print("Creating database schema...")
        schema = initialize_database()

        print("\n✅ Database initialized successfully!")

        # Display table info
        table_info = schema.get_table_info()

        print("\nDatabase Tables Created:")
        print("=" * 60)

        for table_name, info in table_info.items():
            if not table_name.startswith('sqlite_'):
                print(f"\n  📊 {table_name}")
                print(f"     Columns: {info['columns'][:5]}..." if len(info['columns']) > 5 else f"     Columns: {info['columns']}")
                print(f"     Rows: {info['row_count']}")

        print("\n" + "=" * 60)
        print("✓ Database is ready for use!")

    except Exception as e:
        print(f"\n❌ Database setup failed: {e}")
        logging.error("Database setup failed", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
