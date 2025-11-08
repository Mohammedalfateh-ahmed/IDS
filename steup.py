#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
from pathlib import Path

class IDSSetup:
    def __init__(self):
        self.root_dir = Path.cwd()
        self.os_type = platform.system().lower()
        
    def print_banner(self):
        print("=" * 60)
        print("   AI-POWERED INTRUSION DETECTION SYSTEM")
        print("   Initial Setup and Configuration")
        print("=" * 60)
        print()
        
    def check_python_version(self):
        print("[1/10] Checking Python version...")
        if sys.version_info < (3, 8):
            print("❌ Error: Python 3.8+ required")
            sys.exit(1)
        print(f"✅ Python {sys.version.split()[0]} detected")
        
    def create_directories(self):
        print("\n[2/10] Creating directory structure...")
        directories = [
            'data/raw', 'data/processed',
            'models', 'databases', 'logs',
            'config', 'scripts', 'tests', 'docs',
            'src/data_processing', 'src/models',
            'src/detection', 'src/intelligence',
            'src/database', 'src/recommendations',
            'src/alerting', 'src/security',
            'src/dashboard/components',
            'src/dashboard/visualizations'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            
        print(f"✅ Created {len(directories)} directories")
        
    def create_init_files(self):
        print("\n[3/10] Creating Python package files...")
        init_locations = [
            'src', 'src/data_processing', 'src/models',
            'src/detection', 'src/intelligence',
            'src/database', 'src/recommendations',
            'src/alerting', 'src/security',
            'src/dashboard', 'src/dashboard/components',
            'src/dashboard/visualizations', 'tests'
        ]
        
        for location in init_locations:
            init_file = Path(location) / '__init__.py'
            init_file.touch(exist_ok=True)
            
        print(f"✅ Created {len(init_locations)} __init__.py files")
        
    def setup_virtual_environment(self):
        print("\n[4/10] Setting up virtual environment...")
        
        if not Path('venv').exists():
            subprocess.run([sys.executable, '-m', 'venv', 'venv'])
            print("✅ Virtual environment created")
        else:
            print("✅ Virtual environment already exists")
            
        print("\n⚠️  Please activate the virtual environment:")
        if self.os_type == 'windows':
            print("   Run: venv\\Scripts\\activate")
        else:
            print("   Run: source venv/bin/activate")
            
    def install_dependencies(self):
        print("\n[5/10] Installing dependencies...")
        print("This may take a few minutes...")
        
        try:
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', 
                '--upgrade', 'pip'
            ], check=True)
            
            if Path('requirements.txt').exists():
                subprocess.run([
                    sys.executable, '-m', 'pip', 'install',
                    '-r', 'requirements.txt'
                ], check=True)
                print("✅ All dependencies installed")
            else:
                print("⚠️  requirements.txt not found")
                print("   Creating basic requirements.txt...")
                self.create_requirements_file()
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Error installing dependencies: {e}")
            
    def create_requirements_file(self):
        requirements = """xgboost==2.0.3
scikit-learn==1.3.2
pandas==2.1.4
numpy==1.24.3
streamlit==1.29.0
matplotlib==3.8.2
plotly==5.18.0
requests==2.31.0
python-dotenv==1.0.0
joblib==1.3.2
tqdm==4.66.1"""
        
        with open('requirements.txt', 'w') as f:
            f.write(requirements)
        print("✅ requirements.txt created")
        
    def download_dataset(self):
        print("\n[6/10] Downloading NSL-KDD dataset...")
        
        try:
            import requests
            
            datasets = {
                'KDDTrain+.txt': 'https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain+.txt',
                'KDDTest+.txt': 'https://github.com/defcom17/NSL_KDD/raw/master/KDDTest+.txt'
            }
            
            for filename, url in datasets.items():
                filepath = Path('data/raw') / filename
                if not filepath.exists():
                    print(f"   Downloading {filename}...")
                    response = requests.get(url)
                    with open(filepath, 'wb') as f:
                        f.write(response.content)
                    print(f"   ✅ {filename} downloaded")
                else:
                    print(f"   ✅ {filename} already exists")
                    
        except Exception as e:
            print(f"⚠️  Could not download dataset: {e}")
            print("   Please download manually from:")
            print("   https://www.unb.ca/cic/datasets/nsl.html")
            
    def create_env_file(self):
        print("\n[7/10] Creating environment configuration...")
        
        env_path = Path('config/.env')
        if not env_path.exists():
            env_content = """# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your_email@gmail.com
SENDER_PASSWORD=your_app_password
RECIPIENT_EMAILS=admin@example.com

# System Configuration
DETECTION_THRESHOLD=0.7
AUTO_BLOCK_THRESHOLD=0.9
MODEL_PATH=models/
DB_PATH=databases/ids_logs.db"""
            
            with open(env_path, 'w') as f:
                f.write(env_content)
            print("✅ .env file created")
            print("   ⚠️  Please update .env with your email credentials")
        else:
            print("✅ .env file already exists")
            
    def create_gitignore(self):
        print("\n[8/10] Creating .gitignore...")
        
        gitignore_content = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/

# Data
data/raw/*.txt
data/raw/*.csv
data/processed/

# Models
models/*.pkl
models/*.joblib

# Databases
databases/*.db
databases/*.sqlite

# Logs
logs/*.log

# Environment
.env
config/.env

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Jupyter
.ipynb_checkpoints/
*.ipynb"""
        
        with open('.gitignore', 'w') as f:
            f.write(gitignore_content)
        print("✅ .gitignore created")
        
    def create_readme(self):
        print("\n[9/10] Creating README.md...")
        
        readme_content = """# AI-Powered Intrusion Detection System

## Overview
An advanced IDS using XGBoost machine learning to detect and respond to network attacks in real-time.

## Features
- Real-time attack detection
- Multi-class attack classification
- IP intelligence and VPN detection
- Automated security responses
- Email alerting system
- Interactive dashboard

## Quick Start

### 1. Activate Virtual Environment
```bash
source venv/bin/activate  # Linux/Mac
# or
venv\\Scripts\\activate  # Windows
```

### 2. Train the Model
```bash
python scripts/train_model.py --data-path data/raw/KDDTrain+.txt
```

### 3. Start Monitoring
```bash
python scripts/start_monitoring.py
```

### 4. Launch Dashboard
```bash
streamlit run src/dashboard/app.py
```

## Configuration
Edit `config/.env` with your settings:
- Email credentials for alerts
- Detection thresholds
- Security response settings

## Project Structure
```
AI-Powered-IDS/
├── src/           # Source code
├── data/          # Datasets
├── models/        # Trained models
├── scripts/       # Utility scripts
└── dashboard/     # Web interface
```

## License
MIT License - See LICENSE file for details
"""
        
        with open('README.md', 'w') as f:
            f.write(readme_content)
        print("✅ README.md created")
        
    def verify_setup(self):
        print("\n[10/10] Verifying setup...")
        
        checks = {
            'Directory Structure': Path('src').exists(),
            'Virtual Environment': Path('venv').exists(),
            'Requirements File': Path('requirements.txt').exists(),
            'Environment Config': Path('config/.env').exists(),
            'Data Directory': Path('data/raw').exists(),
            'Models Directory': Path('models').exists()
        }
        
        all_good = True
        for check, result in checks.items():
            status = "✅" if result else "❌"
            print(f"   {status} {check}")
            if not result:
                all_good = False
                
        if all_good:
            print("\n✅ Setup completed successfully!")
            print("\n📋 Next Steps:")
            print("1. Activate virtual environment")
            print("2. Update config/.env with your settings")
            print("3. Train the model: python scripts/train_model.py")
            print("4. Start monitoring: python scripts/start_monitoring.py")
            print("5. Launch dashboard: streamlit run src/dashboard/app.py")
        else:
            print("\n⚠️  Some components are missing. Please check and retry.")
            
    def run(self):
        self.print_banner()
        self.check_python_version()
        self.create_directories()
        self.create_init_files()
        self.setup_virtual_environment()
        self.install_dependencies()
        self.download_dataset()
        self.create_env_file()
        self.create_gitignore()
        self.create_readme()
        self.verify_setup()

if __name__ == "__main__":
    setup = IDSSetup()
    setup.run()