# AI-Powered Intrusion Detection System (IDS)

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-ML-green.svg)](https://xgboost.readthedocs.io/)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)]()

> **Graduation Project** | AI Engineering Department | Academic Year 2024-2025
> **Author:** Mohammedalfateh Ahmed

An AI-driven Intrusion Detection System that detects, analyzes, and effectively mitigates network and application-layer attacks using XGBoost machine learning.

---

## 🎯 Features

- **🤖 AI-Powered Detection** - XGBoost multi-class classifier
- **⚡ Real-time Monitoring** - Instant attack detection and response
- **🌍 Threat Intelligence** - IP geolocation and VPN detection
- **📧 Email Alerts** - Automated notifications with attack details
- **💡 Smart Recommendations** - Actionable security advice
- **📊 Comprehensive Logging** - SQLite database with full attack history
- **🎨 (Coming Soon) Dashboard** - Streamlit web interface

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository (if not already done)
git clone <your-repo-url>
cd IDS

# Create virtual environment
python -m venv ids_env
source ids_env/bin/activate  # Linux/Mac
# ids_env\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy environment template
cp .env.template .env

# Edit .env and configure (especially email settings)
nano .env
```

### 3. Setup Database

```bash
python scripts/setup_database.py
```

### 4. Download NSL-KDD Dataset

1. Visit: https://www.unb.ca/cic/datasets/nsl.html
2. Download `KDDTrain+.txt` and `KDDTest+.txt`
3. Place in `data/raw/` directory

### 5. Train Model

```bash
python scripts/train_model.py
```

### 6. Start Monitoring

```bash
python scripts/start_monitoring.py
```

---

## 📚 Documentation

- **[Implementation Guide](IMPLEMENTATION_GUIDE.md)** - Complete setup and usage guide
- **[Project Documentation](docs/README.md)** - Detailed technical documentation
- **[API Documentation](docs/API.md)** - API reference

---

## 🏗️ Architecture

```
┌─────────────────┐
│ Network Traffic │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Feature Extract │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ XGBoost Model   │
│ (Multi-class)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Threat Intel    │
│ (IP/VPN)        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Database Log    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Alerts + Recs   │
└─────────────────┘
```

---

## 🎓 Project Objectives

This graduation project demonstrates:

1. ✅ Machine learning for cybersecurity
2. ✅ Real-time data processing and analysis
3. ✅ Threat intelligence integration
4. ✅ Automated incident response
5. ✅ Full-stack software engineering

---

## 📊 Performance

**Target Metrics:**
- Accuracy: ≥ 85%
- F1-Score: ≥ 0.85
- Detection Latency: < 1 second
- False Positive Rate: < 5%

---

## 🔒 Security & Ethics

**⚠️ Important:**
- This tool is for **defensive security only**
- Only use on **authorized systems**
- Follows **ethical hacking guidelines**
- Complies with **academic integrity standards**

---

## 🛠️ Tech Stack

- **Language:** Python 3.8+
- **ML Framework:** XGBoost, scikit-learn
- **Database:** SQLite
- **Visualization:** Matplotlib, Seaborn, Plotly
- **Dashboard:** Streamlit (planned)
- **Datasets:** NSL-KDD, CIC-IDS2017 (planned)

---

## 📁 Project Structure

```
IDS/
├── config/              # Configuration files
├── data/                # Datasets and database
├── src/                 # Source code
│   ├── data_processing/ # Data loading and preprocessing
│   ├── models/          # ML training and prediction
│   ├── detection/       # Real-time detection
│   ├── intelligence/    # Threat intelligence
│   ├── database/        # Database operations
│   ├── alerting/        # Email notifications
│   └── recommendations/ # Security recommendations
├── scripts/             # Automation scripts
├── models/              # Trained ML models
├── logs/                # System logs
└── docs/                # Documentation
```

---

## 🤝 Contributing

This is an academic graduation project. Suggestions and feedback are welcome!

---

## 📄 License

This project is for **educational purposes** as part of a graduation requirement.

---

## 👨‍🎓 Author

**Mohammedalfateh Ahmed**
AI Engineering Student
Graduation Project 2024-2025

---

## 🙏 Acknowledgments

- NSL-KDD Dataset providers
- XGBoost development team
- Open-source security community

---

**For detailed setup and usage instructions, see [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md)**
