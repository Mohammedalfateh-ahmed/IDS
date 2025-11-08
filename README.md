# IDS
AI-driven Intrusion Detection System (IDS) that detects, analyzes, and effectively mitigates network and application-layer attacks
req
# Create virtual environment
python -m venv ids_env
source ids_env/bin/activate  # Linux/Mac
# ids_env\Scripts\activate   # Windows

# Install core dependencies
pip install xgboost scikit-learn pandas numpy
pip install streamlit plotly matplotlib seaborn
pip install requests geoip2 ipwhois
pip install python-dotenv joblib
