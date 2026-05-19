import sys
from pathlib import Path

# Add project root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent

sys.path.append(str(ROOT_DIR))

import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

from database.db import engine


# =====================================================
# LOAD DATA FROM POSTGRESQL
# =====================================================

query = "SELECT * FROM device_logs"

df = pd.read_sql(query, engine)

print("\n✅ Data Loaded")
print(df.head())


# =====================================================
# FEATURE ENGINEERING
# =====================================================

# Convert timestamp
df["scan_time"] = pd.to_datetime(df["scan_time"])

# Extract hour
df["scan_hour"] = df["scan_time"].dt.hour


# =====================================================
# ENCODE CATEGORICAL FEATURES
# =====================================================

vendor_encoder = LabelEncoder()

device_encoder = LabelEncoder()

df["vendor_encoded"] = vendor_encoder.fit_transform(
    df["vendor"]
)

df["device_type_encoded"] = device_encoder.fit_transform(
    df["device_type"]
)


# =====================================================
# SELECT FEATURES
# =====================================================

X = df[[
    "scan_hour",
    "vendor_encoded",
    "device_type_encoded",
    "is_intruder"
]]


# =====================================================
# TRAIN ISOLATION FOREST
# =====================================================

model = IsolationForest(
    contamination=0.05,
    random_state=42
)

model.fit(X)


# =====================================================
# SAVE MODEL + ENCODERS
# =====================================================

joblib.dump(
    model,
    "ai/models/anomaly_model.pkl"
)

joblib.dump(
    vendor_encoder,
    "ai/models/vendor_encoder.pkl"
)

joblib.dump(
    device_encoder,
    "ai/models/device_encoder.pkl"
)

print("\n✅ AI Model Trained Successfully")

print("\n✅ PKL Files Created")