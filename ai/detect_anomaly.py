import sys
from pathlib import Path

# Add project root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent

sys.path.append(str(ROOT_DIR))

import joblib
import pandas as pd


# =====================================================
# LOAD MODEL + ENCODERS
# =====================================================

model = joblib.load(
    "ai/models/anomaly_model.pkl"
)

vendor_encoder = joblib.load(
    "ai/models/vendor_encoder.pkl"
)

device_encoder = joblib.load(
    "ai/models/device_encoder.pkl"
)


# =====================================================
# AI ANOMALY DETECTION FUNCTION
# =====================================================

def detect_anomaly(
    scan_hour,
    vendor,
    device_type,
    is_intruder
):

    # -----------------------------
    # Encode Vendor
    # -----------------------------
    try:

        vendor_encoded = vendor_encoder.transform(
            [vendor]
        )[0]

    except:

        vendor_encoded = -1

    # -----------------------------
    # Encode Device Type
    # -----------------------------
    try:

        device_encoded = device_encoder.transform(
            [device_type]
        )[0]

    except:

        device_encoded = -1

    # -----------------------------
    # Create Input DataFrame
    # -----------------------------
    data = pd.DataFrame([{

        "scan_hour": scan_hour,

        "vendor_encoded": vendor_encoded,

        "device_type_encoded": device_encoded,

        "is_intruder": int(is_intruder)

    }])

    # -----------------------------
    # Predict Anomaly
    # -----------------------------
    prediction = model.predict(data)[0]

    # -----------------------------
    # Anomaly Score
    # -----------------------------
    score = model.decision_function(data)[0]

    # -----------------------------
    # Return Results
    # -----------------------------
    return {

        "anomaly": bool(prediction == -1),

        "score": float(score)

    }


# =====================================================
# TEST AI MODEL
# =====================================================

if __name__ == "__main__":

    result = detect_anomaly(

        scan_hour=3,

        vendor="Unknown Vendor",

        device_type="Unknown Network Device",

        is_intruder=True

    )

    print("\n🧠 AI Detection Result:\n")

    print(result)