"""
IDS Detector — loads trained models and predicts on a traffic record.
"""

import os
import numpy as np
import joblib

SEVERITY_MAP = {
    "normal": "low",
    "Probe":  "medium",
    "R2L":    "high",
    "DoS":    "high",
    "U2R":    "critical",
}

_detector_instance = None

class IDSDetector:
    def __init__(self, model_dir: str):
        self.iso       = joblib.load(os.path.join(model_dir, "isolation_forest.pkl"))
        self.rf        = joblib.load(os.path.join(model_dir, "random_forest.pkl"))
        self.scaler    = joblib.load(os.path.join(model_dir, "scaler.pkl"))
        self.le_label  = joblib.load(os.path.join(model_dir, "label_encoder.pkl"))
        self.feat_cols = joblib.load(os.path.join(model_dir, "feature_cols.pkl"))

    def _vectorize(self, record: dict) -> np.ndarray:
        from sklearn.preprocessing import LabelEncoder

        le_proto   = LabelEncoder().fit(["tcp","udp","icmp"])
        le_service = LabelEncoder().fit(["http","ftp","smtp","ssh","dns","other"])
        le_flag    = LabelEncoder().fit(["SF","S0","REJ","RSTO","SH","RSTR","S1","S2","S3","OTH"])

        def safe_enc(le, val, default=0):
            try: return int(le.transform([val])[0])
            except: return default

        row = {f: float(record.get(f, 0)) for f in self.feat_cols if f not in ("proto_enc","service_enc","flag_enc")}
        row["proto_enc"]   = safe_enc(le_proto,   record.get("protocol_type","tcp"))
        row["service_enc"] = safe_enc(le_service, record.get("service","http"))
        row["flag_enc"]    = safe_enc(le_flag,     record.get("flag","SF"))

        return np.array([row.get(f, 0) for f in self.feat_cols], dtype=float).reshape(1, -1)

    def predict(self, record: dict) -> dict:
        try:
            X = self._vectorize(record)
            X_scaled = self.scaler.transform(X)

            iso_score = float(self.iso.decision_function(X_scaled)[0])
            iso_pred  = self.iso.predict(X_scaled)[0]   # -1 = anomaly

            rf_pred_enc = self.rf.predict(X_scaled)[0]
            rf_proba    = self.rf.predict_proba(X_scaled)[0]
            attack_type = self.le_label.inverse_transform([rf_pred_enc])[0]
            confidence  = round(float(np.max(rf_proba)) * 100, 1)

            is_anomaly = (iso_pred == -1) or (attack_type != "normal")

            return {
                "is_anomaly":    bool(is_anomaly),
                "attack_type":   attack_type,
                "confidence":    confidence,
                "severity":      SEVERITY_MAP.get(attack_type, "low"),
                "anomaly_score": round(iso_score, 4),
            }
        except Exception as e:
            return {
                "is_anomaly":    False,
                "attack_type":   "normal",
                "confidence":    0.0,
                "severity":      "low",
                "anomaly_score": 0.0,
                "error":         str(e),
            }


def get_detector(model_dir: str = None) -> IDSDetector:
    global _detector_instance
    if _detector_instance is None:
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(__file__), "..", "models")
        _detector_instance = IDSDetector(model_dir)
    return _detector_instance
