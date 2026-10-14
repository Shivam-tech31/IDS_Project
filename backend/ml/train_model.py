"""
Train IDS models on KDD Cup 99 dataset.
Run once before starting the backend:
    python backend/ml/train_model.py
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# KDD Cup 99 column names
COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"
]

ATTACK_MAP = {
    "normal": "normal",
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS", "udpstorm": "DoS",
    "processtable": "DoS", "mailbomb": "DoS",
    # Probe
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    # R2L
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L", "warezclient": "R2L",
    "warezmaster": "R2L", "sendmail": "R2L", "named": "R2L",
    "snmpgetattack": "R2L", "snmpguess": "R2L", "xlock": "R2L",
    "xsnoop": "R2L", "httptunnel": "R2L",
    # U2R
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "ps": "U2R", "sqlattack": "U2R",
    "xterm": "U2R", "worm": "U2R",
}

NUMERIC_FEATURES = [
    "duration","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

def generate_synthetic_data(n=50000):
    """Generate synthetic KDD-like data for training when dataset not available."""
    print("Generating synthetic training data...")
    np.random.seed(42)
    rows = []
    for _ in range(n):
        attack_type = np.random.choice(
            ["normal","DoS","Probe","R2L","U2R"],
            p=[0.60, 0.20, 0.10, 0.07, 0.03]
        )
        row = {f: 0.0 for f in NUMERIC_FEATURES}
        row["protocol_type"] = np.random.choice(["tcp","udp","icmp"])
        row["service"] = np.random.choice(["http","ftp","smtp","ssh","dns","other"])
        row["flag"] = np.random.choice(["SF","S0","REJ","RSTO","SH"])

        if attack_type == "normal":
            row["duration"] = np.random.exponential(2)
            row["src_bytes"] = np.random.randint(0, 5000)
            row["dst_bytes"] = np.random.randint(0, 5000)
            row["logged_in"] = np.random.choice([0, 1], p=[0.3, 0.7])
            row["count"] = np.random.randint(1, 50)
            row["same_srv_rate"] = np.random.uniform(0.8, 1.0)
        elif attack_type == "DoS":
            row["duration"] = 0
            row["src_bytes"] = np.random.randint(0, 100)
            row["dst_bytes"] = 0
            row["count"] = np.random.randint(400, 511)
            row["serror_rate"] = np.random.uniform(0.8, 1.0)
            row["srv_serror_rate"] = np.random.uniform(0.8, 1.0)
            row["same_srv_rate"] = np.random.uniform(0.9, 1.0)
        elif attack_type == "Probe":
            row["duration"] = np.random.exponential(1)
            row["src_bytes"] = np.random.randint(0, 500)
            row["dst_bytes"] = np.random.randint(0, 500)
            row["count"] = np.random.randint(1, 30)
            row["diff_srv_rate"] = np.random.uniform(0.3, 1.0)
            row["dst_host_count"] = np.random.randint(200, 255)
        elif attack_type == "R2L":
            row["duration"] = np.random.exponential(5)
            row["src_bytes"] = np.random.randint(100, 10000)
            row["dst_bytes"] = np.random.randint(100, 10000)
            row["num_failed_logins"] = np.random.randint(1, 5)
            row["logged_in"] = 0
        elif attack_type == "U2R":
            row["duration"] = np.random.exponential(3)
            row["src_bytes"] = np.random.randint(100, 2000)
            row["root_shell"] = 1
            row["num_root"] = np.random.randint(1, 10)
            row["su_attempted"] = np.random.choice([0, 1])

        row["label"] = attack_type
        rows.append(row)

    return pd.DataFrame(rows)

def train():
    # Try to load KDD dataset, else use synthetic
    kdd_path = os.path.join(os.path.dirname(__file__), "kddcup.data_10_percent.gz")
    if os.path.exists(kdd_path):
        print("Loading KDD Cup 99 dataset...")
        df = pd.read_csv(kdd_path, names=COLUMNS, compression="gzip")
        df["label"] = df["label"].str.rstrip(".").map(
            lambda x: ATTACK_MAP.get(x, "normal")
        )
    else:
        df = generate_synthetic_data(50000)

    print(f"Dataset size: {len(df)} rows")
    print(df["label"].value_counts())

    # Encode categorical
    le_proto   = LabelEncoder().fit(["tcp","udp","icmp"])
    le_service = LabelEncoder().fit(["http","ftp","smtp","ssh","dns","other"])
    le_flag    = LabelEncoder().fit(["SF","S0","REJ","RSTO","SH","RSTR","S1","S2","S3","OTH"])

    def safe_encode(le, val, default=0):
        try: return le.transform([val])[0]
        except: return default

    df["proto_enc"]   = df["protocol_type"].apply(lambda x: safe_encode(le_proto,   x))
    df["service_enc"] = df["service"].apply(      lambda x: safe_encode(le_service, x))
    df["flag_enc"]    = df["flag"].apply(          lambda x: safe_encode(le_flag,    x))

    feature_cols = NUMERIC_FEATURES + ["proto_enc","service_enc","flag_enc"]
    X = df[feature_cols].fillna(0).astype(float)
    y = df["label"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Isolation Forest (unsupervised)
    print("Training Isolation Forest...")
    iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_scaled)

    # Random Forest (supervised)
    print("Training Random Forest...")
    le_label = LabelEncoder()
    y_enc = le_label.fit_transform(y)
    X_tr, X_te, y_tr, y_te = train_test_split(X_scaled, y_enc, test_size=0.2, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_tr, y_tr)
    acc = rf.score(X_te, y_te)
    print(f"Random Forest accuracy: {acc:.4f}")

    # Save
    joblib.dump(iso,      os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    joblib.dump(rf,       os.path.join(MODEL_DIR, "random_forest.pkl"))
    joblib.dump(scaler,   os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(le_label, os.path.join(MODEL_DIR, "label_encoder.pkl"))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_cols.pkl"))
    print(f"✅ Models saved to {MODEL_DIR}")

if __name__ == "__main__":
    train()
