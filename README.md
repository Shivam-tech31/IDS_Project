# 🛡️ Intrusion Detection System (IDS)

Real-time network intrusion detection dashboard using machine learning (Isolation Forest + Random Forest), FastAPI WebSocket backend, React frontend, and MongoDB Atlas.

---

## 📁 Project Structure

```
IDS-Project/
├── backend/
│   ├── main.py               # FastAPI app + WebSocket + REST API
│   ├── notifications.py      # Email + SMS alert system
│   ├── requirements.txt
│   ├── .env.example
│   └── ml/
│       ├── train_model.py    # Train Isolation Forest + Random Forest
│       ├── detector.py       # IDSDetector class
│       ├── simulator.py      # Traffic generator
│       └── geoip.py          # IP geolocation
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx   # Stats, charts, live feed, alerts
│   │   │   └── ThreatMap.jsx   # Leaflet world map + blocklist
│   │   └── components/
│   │       ├── StatCard.jsx
│   │       └── AlertBadge.jsx
│   ├── package.json
│   ├── vite.config.js
│   └── .env.example
└── README.md
```

---

## ⚙️ Prerequisites

- Python 3.10+
- Node.js 18+
- MongoDB Atlas account (free tier works)
- VS Code (recommended)

---

## 🚀 Local Setup — Step by Step

### 1. Clone / Open the project

Open the `IDS-Project` folder in VS Code.

### 2. Backend setup

Open a terminal in VS Code and run:

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in:

```env
MONGO_URL=mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
NOTIFICATIONS_ENABLED=false
ALERT_EMAIL=your_gmail@gmail.com
ALERT_EMAIL_PASSWORD=your_app_password
ALERT_RECEIVER=receiver@gmail.com
FAST2SMS_KEY=your_fast2sms_key
SMS_RECEIVER=91XXXXXXXXXX
FRONTEND_URL=http://localhost:5173
```

> **MongoDB Atlas**: Create a free cluster at https://cloud.mongodb.com → Get connection string → Replace `<username>` and `<password>`.
>
> **Email alerts**: Use a Gmail App Password (not your main password). Enable 2FA on Gmail → Security → App Passwords.
>
> **SMS alerts**: Sign up at https://www.fast2sms.com → API → DLT Approved Sender.
>
> Leave `NOTIFICATIONS_ENABLED=false` to skip alerts during development.

### 4. Train the ML model

```bash
# From backend/ folder (venv active)
python ml/train_model.py
```

This creates a `models/` folder with 5 files:
- `isolation_forest.pkl`
- `random_forest.pkl`
- `scaler.pkl`
- `label_encoder.pkl`
- `feature_cols.pkl`

> If you have the KDD Cup 99 dataset (`kddcup.data.corrected`), place it in the `backend/` folder before training. Otherwise, synthetic data is auto-generated (50,000 samples).

### 5. Start the backend

```bash
# From backend/ folder (venv active)
uvicorn main:app --reload --port 8000
```

Backend runs at: http://localhost:8000

API docs: http://localhost:8000/docs

### 6. Frontend setup

Open a **new terminal** in VS Code:

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at: http://localhost:5173

> The Vite dev proxy automatically routes `/api` → `http://localhost:8000` and `/ws` → `ws://localhost:8000`. No `.env` changes needed locally.

---

## 🖥️ Using the Dashboard

| Feature | Description |
|---|---|
| **Dashboard** | Live stat cards, traffic timeline, attack type pie chart, severity bar chart |
| **Live Feed** | Real-time table of every network event (WebSocket) |
| **Alerts** | All detected intrusions with status (open/resolved) |
| **Threat Map** | World map with attack source markers — click to block IP |
| **Blocklist** | Manage blocked IPs manually or from the map |

---

## 🌐 Deployment

### Backend → Render (free tier)

1. Push `backend/` to a GitHub repo
2. Create a new **Web Service** on https://render.com
3. Set:
   - **Build command**: `pip install -r requirements.txt && python ml/train_model.py`
   - **Start command**: `uvicorn main:app --host 0.0.0.0 --port 10000`
4. Add environment variables (same as `.env`) in Render dashboard
5. Set `FRONTEND_URL` to your Vercel URL (e.g. `https://ids-dashboard.vercel.app`)

> **Important**: Render free tier spins down after inactivity. First request may take ~30s.

### Frontend → Vercel (free tier)

1. Push `frontend/` to a GitHub repo
2. Import project on https://vercel.com
3. Add environment variables:
   ```
   VITE_API_URL=https://your-render-app.onrender.com/api
   VITE_WS_URL=wss://your-render-app.onrender.com/ws
   ```
4. Deploy — Vercel auto-detects Vite

### Database → MongoDB Atlas (free tier)

1. Create cluster at https://cloud.mongodb.com
2. Database → `ids_db`, collections auto-created on first event
3. Allow access from anywhere (IP `0.0.0.0/0`) for Render to connect
4. Use the connection string in `MONGO_URL`

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/stats` | Total traffic, attacks, alert counts |
| GET | `/api/alerts` | Recent intrusion alerts |
| GET | `/api/traffic` | Recent traffic log |
| GET | `/api/geoattacks` | Attacks with lat/lon for map |
| POST | `/api/blocklist/{ip}` | Block an IP address |
| DELETE | `/api/blocklist/{ip}` | Unblock an IP address |
| GET | `/api/blocklist` | List all blocked IPs |
| PATCH | `/api/alerts/resolve/{src_ip}` | Mark alerts resolved |
| DELETE | `/api/alerts/clear` | Clear all alerts |
| POST | `/api/analyze` | Manually analyze a traffic record |
| WS | `/ws` | WebSocket for live events |

---

## 🧠 ML Architecture

- **Isolation Forest** — unsupervised anomaly detection (flags outliers)
- **Random Forest** — supervised multi-class classifier (DoS / Probe / R2L / U2R / normal)
- **Features**: 41 KDD Cup 99 network features (duration, protocol, bytes, flags, counts…)
- **Attack categories**:
  - `normal` → severity: low
  - `Probe` → severity: medium  
  - `R2L` → severity: high
  - `DoS` → severity: high
  - `U2R` → severity: critical

---

## 🔔 Alerts

When `NOTIFICATIONS_ENABLED=true` in `.env`, critical/high events trigger:
- **Email** via Gmail SMTP (port 465 SSL)
- **SMS** via Fast2SMS (Indian numbers, free tier = 38 SMS/day)

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, Uvicorn, WebSocket |
| ML | Scikit-learn (Isolation Forest + Random Forest) |
| Database | MongoDB Atlas + Motor (async) |
| GeoIP | ip-api.com (free, no key needed) |
| Frontend | React + Vite |
| Charts | Recharts |
| Map | Leaflet + react-leaflet |
| Hosting | Vercel + Render + MongoDB Atlas |

---

## 📝 Notes

- Traffic simulation generates events every ~0.8 seconds
- 90% normal traffic, 10% randomized attack traffic
- GeoIP lookups are cached in-memory and skip private IPs
- WebSocket auto-reconnects on disconnect (2s delay)
- All times shown in your local timezone
