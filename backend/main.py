"""
IDS — FastAPI Backend
Real-time intrusion detection with WebSocket, GeoIP, Block IP, Email/SMS alerts.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import asyncio, datetime, os, sys

load_dotenv()
sys.path.insert(0, os.path.dirname(__file__))

from ml.simulator    import generate_traffic_record
from ml.detector     import get_detector
from ml.geoip        import geoip_lookup
from notifications   import send_critical_alert

app = FastAPI(title="IDS — Intrusion Detection System", version="2.0.0")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── MongoDB ───────────────────────────────────────────────────────────────────
MONGO_URL    = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client       = AsyncIOMotorClient(MONGO_URL)
db           = client["ids_db"]
alerts_col   = db["alerts"]
traffic_col  = db["traffic_logs"]
blocklist_col = db["blocklist"]

# ── WebSocket manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

# ── In-memory blocklist for fast lookup ──────────────────────────────────────
blocked_ips: set[str] = set()

async def load_blocklist():
    async for doc in blocklist_col.find({}, {"ip": 1}):
        blocked_ips.add(doc["ip"])

# ── Background traffic loop ───────────────────────────────────────────────────
async def traffic_loop():
    model_dir = os.path.join(os.path.dirname(__file__), "models")
    detector  = get_detector(model_dir=model_dir)
    while True:
        record    = generate_traffic_record()
        result    = detector.predict(record)
        src_ip    = record.get("src_ip", "0.0.0.0")
        dst_ip    = record.get("dst_ip", "0.0.0.0")
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

        if src_ip in blocked_ips:
            result["is_anomaly"]  = True
            result["attack_type"] = result.get("attack_type", "Blocked")
            result["severity"]    = "high"

        geo = None
        if result["is_anomaly"]:
            geo = await geoip_lookup(src_ip)

        event = {
            "timestamp":  timestamp,
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "protocol":   record.get("protocol_type", "tcp"),
            "service":    record.get("service", "http"),
            "src_bytes":  record.get("src_bytes", 0),
            "dst_bytes":  record.get("dst_bytes", 0),
            "is_blocked": src_ip in blocked_ips,
            "geo":        geo,
            **result,
        }

        await traffic_col.insert_one(dict(event))
        if result["is_anomaly"]:
            await alerts_col.insert_one({**event, "status": "open"})
            if result["severity"] == "critical":
                asyncio.create_task(send_critical_alert(event))

        await manager.broadcast({"type": "traffic", "data": event})
        await asyncio.sleep(0.8)

@app.on_event("startup")
async def startup():
    await load_blocklist()
    asyncio.create_task(traffic_loop())

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"message": "IDS API v2 running", "docs": "/docs"}

@app.get("/api/stats")
async def get_stats():
    total       = await traffic_col.count_documents({})
    attacks     = await alerts_col.count_documents({})
    open_alerts = await alerts_col.count_documents({"status": "open"})

    pipeline  = [{"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}]
    breakdown = {d["_id"]: d["count"] async for d in alerts_col.aggregate(pipeline)}

    sev_pipe  = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    sev_counts = {d["_id"]: d["count"] async for d in alerts_col.aggregate(sev_pipe)}

    return {
        "total_traffic":    total,
        "total_attacks":    attacks,
        "open_alerts":      open_alerts,
        "normal_traffic":   total - attacks,
        "blocked_ips":      len(blocked_ips),
        "attack_breakdown": breakdown,
        "severity_counts":  sev_counts,
    }

@app.get("/api/alerts")
async def get_alerts(limit: int = 50, status: str = None):
    query  = {"status": status} if status else {}
    cursor = alerts_col.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
    items  = [doc async for doc in cursor]
    return {"alerts": items, "count": len(items)}

@app.get("/api/traffic")
async def get_traffic(limit: int = 100):
    cursor = traffic_col.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    logs   = [doc async for doc in cursor]
    return {"traffic": logs, "count": len(logs)}

@app.get("/api/geoattacks")
async def get_geo_attacks(limit: int = 100):
    cursor = alerts_col.find(
        {"geo": {"$ne": None}},
        {"_id": 0, "src_ip": 1, "attack_type": 1, "severity": 1, "timestamp": 1, "geo": 1}
    ).sort("timestamp", -1).limit(limit)
    attacks = [doc async for doc in cursor]
    return {"attacks": attacks}

@app.post("/api/blocklist/{ip}")
async def block_ip(ip: str, reason: str = "manual"):
    if ip in blocked_ips:
        return {"message": f"{ip} already blocked"}
    blocked_ips.add(ip)
    await blocklist_col.insert_one({
        "ip": ip, "reason": reason,
        "blocked_at": datetime.datetime.utcnow().isoformat() + "Z"
    })
    await manager.broadcast({"type": "ip_blocked", "data": {"ip": ip}})
    return {"message": f"{ip} blocked successfully"}

@app.delete("/api/blocklist/{ip}")
async def unblock_ip(ip: str):
    blocked_ips.discard(ip)
    await blocklist_col.delete_one({"ip": ip})
    return {"message": f"{ip} unblocked"}

@app.get("/api/blocklist")
async def get_blocklist():
    cursor = blocklist_col.find({}, {"_id": 0})
    items  = [doc async for doc in cursor]
    return {"blocked": items, "count": len(items)}

@app.patch("/api/alerts/resolve/{src_ip}")
async def resolve_alert(src_ip: str):
    result = await alerts_col.update_many(
        {"src_ip": src_ip, "status": "open"},
        {"$set": {"status": "resolved"}}
    )
    return {"updated": result.modified_count}

@app.delete("/api/alerts/clear")
async def clear_alerts():
    result = await alerts_col.delete_many({})
    return {"deleted": result.deleted_count}

@app.post("/api/analyze")
async def analyze_record(record: dict):
    model_dir = os.path.join(os.path.dirname(__file__), "models")
    detector  = get_detector(model_dir=model_dir)
    return detector.predict(record)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
