import { useEffect, useState, useRef } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";

const API = import.meta.env.VITE_API_URL || "/api";

const SEVERITY_COLOR = {
  low:      "#4ade80",
  medium:   "#fbbf24",
  high:     "#f87171",
  critical: "#f0abfc",
};

const SEVERITY_RADIUS = {
  low: 5, medium: 8, high: 11, critical: 15,
};

function RecenterMap({ attacks }) {
  const map = useMap();
  useEffect(() => {
    if (attacks.length > 0) map.invalidateSize();
  }, [attacks.length]);
  return null;
}

export default function ThreatMap() {
  const [attacks, setAttacks]     = useState([]);
  const [blocklist, setBlocklist] = useState([]);
  const [blockIp, setBlockIp]     = useState("");
  const [loading, setLoading]     = useState(false);
  const [msg, setMsg]             = useState(null);

  const fetchAttacks   = () => fetch(`${API}/geoattacks`).then(r => r.json()).then(d => setAttacks(d.attacks || [])).catch(() => {});
  const fetchBlocklist = () => fetch(`${API}/blocklist`).then(r => r.json()).then(d => setBlocklist(d.blocked_ips || [])).catch(() => {});

  useEffect(() => {
    fetchAttacks(); fetchBlocklist();
    const iv = setInterval(() => { fetchAttacks(); fetchBlocklist(); }, 5000);
    return () => clearInterval(iv);
  }, []);

  const showMsg = (text, ok = true) => {
    setMsg({ text, ok });
    setTimeout(() => setMsg(null), 3000);
  };

  const blockIP = async (ip) => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/blocklist/${ip}`, { method: "POST" });
      const d = await r.json();
      showMsg(d.message || `Blocked ${ip}`);
      fetchBlocklist();
    } catch { showMsg("Failed to block IP", false); }
    setLoading(false);
  };

  const unblockIP = async (ip) => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/blocklist/${ip}`, { method: "DELETE" });
      const d = await r.json();
      showMsg(d.message || `Unblocked ${ip}`);
      fetchBlocklist();
    } catch { showMsg("Failed to unblock IP", false); }
    setLoading(false);
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0a0e1a", padding: 24 }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, color: "#e2e8f0" }}>🌍 Global Threat Map</h1>
        <p style={{ color: "#64748b", marginTop: 4 }}>Geographic distribution of attack sources</p>
      </div>

      {/* Toast */}
      {msg && (
        <div style={{
          position: "fixed", top: 80, right: 24, zIndex: 9999,
          background: msg.ok ? "#0a2d1a" : "#2d0a0a",
          border: `1px solid ${msg.ok ? "#16a34a" : "#dc2626"}`,
          color: msg.ok ? "#4ade80" : "#f87171",
          borderRadius: 10, padding: "12px 20px", fontWeight: 600, fontSize: 13,
          boxShadow: "0 4px 20px rgba(0,0,0,0.5)",
        }}>
          {msg.text}
        </div>
      )}

      {/* Legend */}
      <div style={{ display: "flex", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
        {Object.entries(SEVERITY_COLOR).map(([sev, color]) => (
          <div key={sev} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{
              width: SEVERITY_RADIUS[sev] * 2, height: SEVERITY_RADIUS[sev] * 2,
              borderRadius: "50%", background: color, opacity: 0.8,
            }} />
            <span style={{ color: "#94a3b8", fontSize: 12, textTransform: "capitalize" }}>{sev}</span>
          </div>
        ))}
        <span style={{ color: "#475569", fontSize: 12, marginLeft: 8 }}>— {attacks.length} attack sources plotted</span>
      </div>

      {/* Map */}
      <div style={{ borderRadius: 12, overflow: "hidden", border: "1px solid #1e2738", marginBottom: 24, height: 480 }}>
        <MapContainer
          center={[20, 0]}
          zoom={2}
          style={{ height: "100%", width: "100%", background: "#0d1117" }}
          zoomControl={true}
          scrollWheelZoom={true}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='© <a href="https://carto.com/">CARTO</a>'
            maxZoom={19}
          />
          <RecenterMap attacks={attacks} />
          {attacks.map((atk, i) => {
            if (!atk.lat || !atk.lon) return null;
            const color  = SEVERITY_COLOR[atk.severity]  || "#94a3b8";
            const radius = SEVERITY_RADIUS[atk.severity] || 5;
            const isBlocked = blocklist.includes(atk.src_ip);
            return (
              <CircleMarker
                key={i}
                center={[atk.lat, atk.lon]}
                radius={radius}
                pathOptions={{
                  color, fillColor: color, fillOpacity: 0.7, weight: 1.5,
                }}
              >
                <Popup>
                  <div style={{ minWidth: 200 }}>
                    <div style={{ fontWeight: 700, marginBottom: 6, fontSize: 14 }}>
                      🚨 {atk.attack_type}
                    </div>
                    <table style={{ fontSize: 12, borderCollapse: "collapse", width: "100%" }}>
                      {[
                        ["Src IP",    atk.src_ip],
                        ["Severity",  atk.severity?.toUpperCase()],
                        ["Confidence",`${atk.confidence}%`],
                        ["Country",   atk.country],
                        ["City",      atk.city || "—"],
                        ["ISP",       atk.isp || "—"],
                      ].map(([k, v]) => (
                        <tr key={k}>
                          <td style={{ color: "#64748b", paddingRight: 8, paddingBottom: 3 }}>{k}:</td>
                          <td style={{ fontWeight: 600 }}>{v}</td>
                        </tr>
                      ))}
                    </table>
                    <div style={{ marginTop: 10 }}>
                      {isBlocked ? (
                        <button onClick={() => unblockIP(atk.src_ip)} style={{
                          background: "#16a34a", color: "#fff", border: "none",
                          borderRadius: 6, padding: "5px 14px", cursor: "pointer",
                          fontWeight: 600, fontSize: 12, width: "100%",
                        }}>✅ Unblock {atk.src_ip}</button>
                      ) : (
                        <button onClick={() => blockIP(atk.src_ip)} style={{
                          background: "#dc2626", color: "#fff", border: "none",
                          borderRadius: 6, padding: "5px 14px", cursor: "pointer",
                          fontWeight: 600, fontSize: 12, width: "100%",
                        }}>🚫 Block {atk.src_ip}</button>
                      )}
                    </div>
                  </div>
                </Popup>
              </CircleMarker>
            );
          })}
        </MapContainer>
      </div>

      {/* Blocklist */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>

        {/* Manual block */}
        <div style={{ background: "#0d1117", border: "1px solid #1e2738", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>
            🚫 Block IP Manually
          </h3>
          <div style={{ display: "flex", gap: 10 }}>
            <input
              value={blockIp}
              onChange={e => setBlockIp(e.target.value)}
              onKeyDown={e => e.key === "Enter" && blockIp.trim() && blockIP(blockIp.trim())}
              placeholder="e.g. 203.0.113.42"
              style={{
                flex: 1, background: "#131820", border: "1px solid #1e2738",
                borderRadius: 8, padding: "8px 14px", color: "#e2e8f0",
                fontSize: 13, fontFamily: "monospace", outline: "none",
              }}
            />
            <button
              onClick={() => blockIp.trim() && blockIP(blockIp.trim())}
              disabled={loading}
              style={{
                background: "#dc2626", color: "#fff", border: "none",
                borderRadius: 8, padding: "8px 20px", cursor: "pointer",
                fontWeight: 600, fontSize: 13,
              }}
            >
              Block
            </button>
          </div>
        </div>

        {/* Blocked IPs list */}
        <div style={{ background: "#0d1117", border: "1px solid #1e2738", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>
            🔒 Blocked IPs ({blocklist.length})
          </h3>
          <div style={{ maxHeight: 200, overflowY: "auto" }}>
            {blocklist.length === 0 ? (
              <p style={{ color: "#475569", fontSize: 13 }}>No IPs blocked yet.</p>
            ) : (
              blocklist.map((ip, i) => (
                <div key={i} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "6px 0", borderBottom: "1px solid #1a1f2e",
                }}>
                  <span style={{ color: "#e2e8f0", fontFamily: "monospace", fontSize: 13 }}>{ip}</span>
                  <button
                    onClick={() => unblockIP(ip)}
                    style={{
                      background: "transparent", color: "#f87171",
                      border: "1px solid #dc2626", borderRadius: 6,
                      padding: "3px 12px", cursor: "pointer", fontSize: 11, fontWeight: 600,
                    }}
                  >
                    Unblock
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
