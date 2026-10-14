import { useEffect, useState, useRef } from "react";
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import StatCard from "../components/StatCard";
import { SeverityBadge, TypeBadge } from "../components/AlertBadge";

const API = import.meta.env.VITE_API_URL || "https://ids-project-m5dw.onrender.com/api";
const WS  = import.meta.env.VITE_WS_URL  || `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`;

const PIE_COLORS = {
  normal: "#4ade80", DoS: "#f87171",
  Probe: "#fbbf24", R2L: "#fb923c",
  U2R: "#f0abfc", Other: "#94a3b8",
};

export default function Dashboard() {
  const [stats, setStats]               = useState(null);
  const [alerts, setAlerts]             = useState([]);
  const [liveEvents, setLiveEvents]     = useState([]);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [connected, setConnected]       = useState(false);
  const [tab, setTab]                   = useState("live");
  const wsRef = useRef(null);

  const fetchStats  = () => fetch(`${API}/stats`).then(r => r.json()).then(setStats).catch(() => {});
  const fetchAlerts = () => fetch(`${API}/alerts?limit=50`).then(r => r.json()).then(d => setAlerts(d.alerts || [])).catch(() => {});

  useEffect(() => {
    fetchStats(); fetchAlerts();
    const iv = setInterval(() => { fetchStats(); fetchAlerts(); }, 5000);
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(WS);
      wsRef.current = ws;
      ws.onopen  = () => setConnected(true);
      ws.onclose = () => { setConnected(false); setTimeout(connect, 2000); };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "traffic") {
          const ev = msg.data;
          setLiveEvents(prev => [ev, ...prev].slice(0, 200));
          setTrafficHistory(prev => {
            const t = new Date(ev.timestamp).toLocaleTimeString();
            const last = prev[prev.length - 1];
            if (last && last.time === t)
              return prev.map((p, i) => i === prev.length - 1
                ? { ...p, total: p.total + 1, attacks: p.attacks + (ev.is_anomaly ? 1 : 0) }
                : p);
            return [...prev, { time: t, total: 1, attacks: ev.is_anomaly ? 1 : 0 }].slice(-30);
          });
        }
      };
    };
    connect();
    return () => wsRef.current?.close();
  }, []);

  const pieData = stats
    ? Object.entries(stats.attack_breakdown || {}).map(([name, value]) => ({ name, value }))
    : [];

  const severityData = stats ? [
    { name: "Low",      value: stats.severity_counts?.low      || 0, fill: "#4ade80" },
    { name: "Medium",   value: stats.severity_counts?.medium   || 0, fill: "#fbbf24" },
    { name: "High",     value: stats.severity_counts?.high     || 0, fill: "#f87171" },
    { name: "Critical", value: stats.severity_counts?.critical || 0, fill: "#f0abfc" },
  ] : [];

  const tabStyle = (active) => ({
    padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer",
    fontWeight: 600, fontSize: 13,
    background: active ? "#2563eb" : "#1a1f2e",
    color: active ? "#fff" : "#94a3b8",
    transition: "all 0.2s",
  });

  return (
    <div style={{ minHeight: "100vh", background: "#0a0e1a", padding: 24 }}>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, color: "#e2e8f0" }}>🛡️ Intrusion Detection System</h1>
          <p style={{ color: "#64748b", marginTop: 4 }}>Real-Time Network Traffic Monitoring</p>
        </div>
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          background: connected ? "#0a2d1a" : "#2d0a0a",
          border: `1px solid ${connected ? "#16a34a" : "#dc2626"}`,
          borderRadius: 20, padding: "6px 16px",
        }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%",
            background: connected ? "#4ade80" : "#f87171",
            boxShadow: connected ? "0 0 6px #4ade80" : "none" }} />
          <span style={{ color: connected ? "#4ade80" : "#f87171", fontSize: 13, fontWeight: 600 }}>
            {connected ? "LIVE" : "CONNECTING..."}
          </span>
        </div>
      </div>

      {/* Stat Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, marginBottom: 24 }}>
        <StatCard label="Total Traffic"    value={stats?.total_traffic}  color="blue"   icon="📡" />
        <StatCard label="Normal Traffic"   value={stats?.normal_traffic} color="green"  icon="✅" />
        <StatCard label="Attacks Detected" value={stats?.total_attacks}  color="red"    icon="🚨" />
        <StatCard label="Open Alerts"      value={stats?.open_alerts}    color="yellow" icon="⚠️" />
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 16, marginBottom: 24 }}>

        <div style={{ background: "#0d1117", border: "1px solid #1e2738", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>
            📈 Traffic Timeline
          </h3>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={trafficHistory}>
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#475569" }} />
              <YAxis tick={{ fontSize: 10, fill: "#475569" }} />
              <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid #2563eb", borderRadius: 8 }} />
              <Line type="monotone" dataKey="total"   stroke="#60a5fa" strokeWidth={2} dot={false} name="Total" />
              <Line type="monotone" dataKey="attacks" stroke="#f87171" strokeWidth={2} dot={false} name="Attacks" />
              <Legend />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: "#0d1117", border: "1px solid #1e2738", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>
            🎯 Attack Types
          </h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={65} label={({ name }) => name}>
                  {pieData.map(entry => <Cell key={entry.name} fill={PIE_COLORS[entry.name] || "#94a3b8"} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid #2563eb", borderRadius: 8 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center", color: "#475569" }}>
              Waiting for data...
            </div>
          )}
        </div>

        <div style={{ background: "#0d1117", border: "1px solid #1e2738", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#94a3b8", fontSize: 13, fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>
            🔥 By Severity
          </h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={severityData} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 10, fill: "#475569" }} />
              <YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: "#94a3b8" }} width={55} />
              <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid #2563eb", borderRadius: 8 }} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {severityData.map(entry => <Cell key={entry.name} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button style={tabStyle(tab === "live")}   onClick={() => setTab("live")}>⚡ Live Feed</button>
        <button style={tabStyle(tab === "alerts")} onClick={() => setTab("alerts")}>🚨 Alerts ({stats?.open_alerts ?? 0})</button>
      </div>

      {/* Live Feed */}
      {tab === "live" && (
        <div style={{ background: "#0d1117", border: "1px solid #1e2738", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ overflowX: "auto", maxHeight: 400, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#131820", borderBottom: "1px solid #1e2738" }}>
                  {["Time","Src IP","Dst IP","Protocol","Service","Type","Severity","Confidence"].map(h => (
                    <th key={h} style={{ padding: "10px 16px", textAlign: "left", color: "#64748b", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5, whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {liveEvents.map((ev, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #1a1f2e", background: ev.is_anomaly ? "#1a0a0a" : "transparent" }}>
                    <td style={{ padding: "8px 16px", color: "#475569", fontSize: 12, whiteSpace: "nowrap" }}>{new Date(ev.timestamp).toLocaleTimeString()}</td>
                    <td style={{ padding: "8px 16px", color: "#e2e8f0", fontFamily: "monospace", fontSize: 12 }}>{ev.src_ip}</td>
                    <td style={{ padding: "8px 16px", color: "#e2e8f0", fontFamily: "monospace", fontSize: 12 }}>{ev.dst_ip}</td>
                    <td style={{ padding: "8px 16px", color: "#94a3b8", fontSize: 12, textTransform: "uppercase" }}>{ev.protocol}</td>
                    <td style={{ padding: "8px 16px", color: "#94a3b8", fontSize: 12 }}>{ev.service}</td>
                    <td style={{ padding: "8px 16px" }}><TypeBadge type={ev.attack_type} /></td>
                    <td style={{ padding: "8px 16px" }}><SeverityBadge severity={ev.severity} /></td>
                    <td style={{ padding: "8px 16px", color: "#94a3b8", fontSize: 12 }}>{ev.confidence}%</td>
                  </tr>
                ))}
                {liveEvents.length === 0 && (
                  <tr><td colSpan={8} style={{ padding: 40, textAlign: "center", color: "#475569" }}>Waiting for traffic...</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Alerts */}
      {tab === "alerts" && (
        <div style={{ background: "#0d1117", border: "1px solid #1e2738", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ overflowX: "auto", maxHeight: 400, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#131820", borderBottom: "1px solid #1e2738" }}>
                  {["Time","Src IP","Dst IP","Attack Type","Severity","Confidence","Status"].map(h => (
                    <th key={h} style={{ padding: "10px 16px", textAlign: "left", color: "#64748b", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5, whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map((al, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #1a1f2e", background: "#150a0a" }}>
                    <td style={{ padding: "8px 16px", color: "#475569", fontSize: 12, whiteSpace: "nowrap" }}>{new Date(al.timestamp).toLocaleString()}</td>
                    <td style={{ padding: "8px 16px", color: "#e2e8f0", fontFamily: "monospace", fontSize: 12 }}>{al.src_ip}</td>
                    <td style={{ padding: "8px 16px", color: "#e2e8f0", fontFamily: "monospace", fontSize: 12 }}>{al.dst_ip}</td>
                    <td style={{ padding: "8px 16px" }}><TypeBadge type={al.attack_type} /></td>
                    <td style={{ padding: "8px 16px" }}><SeverityBadge severity={al.severity} /></td>
                    <td style={{ padding: "8px 16px", color: "#94a3b8", fontSize: 12 }}>{al.confidence}%</td>
                    <td style={{ padding: "8px 16px" }}>
                      <span style={{
                        background: al.status === "open" ? "#2d0a0a" : "#0a2d1a",
                        color: al.status === "open" ? "#f87171" : "#4ade80",
                        border: `1px solid ${al.status === "open" ? "#dc2626" : "#16a34a"}`,
                        borderRadius: 6, padding: "2px 10px", fontSize: 11, fontWeight: 600,
                      }}>{al.status?.toUpperCase()}</span>
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr><td colSpan={7} style={{ padding: 40, textAlign: "center", color: "#475569" }}>No alerts yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
 
