import { useState } from "react";
import "./index.css";
import Dashboard from "./pages/Dashboard";
import ThreatMap from "./pages/ThreatMap";

const NAV = [
  { id: "dashboard", label: "📊 Dashboard" },
  { id: "map",       label: "🌍 Threat Map" },
];

export default function App() {
  const [page, setPage] = useState("dashboard");

  const navStyle = (id) => ({
    padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer",
    fontWeight: 600, fontSize: 13,
    background: page === id ? "#2563eb" : "transparent",
    color: page === id ? "#fff" : "#64748b",
    transition: "all 0.2s",
  });

  return (
    <div>
      <div style={{
        background: "#0d1117", borderBottom: "1px solid #1e2738",
        padding: "10px 24px", display: "flex", alignItems: "center",
        gap: 8, position: "sticky", top: 0, zIndex: 100,
      }}>
        <span style={{ color: "#e2e8f0", fontWeight: 800, fontSize: 16, marginRight: 16 }}>
          🛡️ IDS
        </span>
        {NAV.map(n => (
          <button key={n.id} style={navStyle(n.id)} onClick={() => setPage(n.id)}>
            {n.label}
          </button>
        ))}
      </div>
      {page === "dashboard" && <Dashboard />}
      {page === "map"       && <ThreatMap />}
    </div>
  );
}
