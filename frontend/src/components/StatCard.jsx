const COLORS = {
  blue:   { bg: "#0d1b3e", border: "#1d4ed8", text: "#60a5fa" },
  green:  { bg: "#0a2d1a", border: "#16a34a", text: "#4ade80" },
  red:    { bg: "#2d0a0a", border: "#dc2626", text: "#f87171" },
  yellow: { bg: "#2d2000", border: "#ca8a04", text: "#fbbf24" },
};

export default function StatCard({ label, value, color = "blue", icon }) {
  const c = COLORS[color] || COLORS.blue;
  return (
    <div style={{
      background: c.bg, border: `1px solid ${c.border}`,
      borderRadius: 12, padding: "16px 20px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <span style={{ color: "#64748b", fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>
          {label}
        </span>
        <span style={{ fontSize: 18 }}>{icon}</span>
      </div>
      <div style={{ fontSize: 28, fontWeight: 800, color: c.text }}>
        {value ?? "—"}
      </div>
    </div>
  );
}
