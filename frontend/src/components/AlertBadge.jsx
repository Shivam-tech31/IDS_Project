const TYPE_COLORS = {
  normal: { bg: "#0a2d1a", color: "#4ade80", border: "#16a34a" },
  DoS:    { bg: "#2d0a0a", color: "#f87171", border: "#dc2626" },
  Probe:  { bg: "#2d2000", color: "#fbbf24", border: "#ca8a04" },
  R2L:    { bg: "#2d1500", color: "#fb923c", border: "#ea580c" },
  U2R:    { bg: "#1e0d2d", color: "#f0abfc", border: "#a855f7" },
};

const SEV_COLORS = {
  low:      { bg: "#0a2d1a", color: "#4ade80", border: "#16a34a" },
  medium:   { bg: "#2d2000", color: "#fbbf24", border: "#ca8a04" },
  high:     { bg: "#2d0a0a", color: "#f87171", border: "#dc2626" },
  critical: { bg: "#1e0d2d", color: "#f0abfc", border: "#a855f7" },
};

function Badge({ label, colors }) {
  return (
    <span style={{
      background: colors.bg, color: colors.color, border: `1px solid ${colors.border}`,
      borderRadius: 6, padding: "2px 10px", fontSize: 11, fontWeight: 600,
    }}>
      {label}
    </span>
  );
}

export function TypeBadge({ type }) {
  return <Badge label={type || "normal"} colors={TYPE_COLORS[type] || TYPE_COLORS.normal} />;
}

export function SeverityBadge({ severity }) {
  return <Badge label={(severity || "low").toUpperCase()} colors={SEV_COLORS[severity] || SEV_COLORS.low} />;
}
