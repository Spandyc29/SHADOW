import {
  Scan,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  HelpCircle,
  TrendingUp,
  TrendingDown,
  Minus,
} from "lucide-react";
import "../styles/stat-card.css";

const CONFIGS = {
  total_scans: {
    title: "TOTAL SCANS",
    icon: Scan,
    color: "#a855f7",
    glowBg: "rgba(168, 85, 247, 0.15)",
    borderColor: "rgba(168, 85, 247, 0.3)",
    isBad: false,
  },
  clean: {
    title: "CLEAN",
    icon: ShieldCheck,
    color: "#10b981",
    glowBg: "rgba(16, 185, 129, 0.15)",
    borderColor: "rgba(16, 185, 129, 0.3)",
    isBad: false,
  },
  suspicious: {
    title: "SUSPICIOUS",
    icon: AlertTriangle,
    color: "#f59e0b",
    glowBg: "rgba(245, 158, 11, 0.15)",
    borderColor: "rgba(245, 158, 11, 0.3)",
    isBad: true,
  },
  threats: {
    title: "THREATS",
    icon: ShieldAlert,
    color: "#ef4444",
    glowBg: "rgba(239, 68, 68, 0.15)",
    borderColor: "rgba(239, 68, 68, 0.3)",
    isBad: true,
  },
  not_found: {
    title: "NOT FOUND",
    icon: HelpCircle,
    color: "#3b82f6",
    glowBg: "rgba(59, 130, 246, 0.15)",
    borderColor: "rgba(59, 130, 246, 0.3)",
    isBad: false,
  },
};

function Sparkline({ data = [0, 0, 0, 0, 0, 0, 0], color = "#a855f7", idSuffix = "default" }) {
  const width = 74;
  const height = 28;
  const padding = 3;

  if (!data || data.length === 0) return null;

  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;

  const points = data.map((val, idx) => {
    const x = padding + (idx / (data.length - 1)) * (width - 2 * padding);
    const y = height - padding - ((val - min) / range) * (height - 2 * padding);
    return { x, y };
  });

  const pathD = points.reduce((acc, point, i) => {
    return i === 0 ? `M ${point.x} ${point.y}` : `${acc} L ${point.x} ${point.y}`;
  }, "");

  const fillD = `${pathD} L ${points[points.length - 1].x} ${height} L ${points[0].x} ${height} Z`;
  const gradId = `sparkline-grad-${idSuffix}-${color.replace("#", "")}`;

  return (
    <svg width={width} height={height} className="stat-sparkline-svg" viewBox={`0 0 ${width} ${height}`}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.4" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={fillD} fill={`url(#${gradId})`} />
      <path d={pathD} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function StatCard({ type = "total_scans", title: customTitle, value: customValue, stat }) {
  // Determine normalized config
  const normType = (type || "total_scans").toLowerCase();
  const config = CONFIGS[normType] || CONFIGS.total_scans;

  const title = customTitle || config.title;
  const IconComponent = config.icon;

  // Extract stat data object if passed, or fallback
  let currentCount = 0;
  let previousCount = 0;
  let trendPct = 0;
  let sparklineData = [0, 0, 0, 0, 0, 0, 0];

  if (stat && typeof stat === "object") {
    currentCount = stat.current ?? 0;
    previousCount = stat.previous ?? 0;
    trendPct = stat.trend_pct ?? 0;
    if (Array.isArray(stat.sparkline)) {
      sparklineData = stat.sparkline;
    }
  } else if (customValue !== undefined && customValue !== null) {
    if (typeof customValue === "object") {
      currentCount = customValue.current ?? 0;
      previousCount = customValue.previous ?? 0;
      trendPct = customValue.trend_pct ?? 0;
      if (Array.isArray(customValue.sparkline)) {
        sparklineData = customValue.sparkline;
      }
    } else {
      currentCount = Number(customValue) || 0;
    }
  }

  // Trend formatting & colors
  const isUp = trendPct > 0;
  const isDown = trendPct < 0;
  const isZeroPrevious = previousCount === 0;

  let trendColorClass = "trend-neutral";
  if (isUp) {
    trendColorClass = config.isBad ? "trend-bad" : "trend-good";
  } else if (isDown) {
    trendColorClass = config.isBad ? "trend-good" : "trend-bad";
  }

  let trendLabel = "";
  if (isZeroPrevious) {
    if (currentCount > 0) {
      trendLabel = "New vs last 7 days";
    } else {
      trendLabel = "0% vs last 7 days";
    }
  } else {
    const sign = isUp ? "↑" : isDown ? "↓" : "";
    const absVal = Math.abs(trendPct).toFixed(1).replace(/\.0$/, "");
    trendLabel = `${sign}${absVal}% vs last 7 days`;
  }

  return (
    <div
      className="stat-card"
      style={{
        "--card-accent-color": config.color,
        "--card-glow-bg": config.glowBg,
        "--card-border-color": config.borderColor,
      }}
    >
      {/* HEADER: ICON + TITLE + SPARKLINE */}
      <div className="stat-card-header">
        <div className="stat-card-title-group">
          <div className="stat-icon-wrapper">
            <IconComponent className="stat-icon" />
          </div>
          <span className="stat-card-label">{title}</span>
        </div>

        <div className="stat-sparkline-wrapper">
          <Sparkline data={sparklineData} color={config.color} idSuffix={normType} />
        </div>
      </div>

      {/* BODY: LARGE COUNT */}
      <div className="stat-card-body">
        <span className="stat-card-number">{currentCount.toLocaleString()}</span>
      </div>

      {/* FOOTER: TREND INDICATOR */}
      <div className={`stat-card-footer ${trendColorClass}`}>
        {isUp ? (
          <TrendingUp className="trend-icon" />
        ) : isDown ? (
          <TrendingDown className="trend-icon" />
        ) : (
          <Minus className="trend-icon" />
        )}
        <span className="trend-text">{trendLabel}</span>
      </div>
    </div>
  );
}

export default StatCard;