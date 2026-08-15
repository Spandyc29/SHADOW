import { useMemo } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { Activity } from "lucide-react";

function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#0f1420] border border-slate-700/80 rounded-xl p-3 shadow-xl text-xs">
        <p className="font-bold text-slate-300 mb-2 border-b border-slate-800 pb-1">{label}</p>
        {payload.map((entry, idx) => (
          <div key={idx} className="flex items-center justify-between gap-4 py-0.5">
            <span className="flex items-center gap-1.5 font-medium" style={{ color: entry.color }}>
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
              {entry.name}:
            </span>
            <span className="font-bold text-white">{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
}

function ThreatActivityChart({ stats }) {
  const chartData = useMemo(() => {
    const today = new Date();
    const result = [];

    const threatsSpark = stats?.threats?.sparkline || [0, 0, 0, 0, 0, 0, 0];
    const suspiciousSpark = stats?.suspicious?.sparkline || [0, 0, 0, 0, 0, 0, 0];
    const cleanSpark = stats?.clean?.sparkline || [0, 0, 0, 0, 0, 0, 0];
    const notFoundSpark = stats?.not_found?.sparkline || [0, 0, 0, 0, 0, 0, 0];

    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const dateStr = i === 0 ? "Today" : d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
      const idx = 6 - i;

      result.push({
        date: dateStr,
        Threats: threatsSpark[idx] || 0,
        Suspicious: suspiciousSpark[idx] || 0,
        Clean: cleanSpark[idx] || 0,
        Unknown: notFoundSpark[idx] || 0,
      });
    }
    return result;
  }, [stats]);

  return (
    <div className="dashboard-chart-card">
      <div className="chart-card-header">
        <div className="chart-card-title">
          <div className="chart-icon-box text-purple-400 border-purple-500/30 bg-purple-500/10">
            <Activity className="w-4 h-4" />
          </div>
          <span>
            THREAT ACTIVITY <span className="text-slate-400 font-normal text-xs lowercase ml-1">(last 7 days)</span>
          </span>
        </div>
        <div className="text-xs font-semibold text-slate-400 bg-slate-800/60 px-2.5 py-1 rounded-lg border border-slate-700/50">
          7 Days
        </div>
      </div>

      <div className="chart-container h-[220px] w-full mt-4">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="gradThreats" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradSuspicious" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradClean" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradUnknown" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
            <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: "#1e293b" }} />
            <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip content={<CustomTooltip />} />
            <Area type="monotone" dataKey="Threats" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#gradThreats)" />
            <Area type="monotone" dataKey="Suspicious" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#gradSuspicious)" />
            <Area type="monotone" dataKey="Clean" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#gradClean)" />
            <Area type="monotone" dataKey="Unknown" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#gradUnknown)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* LEGEND BELOW */}
      <div className="flex flex-wrap items-center justify-center gap-3 sm:gap-6 mt-3 pt-3 border-t border-slate-800/80 text-xs font-semibold">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
          <span className="text-slate-300">Threats</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
          <span className="text-slate-300">Suspicious</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
          <span className="text-slate-300">Clean</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
          <span className="text-slate-300">Unknown</span>
        </div>
      </div>
    </div>
  );
}

export default ThreatActivityChart;
