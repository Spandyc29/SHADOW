import { useMemo } from "react";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import { PieChart as PieIcon } from "lucide-react";

const COLOR_MAP = {
  trojan: "#ef4444",
  virus: "#f97316",
  malware: "#f59e0b",
  adware: "#eab308",
  phishing: "#a855f7",
  spyware: "#ec4899",
  other: "#6b7280",
};

const FALLBACK_PALETTE = ["#ef4444", "#f97316", "#f59e0b", "#a855f7", "#3b82f6", "#10b981", "#6b7280"];

function getCategoryColor(name, index) {
  const normName = (name || "").toLowerCase().trim();
  if (COLOR_MAP[normName]) return COLOR_MAP[normName];
  return FALLBACK_PALETTE[index % FALLBACK_PALETTE.length];
}

function CustomTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="bg-[#0f1420] border border-slate-700/80 rounded-xl p-2.5 shadow-xl text-xs font-semibold">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.color }} />
          <span className="capitalize text-slate-200">{data.name}:</span>
          <span className="text-white font-bold">
            {data.value} ({data.payload.pct}%)
          </span>
        </div>
      </div>
    );
  }
  return null;
}

function TopThreatCategoriesChart({ stats }) {
  const topCategories = stats?.top_threat_categories || { total_threats: 0, categories: [] };
  const totalThreats = topCategories.total_threats || 0;
  const categoriesList = topCategories.categories || [];

  const chartData = useMemo(() => {
    if (!categoriesList || categoriesList.length === 0) {
      return [{ name: "No Threats", value: 1, color: "#1e293b", pct: 0 }];
    }
    return categoriesList.map((cat, idx) => ({
      name: cat.name,
      value: cat.count,
      pct: cat.pct,
      color: getCategoryColor(cat.name, idx),
    }));
  }, [categoriesList]);

  return (
    <div className="dashboard-chart-card flex flex-col justify-between">
      <div className="chart-card-header">
        <div className="chart-card-title">
          <div className="chart-icon-box text-purple-400 border-purple-500/30 bg-purple-500/10">
            <PieIcon className="w-4 h-4" />
          </div>
          <span>TOP THREAT CATEGORIES</span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-12 gap-4 items-center my-auto py-2">
        {/* DONUT CHART WITH CENTER OVERLAY */}
        <div className="sm:col-span-6 relative flex items-center justify-center h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={54}
                outerRadius={76}
                paddingAngle={chartData.length > 1 ? 3 : 0}
                dataKey="value"
                stroke="none"
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>

          {/* CENTER OVERLAY */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
            <span className="text-2xl font-black text-white tracking-tight leading-none">{totalThreats}</span>
            <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400 mt-1">Total Threats</span>
          </div>
        </div>

        {/* LEGEND LIST */}
        <div className="sm:col-span-6 flex flex-col gap-2 justify-center pr-2">
          {categoriesList.length === 0 ? (
            <div className="text-xs text-slate-400 italic">No threats recorded</div>
          ) : (
            categoriesList.map((cat, idx) => {
              const color = getCategoryColor(cat.name, idx);
              return (
                <div key={idx} className="flex items-center justify-between text-xs py-1 border-b border-slate-800/50 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
                    <span className="capitalize font-semibold text-slate-300">{cat.name}</span>
                  </div>
                  <div className="flex items-center gap-2 font-bold">
                    <span className="text-white">{cat.count}</span>
                    <span className="text-slate-400 text-[11px] font-normal">({cat.pct}%)</span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

export default TopThreatCategoriesChart;
