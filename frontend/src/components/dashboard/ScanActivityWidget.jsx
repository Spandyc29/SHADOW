import { TrendingUp, TrendingDown, Minus, BarChart3 } from "lucide-react";

function ActivitySubCard({ label, data }) {
  const count = data?.count ?? 0;
  const trendPct = data?.trend_pct ?? 0;
  const isUp = trendPct > 0;
  const isDown = trendPct < 0;

  const absVal = Math.abs(trendPct).toFixed(1).replace(/\.0$/, "");
  const trendText = isUp ? `↑ ${absVal}%` : isDown ? `↓ ${absVal}%` : `0%`;

  return (
    <div className="flex-1 bg-[#0b0e17] border border-slate-800/80 rounded-xl p-3.5 flex flex-col justify-between shadow-sm">
      <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-400">{label}</span>
      <div className="my-2">
        <span className="text-2xl font-black text-white tracking-tight">{count.toLocaleString()}</span>
      </div>
      <div className={`flex items-center gap-1 text-xs font-bold ${isUp ? "text-emerald-400" : isDown ? "text-red-400" : "text-slate-400"}`}>
        {isUp ? <TrendingUp className="w-3.5 h-3.5" /> : isDown ? <TrendingDown className="w-3.5 h-3.5" /> : <Minus className="w-3.5 h-3.5" />}
        <span>{trendText}</span>
      </div>
    </div>
  );
}

function ScanActivityWidget({ stats }) {
  const scanAct = stats?.scan_activity || {};
  const todayData = scanAct.today || { count: 0, trend_pct: 0 };
  const weekData = scanAct.this_week || { count: 0, trend_pct: 0 };
  const monthData = scanAct.this_month || { count: 0, trend_pct: 0 };
  const detRateData = scanAct.detection_rate || { pct: 0, trend_pct: 0 };

  const detPct = detRateData.pct ?? 0;
  const detTrend = detRateData.trend_pct ?? 0;
  const isDetUp = detTrend > 0;
  const isDetDown = detTrend < 0;
  const absDetTrend = Math.abs(detTrend).toFixed(1).replace(/\.0$/, "");
  const detTrendText = isDetUp ? `↑ ${absDetTrend}%` : isDetDown ? `↓ ${absDetTrend}%` : `0%`;

  return (
    <div className="dashboard-chart-card flex flex-col justify-between">
      <div className="chart-card-header">
        <div className="chart-card-title">
          <div className="chart-icon-box text-purple-400 border-purple-500/30 bg-purple-500/10">
            <BarChart3 className="w-4 h-4" />
          </div>
          <span>SCAN ACTIVITY</span>
        </div>
      </div>

      {/* 3 SUB-CARDS */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 my-4">
        <ActivitySubCard label="Today" data={todayData} />
        <ActivitySubCard label="This Week" data={weekData} />
        <ActivitySubCard label="This Month" data={monthData} />
      </div>

      {/* LOWER SECTION: DETECTION RATE */}
      <div className="pt-3 border-t border-slate-800/80">
        <div className="flex items-center justify-between text-xs mb-2">
          <span className="font-extrabold uppercase tracking-wider text-slate-400">Detection Rate</span>
          <span className="text-[11px] font-semibold text-slate-400">vs last 7 days</span>
        </div>

        <div className="flex items-center justify-between gap-4">
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-black text-white tracking-tight">{detPct}%</span>
          </div>

          {/* PROGRESS BAR */}
          <div className="flex-1 bg-slate-900 border border-slate-800 rounded-full h-2.5 overflow-hidden mx-2">
            <div
              className="bg-gradient-to-r from-purple-500 via-indigo-500 to-purple-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.min(Math.max(detPct, 0), 100)}%` }}
            />
          </div>

          <div className={`flex items-center gap-1 text-xs font-bold ${isDetUp ? "text-red-400" : isDetDown ? "text-emerald-400" : "text-slate-400"}`}>
            {isDetUp ? <TrendingUp className="w-3.5 h-3.5" /> : isDetDown ? <TrendingDown className="w-3.5 h-3.5" /> : <Minus className="w-3.5 h-3.5" />}
            <span>{detTrendText}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ScanActivityWidget;
