import { Clock } from "lucide-react";

function RecentScansTable({ scans = [] }) {
  const getVerdict = (scan) => {
    if (scan.vt_status === "not_found") return "Unknown";
    if (scan.vt_detections === 0) return "Clean";
    if (scan.vt_detections <= 5) return "Suspicious";
    return "Malicious";
  };

  const getVerdictBadgeStyle = (verdict) => {
    switch (verdict) {
      case "Clean":
        return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
      case "Suspicious":
        return "bg-amber-500/10 text-amber-400 border border-amber-500/30";
      case "Malicious":
        return "bg-red-500/10 text-red-400 border border-red-500/30";
      default:
        return "bg-slate-500/10 text-slate-400 border border-slate-500/30";
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return "—";
    const date = new Date(dateStr);
    const today = new Date();
    const diff = Math.floor((today - date) / (1000 * 60 * 60 * 24));
    if (diff === 0) return "Today";
    if (diff === 1) return "Yesterday";
    return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  return (
    <div className="dashboard-chart-card">
      <div className="chart-card-header mb-4">
        <div className="chart-card-title">
          <div className="chart-icon-box text-purple-400 border-purple-500/30 bg-purple-500/10">
            <Clock className="w-4 h-4" />
          </div>
          <span>RECENT SCANS</span>
        </div>
      </div>

      {scans.length === 0 ? (
        <p className="text-xs text-slate-400 py-6 text-center italic">No recent scans available.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-extrabold uppercase tracking-wider text-slate-400">
                <th className="py-3 px-3">File / Indicator</th>
                <th className="py-3 px-3">Verdict</th>
                <th className="py-3 px-3">Detections</th>
                <th className="py-3 px-3 text-right">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {scans.map((scan) => {
                const verdict = getVerdict(scan);
                const badgeClass = getVerdictBadgeStyle(verdict);
                return (
                  <tr key={scan.id} className="hover:bg-slate-800/40 transition-colors group">
                    <td className="py-3.5 px-3 font-semibold text-slate-200 truncate max-w-[280px]">
                      {scan.file_name || "—"}
                    </td>
                    <td className="py-3.5 px-3">
                      <span className={`inline-block px-2.5 py-0.5 rounded-md font-extrabold uppercase tracking-wider text-[10px] ${badgeClass}`}>
                        {verdict}
                      </span>
                    </td>
                    <td className="py-3.5 px-3 font-bold text-slate-300">
                      {scan.vt_detections ?? "—"} <span className="text-slate-400 font-normal">/ {scan.vt_total_engines ?? "—"}</span>
                    </td>
                    <td className="py-3.5 px-3 text-right font-medium text-slate-400">
                      {formatDate(scan.created_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default RecentScansTable;