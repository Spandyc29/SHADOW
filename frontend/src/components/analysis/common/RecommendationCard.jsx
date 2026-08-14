import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2 } from "lucide-react";
import { present } from "./display";

function RecommendationCard({ result }) {
  const recommendation = result?.recommendation || {};
  const action = recommendation.action || result?.recommended_action || (result?.verdict === "MALICIOUS" ? "Isolate Host & Block Indicator" : result?.verdict === "SUSPICIOUS" ? "Investigate & Monitor" : "No Action Required");
  const reason = recommendation.reason || result?.recommendation_reason || (result?.verdict === "MALICIOUS" ? "Malicious activity confirmed across multiple threat intelligence sources." : result?.verdict === "SUSPICIOUS" ? "Suspicious indicators detected requiring SOC analyst review." : "No threat activity detected across security engines.");
  const priority = recommendation.priority || (result?.verdict === "MALICIOUS" ? "HIGH" : result?.verdict === "SUSPICIOUS" ? "MEDIUM" : "LOW");
  
  const analystNote =
    recommendation.analyst_note ||
    (priority === "HIGH"
      ? "Isolate Host immediately"
      : priority === "MEDIUM"
        ? "Review in Sandbox"
        : "Clear to proceed");

  const isHigh = priority === "HIGH";
  const isMed = priority === "MEDIUM";

  return (
    <section className="analysis-card relative overflow-hidden flex h-full flex-col justify-between rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl">
      {/* TOP ACCENT LINE */}
      <div className={`absolute top-0 left-0 right-0 h-[2.5px] ${isHigh ? "bg-gradient-to-r from-red-500 to-rose-400" : isMed ? "bg-gradient-to-r from-amber-500 to-yellow-400" : "bg-gradient-to-r from-emerald-500 to-teal-400"}`} />

      {/* HEADER WITH PRIORITY BADGE */}
      <div>
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-4 mb-6">
          <div className="flex items-center gap-3.5">
            <div className={`flex h-10 w-10 items-center justify-center rounded-xl border ${isHigh ? "border-red-500/30 bg-red-500/10 text-red-400" : isMed ? "border-amber-500/30 bg-amber-500/10 text-amber-400" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"}`}>
              {isHigh ? <ShieldAlert className="h-5 w-5" /> : isMed ? <AlertTriangle className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5" />}
            </div>
            <h2 className="text-xs font-extrabold uppercase tracking-widest text-slate-300">
              RECOMMENDED ACTION
            </h2>
          </div>

          <span
            className={`inline-flex items-center rounded-md px-4 py-1.5 text-xs font-extrabold uppercase tracking-wider whitespace-nowrap shadow-sm border ${
              isHigh
                ? "border-red-500/40 bg-red-500/10 text-red-400"
                : isMed
                  ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                  : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
            }`}
          >
            PRIORITY: {priority}
          </span>
        </div>

        {/* CENTERED ACTION ICON, TITLE & REASON */}
        <div className="flex items-start gap-4 my-4">
          <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full border shadow-inner ${
            isHigh
              ? "border-red-500/30 bg-red-500/10 text-red-400"
              : isMed
                ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
          }`}>
            {isHigh ? (
              <ShieldAlert className="h-7 w-7 text-red-400" />
            ) : isMed ? (
              <AlertTriangle className="h-7 w-7 text-amber-400" />
            ) : (
              <CheckCircle2 className="h-7 w-7 text-emerald-400" />
            )}
          </div>
          <div>
            <h3 className="text-2xl sm:text-3xl font-black text-white tracking-wide">
              {present(action)}
            </h3>
            <p className="mt-2 text-xs sm:text-sm text-slate-400 font-medium leading-relaxed">
              {present(reason)}
            </p>
          </div>
        </div>
      </div>

      {/* ACTION SUMMARY GRID */}
      <div className="mt-6 grid grid-cols-3 gap-6 border-t border-slate-800/80 pt-5">
        <div>
          <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1.5">ACTION</p>
          <p className="text-xs sm:text-sm font-bold text-slate-200 truncate">{action}</p>
        </div>
        <div>
          <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1.5">PRIORITY</p>
          <p className={`text-xs sm:text-sm font-black ${isHigh ? "text-red-400" : isMed ? "text-amber-400" : "text-emerald-400"}`}>
            {priority.charAt(0).toUpperCase() + priority.slice(1).toLowerCase()}
          </p>
        </div>
        <div>
          <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1.5">ANALYST NOTE</p>
          <p className="text-xs sm:text-sm font-bold text-slate-300 truncate">{analystNote}</p>
        </div>
      </div>
    </section>
  );
}

export default RecommendationCard;
