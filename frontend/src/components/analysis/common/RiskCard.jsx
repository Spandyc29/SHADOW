import { ShieldAlert, AlertCircle, CheckCircle2 } from "lucide-react";
import { badgeClass, present, progressWidth, riskProgressClass } from "./display";

function RiskCard({ result }) {
  const riskScore = result?.risk_score ?? 0;
  const severity = result?.severity || "LOW";
  const verdict = result?.verdict || "CLEAN";
  const detections = result?.detections ?? 0;
  const threatLabel = result?.threat_label || "Clean Indicator";
  const threatCategories = result?.threat_categories || [];

  // Dynamic risk factor bullet points from actual scan data
  const rawRiskFactors = result?.risk_factors || [];
  let riskFactors = [...rawRiskFactors];

  if (riskFactors.length === 0) {
    if (detections > 0) {
      riskFactors.push({
        text: `${detections} security engine(s) flagged this indicator.`,
        type: "threat",
      });
      if (threatLabel && threatLabel !== "No Threat Detected") {
        riskFactors.push({
          text: `Threat intelligence classified as '${threatLabel}'.`,
          type: "threat",
        });
      }
      if (threatCategories.length > 0) {
        riskFactors.push({
          text: `Classification confirmed under ${threatCategories.length} category/tag.`,
          type: "threat",
        });
      }
      riskFactors.push({
        text: `Elevated risk profile evaluated by SHADOW Risk Engine.`,
        type: "threat",
      });
    } else {
      riskFactors.push({
        text: `No harmful indicators detected`,
        type: "clean",
      });
      riskFactors.push({
        text: `No malicious behavior identified`,
        type: "clean",
      });
      riskFactors.push({
        text: `File is not associated with known threats`,
        type: "clean",
      });
      riskFactors.push({
        text: `Trusted sources report clean`,
        type: "clean",
      });
    }
  }

  return (
    <section className="analysis-card relative flex flex-col justify-between rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl">
      {/* RED TOP ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-gradient-to-r from-red-500 via-rose-500 to-red-400 rounded-t-2xl" />

      <div>
        {/* HEADER */}
        <div className="flex items-center gap-3.5 border-b border-slate-800/80 pb-4 mb-6">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10 text-red-400">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-xs font-extrabold uppercase tracking-widest text-slate-300">
              RISK ASSESSMENT
            </h2>
          </div>
        </div>

        {/* METRICS & PROGRESS BAR */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1">RISK SCORE</p>
              <p className="text-3xl font-black text-red-400">{present(riskScore)} <span className="text-slate-500 text-lg font-bold">/ 90</span></p>
            </div>
            <div className="text-right">
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1">RISK LEVEL</p>
              <span className={`inline-flex items-center ${badgeClass(severity)}`}>
                {present(severity)} Risk
              </span>
            </div>
          </div>

          <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800/90">
            <div
              className={`h-full rounded-full transition-all duration-700 ease-out ${riskProgressClass(verdict || severity)}`}
              style={{ width: progressWidth(riskScore, 90) }}
            />
          </div>
        </div>

        {/* RISK FACTORS BULLET LIST WITH GENEROUS ITEM SPACING */}
        <div className="mt-6 border-t border-slate-800/80 pt-5">
          <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-4">RISK FACTORS</p>
          <ul className="space-y-3.5">
            {riskFactors.map((factor, idx) => {
              const text = typeof factor === "string" ? factor : factor.text;
              const isThreat = typeof factor === "object" ? factor.type === "threat" : detections > 0;
              return (
                <li key={idx} className="flex items-start gap-3 text-xs sm:text-sm text-slate-300 font-medium leading-relaxed">
                  {isThreat ? (
                    <AlertCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 text-red-400/80 shrink-0 mt-0.5" />
                  )}
                  <span>{text}</span>
                </li>
              );
            })}
          </ul>
        </div>
      </div>

      {/* FOOTER */}
      <div className="mt-6 border-t border-slate-800/80 pt-4 text-xs font-semibold text-slate-400 leading-relaxed block">
        Powered by SHADOW Risk Engine
      </div>
    </section>
  );
}

export default RiskCard;
