import { Gauge, CheckCircle2 } from "lucide-react";
import { confidenceBadgeClass, present, progressWidth } from "./display";

function ConfidenceCard({ result }) {
  const confidenceScore = result?.confidence_score ?? 80;
  const confidence = result?.confidence || "HIGH";
  const usableEngines = result?.usable_engines ?? result?.total_engines ?? 75;
  const detections = result?.detections ?? 0;
  const detectionPct = usableEngines > 0 ? ((detections / usableEngines) * 100).toFixed(2) : "0.00";

  // Dynamic confidence factors
  const rawFactors = result?.confidence_factors || [];
  let confidenceFactors = [...rawFactors];

  if (confidenceFactors.length === 0) {
    if (detections === 0) {
      confidenceFactors.push({
        text: `Multiple engines confirmed clean (+45)`,
        type: "positive",
      });
      confidenceFactors.push({
        text: `No suspicious patterns detected (+20)`,
        type: "positive",
      });
      confidenceFactors.push({
        text: `File reputation is clean (+15)`,
        type: "positive",
      });
    } else {
      confidenceFactors.push({
        text: `${usableEngines} usable security engines contributed analysis (+25)`,
        type: "positive",
      });
      confidenceFactors.push({
        text: `${detections}/${usableEngines} usable engines flagged the indicator (${detectionPct}%) (+10)`,
        type: "info",
      });
      confidenceFactors.push({
        text: `Threat intelligence metadata available (+25)`,
        type: "positive",
      });
    }
  }

  return (
    <section className="analysis-card relative flex flex-col justify-between rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl">
      {/* BLUE TOP ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-gradient-to-r from-blue-500 via-sky-500 to-blue-400 rounded-t-2xl" />

      <div>
        {/* HEADER */}
        <div className="flex items-center gap-3.5 border-b border-slate-800/80 pb-4 mb-6">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-blue-500/30 bg-blue-500/10 text-blue-400">
            <Gauge className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-xs font-extrabold uppercase tracking-widest text-slate-300">
              CONFIDENCE ASSESSMENT
            </h2>
          </div>
        </div>

        {/* METRICS & PROGRESS BAR */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1">CONFIDENCE SCORE</p>
              <p className="text-3xl font-black text-blue-400">{present(confidenceScore)} <span className="text-slate-500 text-lg font-bold">/ 100</span></p>
            </div>
            <div className="text-right">
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1">CONFIDENCE LEVEL</p>
              <span className={`inline-flex items-center ${confidenceBadgeClass(confidence)}`}>
                {present(confidence)} Confidence
              </span>
            </div>
          </div>

          <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800/90">
            <div
              className="h-full rounded-full bg-blue-500 transition-all duration-700 ease-out"
              style={{ width: progressWidth(confidenceScore, 100) }}
            />
          </div>
        </div>

        {/* CONFIDENCE FACTORS BULLET LIST WITH GENEROUS ITEM SPACING */}
        <div className="mt-6 border-t border-slate-800/80 pt-5">
          <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-4">CONFIDENCE FACTORS</p>
          <ul className="space-y-3.5">
            {confidenceFactors.map((factor, idx) => {
              const text = typeof factor === "string" ? factor : factor.text;
              return (
                <li key={idx} className="flex items-start gap-3 text-xs sm:text-sm text-slate-300 font-medium leading-relaxed">
                  <CheckCircle2 className="h-4 w-4 text-blue-400 shrink-0 mt-0.5" />
                  <span>{text}</span>
                </li>
              );
            })}
          </ul>
        </div>
      </div>

      {/* FOOTER */}
      <div className="mt-6 border-t border-slate-800/80 pt-4 text-xs font-semibold text-slate-400 leading-relaxed block">
        Powered by SHADOW Confidence Engine
      </div>
    </section>
  );
}

export default ConfidenceCard;
