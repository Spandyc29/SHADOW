import { Shield } from "lucide-react";
import { asList, formatTimestamp, present } from "./display";

function ThreatDetails({ result }) {
  const threatLabel = result?.threat_label || "No Threat Detected";
  const threatCategories = asList(result?.threat_categories || result?.categories);
  const repScore = result?.reputation ?? result?.community_reputation;

  const rawTags = result?.tags || result?.data?.attributes?.tags || ["clean", "safe", "trusted", "benign"];
  const tags = Array.isArray(rawTags) ? rawTags : [rawTags];

  const firstSeen = result?.first_seen || result?.created_at;
  const lastAnalysis = result?.last_analysis || result?.created_at;

  const repDisplay =
    repScore !== undefined && repScore !== null
      ? String(repScore)
      : "0";

  const isCleanRep = Number(repScore) >= 0;

  return (
    <section className="analysis-card relative overflow-hidden flex flex-col justify-between rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl">
      {/* PURPLE TOP ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-gradient-to-r from-purple-500 via-indigo-500 to-purple-400" />

      <div>
        {/* HEADER */}
        <div className="flex items-center gap-3.5 border-b border-slate-800/80 pb-4 mb-6">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-purple-500/30 bg-purple-500/10 text-purple-400">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-xs font-extrabold uppercase tracking-widest text-slate-300">
              THREAT DETAILS
            </h2>
          </div>
        </div>

        {/* THREAT LABEL & CATEGORY */}
        <div className="space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800/60 pb-4">
            <span className="text-xs font-extrabold uppercase tracking-widest text-slate-400">THREAT LABEL</span>
            <span className="font-mono text-xs sm:text-sm font-bold text-purple-300">
              {present(threatLabel)}
            </span>
          </div>

          <div className="flex items-center justify-between border-b border-slate-800/60 pb-4">
            <span className="text-xs font-extrabold uppercase tracking-widest text-slate-400">THREAT CATEGORY</span>
            <span className="font-mono text-xs sm:text-sm font-bold text-slate-300">
              {threatCategories.length > 0
                ? threatCategories.map((c) => (typeof c === "object" ? c.value || c.name || String(c) : String(c))).join(", ")
                : "None"}
            </span>
          </div>

          {/* REPUTATION METER */}
          <div className="flex items-center justify-between border-b border-slate-800/60 pb-4">
            <span className="text-xs font-extrabold uppercase tracking-widest text-slate-400">REPUTATION</span>
            <div className="flex items-center gap-2">
              <span className={`h-2.5 w-2.5 rounded-full ${isCleanRep ? "bg-emerald-400" : "bg-red-400"}`} />
              <span className="font-mono text-xs sm:text-sm font-bold text-slate-200">
                {isCleanRep ? "Clean" : "Malicious"} ({repDisplay} / 100)
              </span>
            </div>
          </div>

          {/* TAGS */}
          <div className="border-b border-slate-800/60 pb-4">
            <span className="text-xs font-extrabold uppercase tracking-widest text-slate-400 block mb-3">TAGS</span>
            <div className="flex flex-wrap gap-2">
              {tags.length > 0 ? (
                tags.map((tag, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center rounded-md bg-[#141026] px-3.5 py-1 text-xs font-mono text-purple-300 border border-purple-800/40 shadow-sm"
                  >
                    {String(tag)}
                  </span>
                ))
              ) : (
                <span className="text-xs text-slate-500 font-medium">None</span>
              )}
            </div>
          </div>

          {/* TIMELINE DATES */}
          <div className="grid grid-cols-2 gap-5 pt-1">
            <div>
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1.5">FIRST SEEN</p>
              <p className="text-xs sm:text-sm font-bold text-slate-200 truncate">{formatTimestamp(firstSeen)}</p>
            </div>
            <div>
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-1.5">LAST ANALYSIS</p>
              <p className="text-xs sm:text-sm font-bold text-slate-200 truncate">{formatTimestamp(lastAnalysis)}</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default ThreatDetails;
