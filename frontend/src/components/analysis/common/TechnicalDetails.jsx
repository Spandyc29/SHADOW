import { ChevronDown, Database, ExternalLink, Server } from "lucide-react";
import { JsonBlock, asList, present } from "./display";

function VirusTotalDonutChart({ malicious = 0, suspicious = 0, undetected = 0, total = 0 }) {
  const safeTotal = total > 0 ? total : (malicious + suspicious + undetected) || 1;
  const safeUndetected = Math.max(0, safeTotal - malicious - suspicious);

  const malPct = (malicious / safeTotal) * 100;
  const suspPct = (suspicious / safeTotal) * 100;
  const undPct = (safeUndetected / safeTotal) * 100;

  const r = 36;
  const c = 2 * Math.PI * r;

  const malStroke = (malPct / 100) * c;
  const suspStroke = (suspPct / 100) * c;
  const undStroke = (undPct / 100) * c;

  const malOffset = 0;
  const suspOffset = -malStroke;
  const undOffset = -(malStroke + suspStroke);

  return (
    <div className="flex flex-wrap items-center gap-6">
      <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90 transform">
          <circle cx="50" cy="50" r={r} fill="transparent" stroke="#1e293b" strokeWidth="12" />
          {undPct > 0 && (
            <circle
              cx="50"
              cy="50"
              r={r}
              fill="transparent"
              stroke="#10b981"
              strokeWidth="12"
              strokeDasharray={`${undStroke} ${c - undStroke}`}
              strokeDashoffset={undOffset}
            />
          )}
          {suspPct > 0 && (
            <circle
              cx="50"
              cy="50"
              r={r}
              fill="transparent"
              stroke="#f59e0b"
              strokeWidth="12"
              strokeDasharray={`${suspStroke} ${c - suspStroke}`}
              strokeDashoffset={suspOffset}
            />
          )}
          {malPct > 0 && (
            <circle
              cx="50"
              cy="50"
              r={r}
              fill="transparent"
              stroke="#ef4444"
              strokeWidth="12"
              strokeDasharray={`${malStroke} ${c - malStroke}`}
              strokeDashoffset={malOffset}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
          <span className="text-xs font-black text-white">{malicious}</span>
          <span className="text-[9px] font-bold text-slate-400">/ {safeTotal}</span>
        </div>
      </div>

      <div className="space-y-1.5 text-xs font-medium min-w-[130px]">
        <div className="flex items-center gap-2.5">
          <span className="h-2.5 w-2.5 rounded-full bg-red-500 shrink-0" />
          <span className="text-slate-400">Malicious</span>
          <span className="font-mono font-bold text-slate-200 ml-auto">{malicious}</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="h-2.5 w-2.5 rounded-full bg-amber-500 shrink-0" />
          <span className="text-slate-400">Suspicious</span>
          <span className="font-mono font-bold text-slate-200 ml-auto">{suspicious}</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 shrink-0" />
          <span className="text-slate-400">Undetected</span>
          <span className="font-mono font-bold text-slate-200 ml-auto">{safeUndetected}</span>
        </div>
      </div>
    </div>
  );
}

function TechnicalDetails({ result }) {
  const engines = asList(result?.flagged_engines);

  return (
    <section className="w-full space-y-5 pt-1">
      {/* 1. TECHNICAL DETAILS ACCORDION */}
      <details className="analysis-card group rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-4 p-6 outline-none hover:bg-white/[0.02] transition-colors rounded-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-800/60 text-slate-300">
              <Server className="h-4.5 w-4.5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-wide">
                Technical Details
              </h2>
              <p className="mt-0.5 text-xs text-slate-400 font-medium">
                File metadata, hashes, entropy, and other technical information
              </p>
            </div>
          </div>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800/60 border border-slate-700/60">
            <ChevronDown className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-180" />
          </div>
        </summary>

        <div className="border-t border-slate-800/80 p-6">
          <div className="grid gap-6 lg:grid-cols-3">
            {/* ENGINE COVERAGE CARD */}
            <div className="rounded-xl border border-slate-800/80 bg-[#06040b] p-5 flex flex-col justify-between">
              <div>
                <p className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400">
                  ENGINE COVERAGE
                </p>
                <p className="mt-2 text-3xl font-black text-white">
                  {present(result?.usable_engines)}{" "}
                  <span className="text-xs font-bold text-slate-400">usable</span>
                </p>
              </div>
              <div className="mt-4 border-t border-slate-800/80 pt-3 text-xs font-semibold text-slate-400 space-y-1">
                <p>{present(result?.unusable_engines)} engines unavailable</p>
                <p>
                  Detections: <span className="text-purple-300 font-bold">{present(result?.detections)}</span> / {present(result?.usable_engines)}
                </p>
              </div>
            </div>

            {/* UNUSABLE BREAKDOWN BLOCK */}
            <div className="rounded-xl border border-slate-800/80 bg-[#06040b] p-5 lg:col-span-2">
              <p className="mb-3 text-[10px] font-extrabold uppercase tracking-widest text-slate-400">
                UNUSABLE BREAKDOWN
              </p>
              <div className="rounded-lg overflow-hidden border border-slate-800/80">
                <JsonBlock value={result?.unusable_breakdown} />
              </div>
            </div>
          </div>
        </div>
      </details>

      {/* 2. PROVIDER EVIDENCE ACCORDION */}
      <details className="analysis-card group rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-4 p-6 outline-none hover:bg-white/[0.02] transition-colors rounded-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-800/60 text-slate-300">
              <Database className="h-4.5 w-4.5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-wide">
                Provider Evidence
              </h2>
              <p className="mt-0.5 text-xs text-slate-400 font-medium">
                Raw data from VirusTotal, OTX and other threat intelligence providers
              </p>
            </div>
          </div>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800/60 border border-slate-700/60">
            <ChevronDown className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-180" />
          </div>
        </summary>

        <div className="border-t border-slate-800/80 p-6 space-y-6">
          {/* VIRUSTOTAL & TOP DETECTIONS SUMMARY GRID */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {/* VT SUMMARY CARD WITH DONUT CHART */}
            <div className="rounded-xl border border-slate-800/80 bg-[#06040b] p-5 flex flex-col justify-between">
              <div>
                <p className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-3">
                  VIRUSTOTAL SUMMARY
                </p>
                <div className="space-y-1 text-xs text-slate-400 mb-4">
                  <div className="flex justify-between">
                    <span>Engines Scanned:</span>
                    <span className="font-bold text-slate-200">{present(result?.usable_engines ?? result?.total_engines ?? 74)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Detections:</span>
                    <span className="font-bold text-red-400">{present(result?.detections ?? 0)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Detection Ratio:</span>
                    <span className="font-bold text-purple-300">
                      {(((result?.detections ?? 0) / (result?.usable_engines ?? result?.total_engines ?? 74)) * 100).toFixed(2)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* DONUT CHART COMPONENT */}
              <div className="pt-3 border-t border-slate-800/80">
                <VirusTotalDonutChart
                  malicious={result?.detections ?? 0}
                  suspicious={result?.suspicious ?? (result?.verdict === "SUSPICIOUS" ? 1 : 0)}
                  undetected={Math.max(0, (result?.usable_engines ?? result?.total_engines ?? 74) - (result?.detections ?? 0))}
                  total={result?.usable_engines ?? result?.total_engines ?? 74}
                />
              </div>
            </div>

            {/* TOP DETECTIONS / THREAT ENGINES LIST */}
            <div className="rounded-xl border border-slate-800/80 bg-[#06040b] p-5">
              <p className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-3">
                TOP DETECTIONS
              </p>
              {engines.length > 0 ? (
                <div className="space-y-2.5 text-xs">
                  {engines.slice(0, 5).map((eng, idx) => (
                    <div key={idx} className="flex items-start justify-between gap-2 border-b border-slate-800/60 pb-2">
                      <span className="font-bold text-slate-200 shrink-0">{present(eng?.engine || eng?.name || eng)}</span>
                      <span className="font-mono text-[11px] font-bold text-red-400 break-all text-right">
                        {present(eng?.result || "Detected")}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">No malicious engine flags detected.</p>
              )}
            </div>

            {/* OTX & EXTERNAL LINK CARD */}
            <div className="rounded-xl border border-slate-800/80 bg-[#06040b] p-5 flex flex-col justify-between">
              <div>
                <p className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400 mb-3">
                  EXTERNAL INTELLIGENCE PROVIDERS
                </p>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  Full provider evidence datasets synced via VirusTotal APIv3 and AlienVault OTX Threat Intelligence Gateway.
                </p>
              </div>

              {result?.permalink && (
                <a
                  href={result.permalink}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex h-9 items-center justify-center gap-2 rounded-xl border border-purple-500/40 bg-purple-500/10 px-4 text-xs font-extrabold uppercase tracking-wider text-purple-300 transition hover:bg-purple-500/20 hover:border-purple-500/60 shadow-md"
                >
                  <span>View Full Evidence</span>
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              )}
            </div>
          </div>

          {/* ENGINE TABLE */}
          <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-[#06040b]">
            <div className="border-b border-slate-800/80 bg-slate-900/40 px-5 py-3.5">
              <p className="text-[10px] font-extrabold uppercase tracking-widest text-slate-400">
                FLAGGED ENGINES ({engines.length})
              </p>
            </div>

            {engines.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[600px] border-collapse text-left text-sm">
                  <thead className="border-b border-slate-800/80 bg-slate-950/40 text-[10px] font-extrabold uppercase tracking-widest text-slate-400">
                    <tr>
                      <th className="px-5 py-3">Engine</th>
                      <th className="px-5 py-3">Category</th>
                      <th className="px-5 py-3">Result</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {engines.map((engine, index) => (
                      <tr
                        key={`${engine?.engine || index}-${index}`}
                        className="transition-colors hover:bg-purple-950/20 text-slate-300"
                      >
                        <td className="px-5 py-3 font-bold text-slate-200 whitespace-nowrap">
                          {present(engine?.engine || engine?.name || engine)}
                        </td>
                        <td className="px-5 py-3">
                          <span className="inline-flex rounded-md bg-slate-800/60 px-2.5 py-0.5 text-xs font-semibold text-slate-400 border border-slate-700/50">
                            {present(engine?.category)}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-red-400 font-bold font-mono text-xs sm:text-sm break-all leading-relaxed">
                          {present(engine?.result)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="p-6 text-center text-xs font-medium text-slate-400">
                No flagged engines reported.
              </p>
            )}
          </div>
        </div>
      </details>
    </section>
  );
}

export default TechnicalDetails;
