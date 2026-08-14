import { ChevronDown, ChevronUp, Server } from "lucide-react";
import { useState } from "react";

function extractDnsRecordsGrouped(result) {
  const records =
    result?.dns_records ||
    result?.raw?.data?.attributes?.last_dns_records ||
    result?.vt_raw?.data?.attributes?.last_dns_records ||
    [];

  const grouped = {
    A: [],
    AAAA: [],
    MX: [],
    NS: [],
    TXT: [],
    CAA: [],
  };

  if (!Array.isArray(records)) {
    return grouped;
  }

  for (const record of records) {
    const type = String(record?.type || record?.record_type || "").toUpperCase();
    const value = record?.value || record?.address || record?.target || (typeof record === "string" ? record : null);

    if (!value) continue;

    if (!grouped[type]) {
      grouped[type] = [];
    }
    grouped[type].push(value);
  }

  return grouped;
}

function RecordGroupCard({ type, values }) {
  const [expanded, setExpanded] = useState(false);
  const INITIAL_LIMIT = 3;
  const isExpandable = values.length > INITIAL_LIMIT;
  const displayedValues = expanded ? values : values.slice(0, INITIAL_LIMIT);

  return (
    <div className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
      <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
        <span className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-bold text-emerald-300">
          {type}
        </span>
        <span className="text-xs font-bold text-slate-400">
          {values.length} {values.length === 1 ? "record" : "records"}
        </span>
      </div>

      <div className="mt-4 flex flex-wrap gap-2.5">
        {displayedValues.map((val, idx) => (
          <span
            key={`${val}-${idx}`}
            className="break-all inline-flex items-center rounded-xl border border-slate-700/60 bg-slate-800/80 px-3.5 py-2 font-mono text-xs sm:text-sm font-medium text-slate-200 shadow-sm"
          >
            {val}
          </span>
        ))}
      </div>

      {isExpandable && (
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="mt-3.5 inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:text-emerald-300 transition"
        >
          {expanded ? (
            <>
              <span>Collapse Records</span>
              <ChevronUp className="h-4 w-4" />
            </>
          ) : (
            <>
              <span>Show More (+{values.length - INITIAL_LIMIT})</span>
              <ChevronDown className="h-4 w-4" />
            </>
          )}
        </button>
      )}
    </div>
  );
}

function DNSRecordsCard({ result }) {
  const grouped = extractDnsRecordsGrouped(result);

  const activeGroups = Object.entries(grouped).filter(
    ([_, values]) => Array.isArray(values) && values.length > 0
  );

  if (activeGroups.length === 0) {
    return null;
  }

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-emerald-500/50 hover:shadow-2xl hover:shadow-emerald-950/20">
      {/* 🟢 TOP EMERALD ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-emerald-500 via-green-500 to-emerald-400" />

      <div className="flex items-center gap-4 border-b border-slate-800/80 pb-5">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 shadow-inner">
          <Server className="h-6 w-6" />
        </div>
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-emerald-300">
            DNS Records
          </p>
          <h2 className="mt-0.5 text-xl sm:text-2xl font-bold text-white">
            Active Resource Records
          </h2>
        </div>
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {activeGroups.map(([type, values]) => (
          <RecordGroupCard key={type} type={type} values={values} />
        ))}
      </div>
    </section>
  );
}

export default DNSRecordsCard;
