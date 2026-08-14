import { ClipboardList, ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";
import { present } from "./display";

function ArrayTagList({ list = [] }) {
  const [expanded, setExpanded] = useState(false);
  const maxDisplay = 2;

  if (!list || list.length === 0) {
    return <span className="text-slate-500 font-medium text-xs">—</span>;
  }

  const displayedItems = expanded ? list : list.slice(0, maxDisplay);
  const hiddenCount = list.length - maxDisplay;

  return (
    <div className="flex flex-wrap items-center gap-2 mt-1.5">
      {displayedItems.map((val, idx) => (
        <span
          key={`${val}-${idx}`}
          className="inline-flex items-center rounded-md bg-[#141026] px-3.5 py-1 text-xs font-mono text-purple-300 border border-purple-800/40 shadow-sm break-all"
          title={String(val).trim()}
        >
          {String(val).trim()}
        </span>
      ))}
      {hiddenCount > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="inline-flex items-center gap-1.5 text-xs font-bold text-purple-400 hover:text-purple-300 transition-colors px-3 py-1 rounded-md bg-purple-500/10 border border-purple-500/20"
        >
          {expanded ? (
            <>
              Show less <ChevronUp className="h-3.5 w-3.5" />
            </>
          ) : (
            <>
              +{hiddenCount} more <ChevronDown className="h-3.5 w-3.5" />
            </>
          )}
        </button>
      )}
    </div>
  );
}

function BasicProperties({ title = "BASIC PROPERTIES", items = [] }) {
  const validItems = items.filter((item) => item.value !== undefined && item.value !== null);

  if (!validItems.length) {
    return null;
  }

  return (
    <section className="analysis-card flex h-full flex-col rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl">
      <div className="flex items-center gap-3.5 border-b border-slate-800/80 pb-4 mb-6">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-purple-500/30 bg-purple-500/10 text-purple-400">
          <ClipboardList className="h-5 w-5" />
        </div>
        <h2 className="text-xs font-extrabold uppercase tracking-widest text-slate-300">
          {title}
        </h2>
      </div>

      <div className="grid gap-x-8 gap-y-7 sm:grid-cols-2 md:grid-cols-3 flex-1 items-start">
        {validItems.map((item) => {
          let listValue = null;

          if (Array.isArray(item.value)) {
            listValue = item.value;
          } else if (typeof item.value === "string" && item.value.includes(",")) {
            listValue = item.value.split(",").map((s) => s.trim()).filter(Boolean);
          }

          return (
            <div key={item.label} className="min-w-0 flex flex-col justify-start">
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400 mb-2">
                {item.label}
              </p>
              <div className="break-words text-xs sm:text-sm font-bold text-slate-200 leading-relaxed">
                {item.isBadge ? (
                  <span
                    className={`inline-flex items-center rounded-md px-3.5 py-1 text-xs font-bold border ${
                      item.badgeClass || "border-slate-700 bg-slate-800 text-slate-200"
                    }`}
                  >
                    {present(item.value)}
                  </span>
                ) : listValue ? (
                  <ArrayTagList list={listValue} />
                ) : (
                  <span className="font-mono text-slate-200 font-semibold">{present(item.value)}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default BasicProperties;
