import { AtSign, Globe, Hash, Link, Network } from "lucide-react";
import { asList } from "../common/display";

const IOC_GROUPS = [
  { key: "urls", label: "URLs", icon: Link },
  { key: "domains", label: "Domains", icon: Globe },
  { key: "ips", label: "IPs", icon: Network },
  { key: "emails", label: "Emails", icon: AtSign },
  { key: "hashes", label: "Hashes", icon: Hash },
];

function IOCCard({ label, values, Icon }) {
  const items = asList(values);

  return (
    <div className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-700 bg-slate-800/60 text-slate-300">
            <Icon className="h-4.5 w-4.5" />
          </div>
          <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            {label}
          </p>
        </div>
        <span className="rounded-lg border border-slate-700/60 bg-slate-800/70 px-2.5 py-1 text-xs font-bold text-slate-200">
          {items.length}
        </span>
      </div>

      {items.length > 0 ? (
        <ul className="mt-3.5 max-h-44 space-y-2 overflow-auto border-t border-slate-800/60 pt-3">
          {items.map((item, index) => (
            <li key={`${item}-${index}`} className="break-all font-mono text-xs text-slate-200">
              {String(item)}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3.5 border-t border-slate-800/60 pt-3 text-xs text-slate-500">
          No indicators found.
        </p>
      )}
    </div>
  );
}

function IOCExtraction({ ioc }) {
  if (!ioc) {
    return null;
  }

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-purple-500/50 hover:shadow-2xl hover:shadow-purple-950/20">
      {/* 🟣 TOP PURPLE ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-purple-500 via-indigo-500 to-purple-400" />

      <div className="border-b border-slate-800/80 pb-5">
        <p className="text-sm font-semibold uppercase tracking-wider text-purple-400">
          IOC Extraction
        </p>
        <h2 className="mt-0.5 text-xl sm:text-2xl font-bold text-white">
          Extracted Regex Indicators
        </h2>
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-2 xl:grid-cols-5">
        {IOC_GROUPS.map((group) => (
          <IOCCard
            key={group.key}
            label={group.label}
            values={ioc[group.key]}
            Icon={group.icon}
          />
        ))}
      </div>
    </section>
  );
}

export default IOCExtraction;
