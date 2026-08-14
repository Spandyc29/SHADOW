import { Check, Copy, Globe } from "lucide-react";
import { useState } from "react";
import { badgeClass, present } from "../common/display";

function DomainOverview({ result }) {
  const [copiedDomain, setCopiedDomain] = useState(false);
  const domainInfo = result?.domain_info || {};
  const whoisInfo = result?.whois_info || {};

  const domain = domainInfo.domain || result?.domain || result?.indicator;
  const tld = domainInfo.tld;
  const secondLevelDomain = domainInfo.second_level_domain;
  const subdomain = domainInfo.subdomain;
  const domainAge = whoisInfo.domain_age;
  const expiresIn = whoisInfo.remaining_time;

  const dnssecStatus = whoisInfo.dnssec || "Unsigned";
  const reputationLabel = result?.reputation_label || result?.community_reputation_label;

  const copyDomain = async () => {
    if (!domain) return;
    await navigator.clipboard.writeText(domain);
    setCopiedDomain(true);
    setTimeout(() => setCopiedDomain(false), 1600);
  };

  const items = [
    { label: "Domain", value: domain },
    { label: "TLD", value: tld },
    { label: "Second Level Domain", value: secondLevelDomain },
    { label: "Subdomain", value: subdomain },
    { label: "Domain Age", value: domainAge },
    { label: "Expires In", value: expiresIn },
    {
      label: "DNSSEC",
      value: dnssecStatus,
      isBadge: true,
      badgeClass:
        dnssecStatus === "Signed"
          ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-300 font-bold px-3.5 py-2 text-xs sm:text-sm rounded-xl shadow-sm"
          : "border-slate-600/80 bg-slate-800/80 text-slate-300 font-bold px-3.5 py-2 text-xs sm:text-sm rounded-xl shadow-sm",
    },
    {
      label: "Reputation Label",
      value: reputationLabel,
      isBadge: true,
      badgeClass: badgeClass(reputationLabel),
    },
  ];

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-purple-500/50 hover:shadow-2xl hover:shadow-purple-950/20">
      {/* 🟣 TOP PURPLE ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-purple-500 via-indigo-500 to-purple-400" />

      {/* CARD HEADER */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-5">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-purple-500/30 bg-purple-500/10 text-purple-400 shadow-inner">
            <Globe className="h-6 w-6" />
          </div>
          <div>
            <p className="text-sm font-semibold uppercase tracking-wider text-purple-400">
              Domain Overview
            </p>
            <h2 className="mt-1 text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight">
              {present(domain)}
            </h2>
          </div>
        </div>

        {domain && (
          <button
            type="button"
            onClick={copyDomain}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-slate-700/80 bg-slate-800/60 px-4 text-xs sm:text-sm font-semibold text-slate-200 transition hover:bg-slate-700/80 hover:text-white shadow-sm"
          >
            {copiedDomain ? (
              <>
                <Check className="h-4 w-4 text-emerald-400" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-4 w-4 text-slate-400" />
                <span>Copy Domain</span>
              </>
            )}
          </button>
        )}
      </div>

      {/* STATS GRID */}
      <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {items.map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
            <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              {item.label}
            </p>
            <div className="mt-2.5 break-words text-lg font-semibold text-slate-100">
              {item.isBadge ? (
                <span className={`inline-flex items-center border ${item.badgeClass}`}>
                  {present(item.value)}
                </span>
              ) : (
                present(item.value)
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default DomainOverview;
