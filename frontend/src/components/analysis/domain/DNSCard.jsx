import { Check, Copy, Network } from "lucide-react";
import { useState } from "react";
import { asList } from "../common/display";

function DNSCard({ result }) {
  const [copiedIPs, setCopiedIPs] = useState(false);
  const dnsInfo = result?.dns_info || {};

  const isResolved = Boolean(dnsInfo.resolved);
  const ipAddresses = asList(dnsInfo.ip_addresses);
  const aliases = asList(dnsInfo.aliases);

  const copyIPs = async () => {
    if (ipAddresses.length === 0) return;
    await navigator.clipboard.writeText(ipAddresses.join("\n"));
    setCopiedIPs(true);
    setTimeout(() => setCopiedIPs(false), 1600);
  };

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-cyan-500/50 hover:shadow-2xl hover:shadow-cyan-950/20">
      {/* 🟢 TOP CYAN ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-cyan-500 via-teal-500 to-cyan-400" />

      <div className="flex items-center gap-4 border-b border-slate-800/80 pb-5">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 shadow-inner">
          <Network className="h-6 w-6" />
        </div>
        <div className="flex flex-1 items-center justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wider text-cyan-300">
              DNS Information
            </p>
            <h2 className="mt-0.5 text-xl sm:text-2xl font-bold text-white">
              Host Resolution & IP Mapping
            </h2>
          </div>
          <span
            className={`inline-flex items-center border px-4 py-2 text-xs sm:text-sm font-bold rounded-xl shadow-sm ${
              isResolved
                ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-300"
                : "border-red-400/40 bg-red-500/10 text-red-300"
            }`}
          >
            {isResolved ? "Resolved" : "Not Resolved"}
          </span>
        </div>
      </div>

      <div className="mt-6 grid gap-6 sm:grid-cols-2">
        {/* Resolved IP Addresses */}
        <div className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              Resolved IP Addresses
            </p>
            {ipAddresses.length > 0 && (
              <button
                type="button"
                onClick={copyIPs}
                className="inline-flex h-6 w-6 items-center justify-center rounded text-slate-400 transition hover:bg-slate-800 hover:text-white"
                title="Copy Resolved IP Addresses"
              >
                {copiedIPs ? (
                  <Check className="h-4 w-4 text-emerald-400" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            )}
          </div>
          <div className="mt-3.5 flex flex-wrap gap-3">
            {ipAddresses.length > 0 ? (
              ipAddresses.map((ip, index) => (
                <span
                  key={`${ip}-${index}`}
                  className="inline-flex items-center rounded-xl border border-slate-700/60 bg-slate-800/80 px-3.5 py-2 font-mono text-xs sm:text-sm font-medium text-slate-200 shadow-sm"
                >
                  {ip}
                </span>
              ))
            ) : (
              <span className="text-base font-normal text-slate-400">Not Available</span>
            )}
          </div>
        </div>

        {/* Aliases */}
        <div className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
          <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Hostname Aliases
          </p>
          <div className="mt-3.5 flex flex-wrap gap-3">
            {aliases.length > 0 ? (
              aliases.map((alias, index) => (
                <span
                  key={`${alias}-${index}`}
                  className="inline-flex items-center rounded-xl border border-slate-700/60 bg-slate-800/80 px-3.5 py-2 font-mono text-xs sm:text-sm font-medium text-slate-200 shadow-sm"
                >
                  {alias}
                </span>
              ))
            ) : (
              <span className="text-base font-normal text-slate-400">Not Available</span>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export default DNSCard;
