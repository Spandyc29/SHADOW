import { Check, Copy, Network } from "lucide-react";
import { useState } from "react";
import { present, presentOr } from "../common/display";

function IPOverview({ result }) {
  const [copiedIp, setCopiedIp] = useState(false);
  const ipInfo = result?.ip_info || {};

  const ipAddress = ipInfo.ip || result?.ip || result?.indicator;
  const version = ipInfo.version || (ipInfo.ip_version ? `IPv${ipInfo.ip_version}` : "Not Available");
  const isPublic = ipInfo.is_public;
  const isPrivate = ipInfo.is_private;
  const isLoopback = ipInfo.is_loopback;
  const isReserved = ipInfo.is_reserved;
  const isLinkLocal = ipInfo.is_link_local;
  const isMulticast = ipInfo.is_multicast;
  const reverseDns = presentOr(ipInfo.reverse_dns, "Reverse DNS not available.");

  const rawReputation = result?.reputation_label || result?.community_reputation_label;

  const copyIp = async () => {
    if (!ipAddress) return;
    await navigator.clipboard.writeText(ipAddress);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 1600);
  };

  const scopeLabel = isPublic ? "Public IP" : isPrivate ? "Private IP" : isLoopback ? "Loopback IP" : "Special IP";
  const scopeBadgeClass = isPublic
    ? "border-cyan-400/40 bg-cyan-500/10 text-cyan-300 font-bold px-3 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm"
    : isPrivate
      ? "border-amber-400/40 bg-amber-500/10 text-amber-300 font-bold px-3 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm"
      : "border-slate-600/80 bg-slate-800/80 text-slate-300 font-bold px-3 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm";

  const renderReputationBadge = (rep) => {
    if (!rep || rep === "Not Available") {
      return (
        <span className="inline-flex items-center border border-slate-700/60 bg-slate-800/80 text-slate-400 font-medium px-3.5 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm">
          No threat classification reported.
        </span>
      );
    }

    const normalized = String(rep).toLowerCase();

    if (normalized.includes("excellent")) {
      return (
        <span className="inline-flex items-center gap-1.5 border border-emerald-400/40 bg-emerald-500/10 text-emerald-300 font-bold px-3.5 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm">
          <span>🟢</span> Excellent
        </span>
      );
    }

    if (normalized.includes("good")) {
      return (
        <span className="inline-flex items-center gap-1.5 border border-emerald-400/40 bg-emerald-500/10 text-emerald-300 font-bold px-3.5 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm">
          <span>🟢</span> Good
        </span>
      );
    }

    if (normalized.includes("neutral")) {
      return (
        <span className="inline-flex items-center gap-1.5 border border-amber-400/40 bg-amber-500/10 text-amber-300 font-bold px-3.5 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm">
          <span>🟡</span> Neutral
        </span>
      );
    }

    if (normalized.includes("poor") || normalized.includes("malicious")) {
      return (
        <span className="inline-flex items-center gap-1.5 border border-red-400/40 bg-red-500/10 text-red-300 font-bold px-3.5 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm">
          <span>🔴</span> Poor
        </span>
      );
    }

    return (
      <span className="inline-flex items-center gap-1.5 border border-slate-700/60 bg-slate-800/80 text-slate-200 font-bold px-3.5 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm">
        {rep}
      </span>
    );
  };

  const booleanBadge = (val) =>
    val ? (
      <span className="inline-flex items-center border border-emerald-400/40 bg-emerald-500/10 text-emerald-300 font-bold px-3 py-1 text-xs sm:text-sm rounded-xl shadow-sm">
        Yes
      </span>
    ) : (
      <span className="inline-flex items-center border border-slate-700/60 bg-slate-800/80 text-slate-400 font-medium px-3 py-1 text-xs sm:text-sm rounded-xl shadow-sm">
        No
      </span>
    );

  const items = [
    { label: "IP Address", value: ipAddress },
    {
      label: "IP Version",
      value: version,
      isBadge: true,
      badgeClass: "border-purple-400/40 bg-purple-500/10 text-purple-300 font-bold px-3.5 py-1.5 text-xs sm:text-sm rounded-xl shadow-sm",
    },
    {
      label: "Access Scope",
      value: scopeLabel,
      isBadge: true,
      badgeClass: scopeBadgeClass,
    },
    {
      label: "Reverse DNS",
      value: reverseDns,
      isMuted: reverseDns === "Reverse DNS not available.",
    },
    {
      label: "Loopback",
      customRender: booleanBadge(isLoopback),
    },
    {
      label: "Reserved",
      customRender: booleanBadge(isReserved),
    },
    {
      label: "Link Local",
      customRender: booleanBadge(isLinkLocal),
    },
    {
      label: "Multicast",
      customRender: booleanBadge(isMulticast),
    },
    {
      label: "Threat Classification",
      customRender: renderReputationBadge(rawReputation),
    },
  ];

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-cyan-500/50 hover:shadow-2xl hover:shadow-cyan-950/20">
      {/* Top Cyan Accent Bar */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500" />

      {/* Card Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-5">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 shadow-inner">
            <Network className="h-6 w-6" />
          </div>
          <div>
            <p className="text-sm font-semibold uppercase tracking-wider text-cyan-400">
              IP Overview
            </p>
            <h2 className="mt-1 text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight">
              {present(ipAddress)}
            </h2>
          </div>
        </div>

        {ipAddress && (
          <button
            type="button"
            onClick={copyIp}
            title="Copy IP Address"
            className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-slate-700/80 bg-slate-800/60 px-4 text-xs sm:text-sm font-semibold text-slate-200 transition hover:bg-slate-700/80 hover:text-white shadow-sm"
          >
            {copiedIp ? (
              <>
                <Check className="h-4 w-4 text-emerald-400" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-4 w-4 text-slate-400" />
                <span>Copy IP</span>
              </>
            )}
          </button>
        )}
      </div>

      {/* Stats Grid */}
      <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
            <p className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-slate-400">
              {item.label}
            </p>
            <div className="mt-2.5 break-words text-base sm:text-lg font-semibold text-slate-100">
              {item.customRender ? (
                item.customRender
              ) : item.isBadge ? (
                <span className={`inline-flex items-center ${item.badgeClass}`}>
                  {present(item.value)}
                </span>
              ) : (
                <span className={item.isMuted ? "text-slate-400 font-normal text-sm sm:text-base" : ""}>
                  {present(item.value)}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default IPOverview;
