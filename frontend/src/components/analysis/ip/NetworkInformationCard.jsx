import { Check, ChevronDown, ChevronUp, Copy, Server } from "lucide-react";
import { useState } from "react";
import { presentOr } from "../common/display";

function NetworkInformationCard({ result }) {
  const [copiedKey, setCopiedKey] = useState(null);
  const [expandedWhois, setExpandedWhois] = useState(false);

  const ipInfo = result?.ip_info || {};

  const rawAsn = ipInfo.asn || result?.asn;
  const rawAsOwner = ipInfo.as_owner || ipInfo.as_org || result?.as_owner;
  const rawNetwork = ipInfo.network || result?.network;
  const rawCidr = ipInfo.cidr || ipInfo.network || result?.network;
  const whoisData = ipInfo.whois || result?.whois;

  const asn = presentOr(rawAsn, "Provider did not return ASN information.");
  const asOwner = presentOr(rawAsOwner, "Provider did not return AS owner information.");
  const network = presentOr(rawNetwork, "Provider did not return network range.");
  const cidr = presentOr(rawCidr, "Provider did not return CIDR information.");

  const copyToClipboard = async (text, key) => {
    if (!text) return;
    await navigator.clipboard.writeText(String(text));
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1600);
  };

  const items = [
    {
      label: "ASN",
      value: asn,
      raw: rawAsn,
      isMuted: asn.startsWith("Provider"),
    },
    {
      label: "AS Owner / Organization",
      value: asOwner,
      raw: rawAsOwner,
      isMuted: asOwner.startsWith("Provider"),
    },
    {
      label: "Network Range",
      value: network,
      raw: rawNetwork,
      isMuted: network.startsWith("Provider"),
    },
    {
      label: "CIDR Notation",
      value: cidr,
      raw: rawCidr,
      isMuted: cidr.startsWith("Provider"),
    },
  ];

  // WHOIS line truncation logic
  const whoisString = typeof whoisData === "string" ? whoisData.trim() : "";
  const whoisLines = whoisString ? whoisString.split("\n") : [];
  const maxInitialLines = 14;
  const needsTruncation = whoisLines.length > maxInitialLines;

  const displayedWhoisText =
    needsTruncation && !expandedWhois
      ? whoisLines.slice(0, maxInitialLines).join("\n") + "\n..."
      : whoisString;

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-blue-500/50 hover:shadow-2xl hover:shadow-blue-950/20">
      {/* Top Blue Accent Bar */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-500" />

      {/* Card Header */}
      <div className="flex items-center gap-4 border-b border-slate-800/80 pb-5">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-blue-500/30 bg-blue-500/10 text-blue-400 shadow-inner">
          <Server className="h-6 w-6" />
        </div>
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-blue-400">
            Network & Autonomous System
          </p>
          <h2 className="mt-1 text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight">
            Network Information
          </h2>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {items.map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
            <div className="flex items-center justify-between">
              <p className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-slate-400">
                {item.label}
              </p>
              {item.raw && (
                <button
                  type="button"
                  onClick={() => copyToClipboard(item.raw, item.label)}
                  className="inline-flex h-6 w-6 items-center justify-center rounded text-slate-400 transition hover:bg-slate-800 hover:text-white"
                  title={`Copy ${item.label}`}
                >
                  {copiedKey === item.label ? (
                    <Check className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              )}
            </div>
            <div className={`mt-2.5 break-words text-base sm:text-lg font-semibold ${item.isMuted ? "text-slate-400 font-normal text-sm sm:text-base" : "text-slate-100"}`}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      {/* WHOIS Record Block */}
      <div className="mt-6 rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-3">
          <p className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-slate-400">
            WHOIS Record
          </p>
          {whoisString && (
            <button
              type="button"
              onClick={() => copyToClipboard(whoisString, "WHOIS")}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-800/60 px-3 py-1 text-xs font-semibold text-slate-300 transition hover:bg-slate-700 hover:text-white"
              title="Copy raw WHOIS text"
            >
              {copiedKey === "WHOIS" ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5 text-slate-400" />
                  <span>Copy WHOIS</span>
                </>
              )}
            </button>
          )}
        </div>

        {whoisString ? (
          <div>
            <pre className="max-h-[400px] overflow-auto whitespace-pre-wrap break-all font-mono text-[13px] sm:text-sm text-slate-300 leading-relaxed rounded-lg border border-slate-800/90 bg-[#07090e] p-4 transition-all duration-300">
              {displayedWhoisText}
            </pre>
            {needsTruncation && (
              <div className="mt-3 flex justify-center">
                <button
                  type="button"
                  onClick={() => setExpandedWhois(!expandedWhois)}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-700/80 bg-slate-800/60 px-4 py-2 text-xs sm:text-sm font-semibold text-slate-200 transition hover:bg-slate-700/80 hover:text-white shadow-sm"
                >
                  {expandedWhois ? (
                    <>
                      <span>Show Less</span>
                      <ChevronUp className="h-4 w-4 text-slate-400" />
                    </>
                  ) : (
                    <>
                      <span>Show More ({whoisLines.length} lines)</span>
                      <ChevronDown className="h-4 w-4 text-slate-400" />
                    </>
                  )}
                </button>
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-slate-400 font-normal py-2">
            WHOIS data not available for this IP address.
          </p>
        )}
      </div>
    </section>
  );
}

export default NetworkInformationCard;
