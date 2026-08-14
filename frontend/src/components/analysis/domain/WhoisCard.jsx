import { Check, Copy, Database } from "lucide-react";
import { useState } from "react";
import { asList, formatCountry, normalizeStatusList, present } from "../common/display";

function WhoisCard({ result }) {
  const [copiedKey, setCopiedKey] = useState(null);
  const whoisInfo = result?.whois_info || {};

  const registrar = whoisInfo.registrar;
  const country = whoisInfo.country;
  const org = whoisInfo.org;
  const created = whoisInfo.creation_date;
  const updated = whoisInfo.updated_date;
  const expiration = whoisInfo.expiration_date;

  const statusList = normalizeStatusList(whoisInfo.status);
  const nameServers = asList(whoisInfo.name_servers);
  const emails = asList(whoisInfo.emails);

  const copyToClipboard = async (text, key) => {
    if (!text) return;
    await navigator.clipboard.writeText(Array.isArray(text) ? text.join("\n") : text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1600);
  };

  const scalarFields = [
    { label: "Registrar", value: registrar, copyable: Boolean(registrar) },
    { label: "Country", value: formatCountry(country) },
    { label: "Organization", value: org },
    { label: "Created Date", value: created },
    { label: "Updated Date", value: updated },
    { label: "Expiration Date", value: expiration },
  ];

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-blue-500/50 hover:shadow-2xl hover:shadow-blue-950/20">
      {/* 🔵 TOP BLUE ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-blue-500 via-sky-500 to-blue-400" />

      <div className="flex items-center gap-4 border-b border-slate-800/80 pb-5">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-blue-500/30 bg-blue-500/10 text-blue-400 shadow-inner">
          <Database className="h-6 w-6" />
        </div>
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-blue-400">
            WHOIS Information
          </p>
          <h2 className="mt-0.5 text-xl sm:text-2xl font-bold text-white">
            Registration & Contact Details
          </h2>
        </div>
      </div>

      {/* Scalar Fields Grid */}
      <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {scalarFields.map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
                {item.label}
              </p>
              {item.copyable && item.value !== "Not Available" && (
                <button
                  type="button"
                  onClick={() => copyToClipboard(item.value, item.label)}
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
            <p className="mt-2.5 break-words text-lg font-semibold text-slate-100">
              {present(item.value)}
            </p>
          </div>
        ))}
      </div>

      {/* Badge Fields Grid */}
      <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {/* Status Badges */}
        <div className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              Status
            </p>
            {statusList.length > 0 && (
              <button
                type="button"
                onClick={() => copyToClipboard(statusList.join("\n"), "Status")}
                className="inline-flex h-6 w-6 items-center justify-center rounded text-slate-400 transition hover:bg-slate-800 hover:text-white"
                title="Copy WHOIS Statuses"
              >
                {copiedKey === "Status" ? (
                  <Check className="h-4 w-4 text-emerald-400" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            )}
          </div>
          <div className="mt-3.5 flex flex-wrap gap-3">
            {statusList.length > 0 ? (
              statusList.map((status, index) => (
                <span
                  key={`${status}-${index}`}
                  className="inline-flex items-center rounded-xl border border-slate-700/60 bg-slate-800/80 px-3.5 py-2 font-mono text-xs sm:text-sm font-medium text-slate-200 shadow-sm"
                >
                  {status}
                </span>
              ))
            ) : (
              <span className="text-base font-normal text-slate-400">Not Available</span>
            )}
          </div>
        </div>

        {/* Name Servers Badges */}
        <div className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              Name Servers
            </p>
            {nameServers.length > 0 && (
              <button
                type="button"
                onClick={() => copyToClipboard(nameServers.join("\n"), "NameServers")}
                className="inline-flex h-6 w-6 items-center justify-center rounded text-slate-400 transition hover:bg-slate-800 hover:text-white"
                title="Copy Name Servers"
              >
                {copiedKey === "NameServers" ? (
                  <Check className="h-4 w-4 text-emerald-400" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            )}
          </div>
          <div className="mt-3.5 flex flex-wrap gap-3">
            {nameServers.length > 0 ? (
              nameServers.map((ns, index) => (
                <span
                  key={`${ns}-${index}`}
                  className="inline-flex items-center rounded-xl border border-slate-700/60 bg-slate-800/80 px-3.5 py-2 font-mono text-xs sm:text-sm font-medium text-slate-200 shadow-sm"
                >
                  {ns}
                </span>
              ))
            ) : (
              <span className="text-base font-normal text-slate-400">Not Available</span>
            )}
          </div>
        </div>

        {/* Administrative Emails */}
        <div className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              Administrative Emails
            </p>
            {emails.length > 0 && (
              <button
                type="button"
                onClick={() => copyToClipboard(emails.join("\n"), "Emails")}
                className="inline-flex h-6 w-6 items-center justify-center rounded text-slate-400 transition hover:bg-slate-800 hover:text-white"
                title="Copy Administrative Emails"
              >
                {copiedKey === "Emails" ? (
                  <Check className="h-4 w-4 text-emerald-400" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            )}
          </div>
          <div className="mt-3.5 flex flex-wrap gap-3">
            {emails.length > 0 ? (
              emails.map((email, index) => (
                <span
                  key={`${email}-${index}`}
                  className="inline-flex items-center rounded-xl border border-slate-700/60 bg-slate-800/80 px-3.5 py-2 font-mono text-xs sm:text-sm font-medium text-slate-200 shadow-sm"
                >
                  {email}
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

export default WhoisCard;
