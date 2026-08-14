import { Link2 } from "lucide-react";
import { present } from "../common/display";

function URLInformation({ urlInfo = {}, communityReputation }) {
  const items = [
    { label: "URL", value: urlInfo.url },
    { label: "Protocol", value: urlInfo.protocol },
    { label: "Host", value: urlInfo.host },
    { label: "Domain", value: urlInfo.domain },
    { label: "Path", value: urlInfo.path },
    { label: "Query", value: urlInfo.query },
    { label: "Fragment", value: urlInfo.fragment },
    { label: "Port", value: urlInfo.port },
    { label: "URL Length", value: urlInfo.url_length },
    { label: "Community Reputation", value: communityReputation },
  ];

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-purple-500/50 hover:shadow-2xl hover:shadow-purple-950/20">
      {/* 🟣 TOP PURPLE ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-purple-500 via-indigo-500 to-purple-400" />

      <div className="flex items-center gap-4 border-b border-slate-800/80 pb-5">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-purple-500/30 bg-purple-500/10 text-purple-400 shadow-inner">
          <Link2 className="h-6 w-6" />
        </div>
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-purple-400">
            URL Information
          </p>
          <h2 className="mt-0.5 text-xl sm:text-2xl font-bold text-white">
            Structure & Parameters
          </h2>
        </div>
      </div>

      <div className="mt-6 grid gap-6 sm:grid-cols-2 md:grid-cols-3">
        {items.map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
            <p className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              {item.label}
            </p>
            <p className="mt-2.5 break-words text-lg font-semibold text-slate-100">
              {present(item.value)}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}

export default URLInformation;
