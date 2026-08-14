import { SearchX } from "lucide-react";

function NotFoundState({ hash }) {
  return (
    <div className="flex w-full flex-col items-center justify-center rounded-2xl border border-slate-800/80 bg-[#0d1017] p-8 text-center shadow-xl">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-slate-700 bg-slate-800/60 text-slate-400">
        <SearchX className="h-6 w-6" />
      </div>
      <h3 className="mt-4 text-lg font-bold text-white">Indicator Not Found</h3>
      <p className="mt-2 max-w-md text-xs leading-relaxed text-slate-400">
        No record found for <span className="font-mono text-slate-200">{hash}</span> in threat intelligence providers.
      </p>
    </div>
  );
}

export default NotFoundState;
