import { FileType } from "lucide-react";
import { present } from "../common/display";

function FileInformation({ fileType }) {
  if (!fileType) {
    return null;
  }

  const items = [
    { label: "Category", value: fileType.category },
    { label: "MIME Type", value: fileType.mime },
    { label: "Extension", value: fileType.extension },
  ];

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-cyan-500/50 hover:shadow-2xl hover:shadow-cyan-950/20">
      {/* 🟢 TOP CYAN ACCENT BAR */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-cyan-500 via-teal-500 to-cyan-400" />

      <div className="flex items-center gap-4 border-b border-slate-800/80 pb-5">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 shadow-inner">
          <FileType className="h-6 w-6" />
        </div>
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-cyan-300">
            File Information
          </p>
          <h2 className="mt-0.5 text-xl sm:text-2xl font-bold text-white">
            {present(fileType.type)}
          </h2>
        </div>
      </div>

      <div className="mt-6 grid gap-6 sm:grid-cols-3">
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

export default FileInformation;
