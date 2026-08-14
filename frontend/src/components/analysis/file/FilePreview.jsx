import { FileText } from "lucide-react";

function FilePreview({ lines }) {
  if (!Array.isArray(lines) || lines.length === 0) {
    return null;
  }

  return (
    <section className="analysis-card rounded-2xl border border-slate-800/80 bg-[#0d1017] shadow-xl">
      <div className="flex items-center gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
          <FileText className="h-5 w-5" />
        </div>
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider text-emerald-300">
            Preview
          </p>
          <h2 className="text-base font-bold text-white">
            First 20 Lines
          </h2>
        </div>
      </div>

      <pre className="mt-5 max-h-96 overflow-auto rounded-xl border border-slate-800/80 bg-[#07090e] p-4 font-mono text-xs leading-relaxed text-slate-300">
        {lines.map((line, index) => `${String(index + 1).padStart(2, " ")}  ${line}`).join("\n")}
      </pre>
    </section>
  );
}

export default FilePreview;
