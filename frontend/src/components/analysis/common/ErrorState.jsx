import { AlertTriangle, RefreshCw } from "lucide-react";

function ErrorState({ title = "Analysis Failed", message, onRetry }) {
  return (
    <div className="flex w-full flex-col items-center justify-center rounded-2xl border border-red-500/20 bg-red-500/5 p-8 text-center shadow-xl">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10 text-red-400">
        <AlertTriangle className="h-6 w-6" />
      </div>
      <h3 className="mt-4 text-lg font-bold text-white">{title}</h3>
      <p className="mt-2 max-w-md text-xs leading-relaxed text-slate-400">
        {message || "An unexpected error occurred during execution."}
      </p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-5 inline-flex h-9 items-center justify-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 text-xs font-semibold text-red-300 transition hover:bg-red-500/20"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Retry Investigation
        </button>
      )}
    </div>
  );
}

export default ErrorState;
