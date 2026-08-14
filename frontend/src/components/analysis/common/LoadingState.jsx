function LoadingState({ message = "Executing Threat Intelligence Analysis..." }) {
  return (
    <div className="flex w-full flex-col items-center justify-center rounded-2xl border border-slate-800/80 bg-[#0d1017] p-12 text-center shadow-xl">
      <div className="relative flex h-12 w-12 items-center justify-center">
        <div className="absolute h-full w-full animate-ping rounded-full bg-purple-500/20" />
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-purple-500 border-t-transparent" />
      </div>
      <p className="mt-4 text-xs font-semibold uppercase tracking-wider text-slate-400">{message}</p>
    </div>
  );
}

export default LoadingState;
