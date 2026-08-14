import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { KeyRound, Search, ShieldCheck } from "lucide-react";
import { analyzeHash } from "../services/api";
import { useAuth } from "../context/AuthContext";
import AnalysisResult from "../components/analysis/AnalysisResult";
import ErrorState from "../components/analysis/common/ErrorState";
import LoadingState from "../components/analysis/common/LoadingState";
import NotFoundState from "../components/analysis/common/NotFoundState";


function HashAnalysis() {
  const location = useLocation();
  const [hash, setHash] = useState("");
  const [submittedHash, setSubmittedHash] = useState("");
  const [result, setResult] = useState(null);
  const [metadata, setMetadata] = useState({});
  const [loading, setLoading] = useState(false);
  const [state, setState] = useState({ type: "idle", message: "" });
  const { isGuest, user } = useAuth();

  useEffect(() => {
    const restored = location.state?.result || location.state?.analysisResult;
    if (restored && !result) {
      setResult(restored);
      const restoredHash = restored.indicator || restored.hashes?.sha256 || restored.hashes?.md5 || "";
      setSubmittedHash(restoredHash);
      setHash(restoredHash);
      setMetadata({
        hashType: restored.indicator_type || restored.hash_type || "hash",
        scanId: restored.scan_id,
        scannedAt: restored.scanned_at,
      });
    }
  }, [location.state]);

  const runAnalysis = async (event, retryHash) => {
    // ... (Keep your existing runAnalysis logic exactly as it is)
    event.preventDefault();
    const hashValue = (retryHash || hash).trim();
    if (!hashValue) {
      setState({ type: "error", message: "Enter a hash before running analysis." });
      return;
    }
    setLoading(true);
    setResult(null);
    setMetadata({});
    setSubmittedHash(hashValue);
    setState({ type: "idle", message: "" });
    try {
      const response = await analyzeHash(hashValue, { headers: { "x-guest-mode": isGuest ? "true" : "false" } });
      const analysis = response.data?.result || response.data;
      const responseMetadata = {
        hashType: response.data?.hash_type || analysis?.hash_type || analysis?.indicator_type,
        scanId: response.data?.scan_id || analysis?.scan_id,
        scannedAt: response.data?.scanned_at || analysis?.scanned_at,
      };
      if (analysis?.status === "not_found") {
        setState({ type: "not_found", message: "" });
        setMetadata(responseMetadata);
        return;
      }
      if (analysis?.status === "rate_limited") {
        setState({ type: "rate_limited", message: "The intelligence provider rate limit was reached. Try again later." });
        setMetadata(responseMetadata);
        return;
      }
      if (analysis?.status === "error") {
        setState({ type: "error", message: "The backend returned an analysis error status." });
        setMetadata(responseMetadata);
        return;
      }
      setMetadata(responseMetadata);
      setResult(analysis);
    } catch (error) {
      const status = error.response?.status;
      const detail = error.response?.data?.detail;
      if (status === 404) {
        setState({ type: "not_found", message: "" });
        return;
      }
      if (status === 429) {
        setState({ type: "rate_limited", message: detail || "The request was rate limited. Try again later." });
        return;
      }
      setState({ type: "error", message: detail || error.message || "Hash analysis failed." });
    } finally {
      setLoading(false);
    }
  };

  const retry = () => {
    if (submittedHash) {
      runAnalysis({ preventDefault: () => { } }, submittedHash);
    }
  };

  const basicProperties = result
    ? [
      { label: "Hash", value: submittedHash || result?.indicator },
      { label: "Hash Type", value: metadata.hashType },
      { label: "Meaningful Name", value: result?.meaningful_name },
      { label: "Associated Names", value: Array.isArray(result?.associated_names) ? result.associated_names.join(", ") : result?.associated_names },
      { label: "File Type", value: result?.file_type },
      { label: "File Size", value: result?.file_size },
    ]
    : [];

  return (
    <div className="min-h-screen w-full bg-[#07090e] px-10 py-8 text-slate-100">
      <div className="w-full space-y-10 pb-12">
        <header className="flex flex-col gap-2 border-b border-slate-800/80 pb-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center rounded-md bg-purple-500/10 px-2 py-0.5 text-xs font-bold tracking-wider text-purple-400 border border-purple-500/20">
                SHADOW SOC CONSOLE
              </span>
            </div>
            <h1 className="mt-3 text-3xl font-bold tracking-tight text-white">Hash Analysis</h1>
            <p className="mt-2 text-sm text-slate-400">
              Query SHADOW Threat Intelligence database for legacy and active file signatures.
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-400 bg-[#0d1017] px-4 py-2 rounded-lg border border-slate-800/80">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            <span>Pipeline Status: <strong className="text-emerald-400 font-medium">Operational</strong></span>
          </div>
        </header>

        <form onSubmit={runAnalysis} className="rounded-2xl border border-slate-800/80 bg-[#0d1017] p-8 shadow-xl">
          <div className="flex items-center justify-between">
            <label htmlFor="hash-input" className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <KeyRound className="h-5 w-5 text-purple-400" />
              Cryptographic Hash
            </label>
            <span className="text-xs text-slate-500">Supports MD5, SHA1, SHA256</span>
          </div>
          <div className="mt-4 flex flex-col gap-4 sm:flex-row">
            <input
              id="hash-input"
              value={hash}
              onChange={(event) => {
                setHash(event.target.value);
                setState({ type: "idle", message: "" });
              }}
              placeholder="Paste MD5, SHA1, or SHA256 string..."
              className="h-12 flex-1 rounded-xl border border-slate-800 bg-[#07090e] px-4 font-mono text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
            />
            <button
              type="submit"
              disabled={loading || !hash.trim()}
              className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-purple-600 px-8 text-sm font-semibold text-white transition hover:bg-purple-500 shadow-lg shadow-purple-600/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Search className="h-5 w-5" />
              {loading ? "Analyzing..." : "Query Hash"}
            </button>
          </div>
        </form>

        {/* ... (Keep Loading, Error, NotFound states exact same) */}
        {loading && <LoadingState />}
        {!loading && state.type === "not_found" && <NotFoundState hash={submittedHash} />}
        {!loading && state.type === "rate_limited" && <ErrorState title="Rate Limited" message={state.message} onRetry={retry} />}
        {!loading && state.type === "error" && <ErrorState title="Unable to analyze hash" message={state.message} onRetry={submittedHash ? retry : undefined} />}

        {!loading && result && (
          <AnalysisResult
            result={result}
            title="Hash Intelligence Report"
            indicatorLabel="Hash"
            indicatorValue={submittedHash}
            indicatorType={metadata.hashType}
            scanId={metadata.scanId}
            scannedAt={metadata.scannedAt}
            showScanId={Boolean(user)}
            basicProperties={basicProperties}
          />
        )}
      </div>
    </div>
  );
}

export default HashAnalysis;