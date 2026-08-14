import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { Link2, Search, ShieldCheck } from "lucide-react";
import AnalysisResult from "../components/analysis/AnalysisResult";
import ErrorState from "../components/analysis/common/ErrorState";
import LoadingState from "../components/analysis/common/LoadingState";

import { useAuth } from "../context/AuthContext";
import { analyzeUrl } from "../services/urlApi";

function URLAnalysis() {
  const location = useLocation();
  const [url, setUrl] = useState("");
  const [submittedUrl, setSubmittedUrl] = useState("");
  const [result, setResult] = useState(null);
  const [metadata, setMetadata] = useState({});
  const [loading, setLoading] = useState(false);
  const [state, setState] = useState({ type: "idle", message: "" });
  const { isGuest, user } = useAuth();

  useEffect(() => {
    const restored = location.state?.result || location.state?.analysisResult;
    if (restored && !result) {
      setResult(restored);
      const restoredUrl = restored.indicator || restored.url || "";
      setSubmittedUrl(restoredUrl);
      setUrl(restoredUrl);
      setMetadata({
        scanId: restored.scan_id,
        scannedAt: restored.scanned_at,
        normalizedUrl: restoredUrl,
      });
    }
  }, [location.state]);

  const requestConfig = {
    headers: {
      "x-guest-mode": isGuest ? "true" : "false",
    },
  };

  const resetResult = () => {
    setResult(null);
    setMetadata({});
    setState({ type: "idle", message: "" });
  };

  const retry = () => {
    if (submittedUrl) {
      runAnalysis({ preventDefault: () => {} }, submittedUrl);
    }
  };

  const runAnalysis = async (event, retryUrl) => {
    event.preventDefault();

    const urlValue = (retryUrl || url).trim();

    if (!urlValue) {
      setState({ type: "error", message: "Enter a URL before running analysis." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setSubmittedUrl(urlValue);
    setState({ type: "idle", message: "" });

    try {
      const response = await analyzeUrl(urlValue, requestConfig);
      const analysis = response.data?.result || response.data;
      const normalizedUrl = response.data?.url || analysis?.url || analysis?.indicator || urlValue;

      setMetadata({
        scanId: response.data?.scan_id || analysis?.scan_id,
        scannedAt: response.data?.scanned_at || analysis?.scanned_at,
        normalizedUrl,
      });
      setResult(analysis);
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "URL analysis failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const urlInfo = result?.url_info || {};
  const basicProperties = result
    ? [
        { label: "URL", value: metadata.normalizedUrl || result?.indicator },
        { label: "Protocol", value: urlInfo.protocol },
        { label: "Host", value: urlInfo.host },
        { label: "Domain", value: urlInfo.domain },
        { label: "Path", value: urlInfo.path },
        { label: "Query", value: urlInfo.query },
        { label: "Fragment", value: urlInfo.fragment },
        { label: "Port", value: urlInfo.port },
        { label: "URL Length", value: urlInfo.url_length },
        { label: "Community Reputation", value: result?.community_reputation },
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
            <h1 className="mt-3 text-3xl font-bold tracking-tight text-white">URL Analysis</h1>
            <p className="mt-2 text-sm text-slate-400">
              Query SHADOW Threat Intelligence for suspicious links and web indicators.
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-400 bg-[#0d1017] px-4 py-2 rounded-lg border border-slate-800/80">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            <span>Pipeline Status: <strong className="text-emerald-400 font-medium">Operational</strong></span>
          </div>
        </header>

        <form onSubmit={runAnalysis} className="rounded-2xl border border-slate-800/80 bg-[#0d1017] p-8 shadow-xl">
          <div className="flex items-center justify-between">
            <label htmlFor="url-input" className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <Link2 className="h-5 w-5 text-purple-400" />
              URL
            </label>
            <span className="text-xs text-slate-500">HTTP and HTTPS URLs</span>
          </div>
          <div className="mt-4 flex flex-col gap-4 sm:flex-row">
            <input
              id="url-input"
              value={url}
              onChange={(event) => {
                setUrl(event.target.value);
                resetResult();
              }}
              placeholder="https://example.com/login"
              className="h-12 flex-1 rounded-xl border border-slate-800 bg-[#07090e] px-4 font-mono text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-purple-600 px-8 text-sm font-semibold text-white transition hover:bg-purple-500 shadow-lg shadow-purple-600/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Search className="h-5 w-5" />
              {loading ? "Analyzing..." : "Analyze URL"}
            </button>
          </div>
        </form>

        {loading && <LoadingState />}
        {!loading && state.type === "rate_limited" && <ErrorState title="Rate Limited" message={state.message} onRetry={retry} />}
        {!loading && state.type === "error" && <ErrorState title="Unable to analyze URL" message={state.message} onRetry={submittedUrl ? retry : undefined} />}

        {!loading && result && (
          <AnalysisResult
            result={result}
            title="URL Intelligence Report"
            indicatorLabel="URL"
            indicatorValue={metadata.normalizedUrl || submittedUrl}
            indicatorType="URL"
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

export default URLAnalysis;
