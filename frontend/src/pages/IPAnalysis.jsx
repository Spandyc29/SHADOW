import { Network, Search, ShieldCheck } from "lucide-react";
import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import AnalysisResult from "../components/analysis/AnalysisResult";
import ErrorState from "../components/analysis/common/ErrorState";
import LoadingState from "../components/analysis/common/LoadingState";
import { badgeClass, formatCountry } from "../components/analysis/common/display";

import { useAuth } from "../context/AuthContext";
import { analyzeIp } from "../services/ipApi";

function IPAnalysis() {
  const location = useLocation();
  const [ipInput, setIpInput] = useState("");
  const [submittedIp, setSubmittedIp] = useState("");
  const [result, setResult] = useState(null);
  const [metadata, setMetadata] = useState({});
  const [loading, setLoading] = useState(false);
  const [state, setState] = useState({ type: "idle", message: "" });
  const { isGuest, user } = useAuth();

  useEffect(() => {
    const restored = location.state?.result || location.state?.analysisResult;
    if (restored && !result) {
      setResult(restored);
      const restoredIp = restored.indicator || restored.ip || "";
      setSubmittedIp(restoredIp);
      setIpInput(restoredIp);
      setMetadata({
        scanId: restored.scan_id,
        scannedAt: restored.scanned_at,
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
    if (submittedIp) {
      runAnalysis({ preventDefault: () => {} }, submittedIp);
    }
  };

  const runAnalysis = async (event, retryIp) => {
    if (event) event.preventDefault();

    const ipValue = (retryIp || ipInput).trim();

    if (!ipValue) {
      setState({ type: "error", message: "Enter an IP address before running analysis." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setSubmittedIp(ipValue);
    setState({ type: "idle", message: "" });

    try {
      const response = await analyzeIp(ipValue, requestConfig);
      const analysis = response.data?.result || response.data;
      const normalizedIp = response.data?.ip || analysis?.ip || analysis?.indicator || ipValue;

      setMetadata({
        scanId: response.data?.scan_id || analysis?.scan_id,
        scannedAt: response.data?.scanned_at || analysis?.scanned_at,
        normalizedIp,
      });
      setResult(analysis);
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "IP analysis failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const ipInfo = result?.ip_info || {};
  const reputationLabel = result?.reputation_label || result?.community_reputation_label || "Not Available";

  const basicProperties = result
    ? [
        { label: "IP Address", value: metadata.normalizedIp || result?.indicator },
        { label: "IP Version", value: ipInfo.version },
        { label: "ASN", value: ipInfo.asn },
        { label: "AS Owner", value: ipInfo.as_owner },
        { label: "Country", value: formatCountry(ipInfo.country) },
        { label: "Network", value: ipInfo.network },
        { label: "Reverse DNS", value: ipInfo.reverse_dns },
        {
          label: "Reputation Label",
          value: reputationLabel,
          isBadge: true,
          badgeClass: badgeClass(reputationLabel),
        },
      ]
    : [];

  return (
    <div className="min-h-screen w-full bg-[#07090e] px-6 sm:px-10 py-8 text-slate-100">
      <div className="w-full space-y-8 pb-12">
        <header className="flex flex-col gap-3 border-b border-slate-800/80 pb-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center rounded-md bg-cyan-500/10 px-2.5 py-0.5 text-xs font-bold tracking-wider text-cyan-400 border border-cyan-500/20">
                SHADOW SOC CONSOLE
              </span>
            </div>
            <h1 className="mt-3 text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
              <span>IP Intelligence</span>
            </h1>
            <p className="mt-2 text-base text-slate-400">
              Perform reverse DNS, ASN/geolocation extraction, and threat intelligence analysis on IPv4 and IPv6 addresses.
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-400 bg-[#0d1017] px-4 py-2.5 rounded-xl border border-slate-800/80 shadow-sm">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            <span>Pipeline Status: <strong className="text-emerald-400 font-medium">Operational</strong></span>
          </div>
        </header>

        <form onSubmit={runAnalysis} className="rounded-2xl border border-slate-800/80 bg-[#0d1017] p-6 sm:p-8 shadow-xl">
          <div className="flex items-center justify-between">
            <label htmlFor="ip-input" className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <Network className="h-5 w-5 text-cyan-400" />
              IP Address
            </label>
            <span className="text-xs text-slate-500">e.g. 8.8.8.8, 1.1.1.1, 2001:4860:4860::8888</span>
          </div>
          <div className="mt-4 flex flex-col gap-4 sm:flex-row">
            <input
              id="ip-input"
              value={ipInput}
              onChange={(event) => {
                setIpInput(event.target.value);
                resetResult();
              }}
              placeholder="8.8.8.8"
              className="h-12 flex-1 rounded-xl border border-slate-800 bg-[#07090e] px-4 font-mono text-base text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            />
            <button
              type="submit"
              disabled={loading || !ipInput.trim()}
              className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-cyan-600 px-8 text-sm font-semibold text-white transition hover:bg-cyan-500 shadow-lg shadow-cyan-600/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Search className="h-5 w-5" />
              {loading ? "Analyzing..." : "Analyze IP"}
            </button>
          </div>
        </form>

        {loading && <LoadingState />}
        {!loading && state.type === "rate_limited" && <ErrorState title="Rate Limited" message={state.message} onRetry={retry} />}
        {!loading && state.type === "error" && <ErrorState title="Unable to analyze IP Address" message={state.message} onRetry={submittedIp ? retry : undefined} />}

        {!loading && result && (
          <AnalysisResult
            result={result}
            title="IP Intelligence Report"
            indicatorLabel="IP"
            indicatorValue={metadata.normalizedIp || submittedIp}
            indicatorType="IP"
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

export default IPAnalysis;
