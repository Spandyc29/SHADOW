import { Globe, Search, ShieldCheck } from "lucide-react";
import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import AnalysisResult from "../components/analysis/AnalysisResult";
import ErrorState from "../components/analysis/common/ErrorState";
import LoadingState from "../components/analysis/common/LoadingState";
import { badgeClass, formatCountry } from "../components/analysis/common/display";

import { useAuth } from "../context/AuthContext";
import { analyzeDomain } from "../services/domainApi";

function DomainAnalysis() {
  const location = useLocation();
  const [domainInput, setDomainInput] = useState("");
  const [submittedDomain, setSubmittedDomain] = useState("");
  const [result, setResult] = useState(null);
  const [metadata, setMetadata] = useState({});
  const [loading, setLoading] = useState(false);
  const [state, setState] = useState({ type: "idle", message: "" });
  const { isGuest, user } = useAuth();

  useEffect(() => {
    const restored = location.state?.result || location.state?.analysisResult;
    if (restored && !result) {
      setResult(restored);
      const restoredDomain = restored.indicator || restored.domain || "";
      setSubmittedDomain(restoredDomain);
      setDomainInput(restoredDomain);
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
    if (submittedDomain) {
      runAnalysis({ preventDefault: () => {} }, submittedDomain);
    }
  };

  const runAnalysis = async (event, retryDomain) => {
    if (event) event.preventDefault();

    const domainValue = (retryDomain || domainInput).trim();

    if (!domainValue) {
      setState({ type: "error", message: "Enter a domain before running analysis." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setSubmittedDomain(domainValue);
    setState({ type: "idle", message: "" });

    try {
      const response = await analyzeDomain(domainValue, requestConfig);
      const analysis = response.data?.result || response.data;
      const normalizedDomain = response.data?.domain || analysis?.domain || analysis?.indicator || domainValue;

      setMetadata({
        scanId: response.data?.scan_id || analysis?.scan_id,
        scannedAt: response.data?.scanned_at || analysis?.scanned_at,
        normalizedDomain,
      });
      setResult(analysis);
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "Domain analysis failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const whois = result?.whois_info || {};

  const reputationLabel = result?.reputation_label || result?.community_reputation_label || "Not Available";
  const dnssecStatus = whois.dnssec || "Unsigned";

  const basicProperties = result
    ? [
        { label: "Domain", value: metadata.normalizedDomain || result?.indicator },
        { label: "Registrar", value: whois.registrar },
        { label: "Organization", value: whois.org },
        { label: "Country", value: formatCountry(whois.country) },
        { label: "Creation Date", value: whois.creation_date },
        { label: "Updated Date", value: whois.updated_date },
        { label: "Expiration Date", value: whois.expiration_date },
        { label: "Domain Age", value: whois.domain_age },
        { label: "Time to Expiration", value: whois.remaining_time },
        {
          label: "Reputation Label",
          value: reputationLabel,
          isBadge: true,
          badgeClass: badgeClass(reputationLabel),
        },
        {
          label: "DNSSEC",
          value: dnssecStatus,
          isBadge: true,
          badgeClass: dnssecStatus === "Signed" ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-300" : "border-slate-500/50 bg-slate-700/50 text-slate-300",
        },
        { label: "Name Servers", value: whois.name_servers },
        { label: "Status", value: whois.status },
      ]
    : [];

  return (
    <div className="min-h-screen w-full bg-[#07090e] px-6 sm:px-10 py-8 text-slate-100">
      <div className="w-full space-y-8 pb-12">
        <header className="flex flex-col gap-3 border-b border-slate-800/80 pb-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center rounded-md bg-purple-500/10 px-2.5 py-0.5 text-xs font-bold tracking-wider text-purple-400 border border-purple-500/20">
                SHADOW SOC CONSOLE
              </span>
            </div>
            <h1 className="mt-3 text-4xl font-extrabold tracking-tight text-white flex items-center gap-3">
              <span>Domain Intelligence</span>
            </h1>
            <p className="mt-2 text-base text-slate-400">
              Perform WHOIS, DNS resolution, and threat intelligence analysis on domain names.
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-400 bg-[#0d1017] px-4 py-2.5 rounded-xl border border-slate-800/80 shadow-sm">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            <span>Pipeline Status: <strong className="text-emerald-400 font-medium">Operational</strong></span>
          </div>
        </header>

        <form onSubmit={runAnalysis} className="rounded-2xl border border-slate-800/80 bg-[#0d1017] p-6 sm:p-8 shadow-xl">
          <div className="flex items-center justify-between">
            <label htmlFor="domain-input" className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <Globe className="h-5 w-5 text-purple-400" />
              Domain Name
            </label>
            <span className="text-xs text-slate-500">e.g. google.com, example.org</span>
          </div>
          <div className="mt-4 flex flex-col gap-4 sm:flex-row">
            <input
              id="domain-input"
              value={domainInput}
              onChange={(event) => {
                setDomainInput(event.target.value);
                resetResult();
              }}
              placeholder="example.com"
              className="h-12 flex-1 rounded-xl border border-slate-800 bg-[#07090e] px-4 font-mono text-base text-white outline-none transition placeholder:text-slate-600 focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
            />
            <button
              type="submit"
              disabled={loading || !domainInput.trim()}
              className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-purple-600 px-8 text-sm font-semibold text-white transition hover:bg-purple-500 shadow-lg shadow-purple-600/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Search className="h-5 w-5" />
              {loading ? "Analyzing..." : "Analyze Domain"}
            </button>
          </div>
        </form>

        {loading && <LoadingState />}
        {!loading && state.type === "rate_limited" && <ErrorState title="Rate Limited" message={state.message} onRetry={retry} />}
        {!loading && state.type === "error" && <ErrorState title="Unable to analyze Domain" message={state.message} onRetry={submittedDomain ? retry : undefined} />}

        {!loading && result && (
          <AnalysisResult
            result={result}
            title="Domain Intelligence Report"
            indicatorLabel="Domain"
            indicatorValue={metadata.normalizedDomain || submittedDomain}
            indicatorType="Domain"
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

export default DomainAnalysis;
