import { AlertTriangle, ArrowLeft, Check, Copy, Download, FileText, HelpCircle, Loader2, RotateCcw, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { renderReport } from "../../../services/api";
import { badgeClass, formatTimestamp, present, progressWidth, riskProgressClass } from "./display";

function SegmentedBar({ totalSegments = 4, activeSegments = 1, activeColor = "bg-emerald-400" }) {
  return (
    <div className="flex gap-2 mt-3">
      {Array.from({ length: totalSegments }).map((_, idx) => (
        <div
          key={idx}
          className={`h-2.5 flex-1 rounded-md transition-colors ${
            idx < activeSegments ? activeColor : "bg-slate-800/90"
          }`}
        />
      ))}
    </div>
  );
}

function getSeveritySegments(severityStr) {
  const norm = String(severityStr || "").toLowerCase();
  if (norm.includes("critical")) return { count: 4, color: "bg-red-500" };
  if (norm.includes("high")) return { count: 3, color: "bg-red-400" };
  if (norm.includes("medium")) return { count: 2, color: "bg-amber-400" };
  if (norm.includes("low") || norm.includes("none")) return { count: 1, color: "bg-emerald-400" };
  return { count: 0, color: "bg-slate-700" };
}

function getConfidenceSegments(confidenceStr) {
  const norm = String(confidenceStr || "").toLowerCase();
  if (norm.includes("high") || norm.includes("strong")) return { count: 3, color: "bg-blue-400" };
  if (norm.includes("medium") || norm.includes("moderate")) return { count: 2, color: "bg-blue-400" };
  if (norm.includes("low")) return { count: 1, color: "bg-slate-500" };
  return { count: 1, color: "bg-slate-600" };
}

function getVerdictIcon(verdictStr) {
  const norm = String(verdictStr || "").toLowerCase();
  if (norm.includes("clean") || norm.includes("safe")) return <ShieldCheck className="h-7 w-7 text-emerald-400" />;
  if (norm.includes("malicious") || norm.includes("critical")) return <ShieldAlert className="h-7 w-7 text-red-400" />;
  if (norm.includes("suspicious")) return <AlertTriangle className="h-7 w-7 text-amber-400" />;
  return <HelpCircle className="h-7 w-7 text-blue-400" />;
}

function getVerdictBorderClass(verdictStr) {
  const norm = String(verdictStr || "").toLowerCase();
  if (norm.includes("clean") || norm.includes("safe")) return "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
  if (norm.includes("malicious") || norm.includes("critical")) return "border-red-500/40 bg-red-500/10 text-red-400";
  if (norm.includes("suspicious")) return "border-amber-500/40 bg-amber-500/10 text-amber-400";
  return "border-blue-500/40 bg-blue-500/10 text-blue-400";
}

function getVerdictTextColor(verdictStr) {
  const norm = String(verdictStr || "").toLowerCase();
  if (norm.includes("clean") || norm.includes("safe")) return "text-emerald-400";
  if (norm.includes("malicious") || norm.includes("critical")) return "text-red-400";
  if (norm.includes("suspicious")) return "text-amber-400";
  return "text-blue-400";
}

function getVerdictExplanation(verdictStr) {
  const norm = String(verdictStr || "").toLowerCase();
  if (norm.includes("clean") || norm.includes("safe")) return "No threat activity detected across security engines.";
  if (norm.includes("malicious")) return "Malicious threat confirmed across security engines.";
  if (norm.includes("suspicious")) return "This file / indicator exhibits suspicious characteristics.";
  return "Insufficient indicators to determine threat level.";
}

function getLeftAccentBorderClass(verdictStr) {
  const norm = String(verdictStr || "").toLowerCase();
  if (norm.includes("clean") || norm.includes("safe")) return "border-l-emerald-500";
  if (norm.includes("malicious") || norm.includes("critical")) return "border-l-red-500";
  if (norm.includes("suspicious")) return "border-l-amber-500";
  return "border-l-blue-500";
}

function ResultHeader({
  result,
  title = "Investigation Report",
  indicatorLabel = "Indicator",
  indicatorValue,
  indicatorType,
  scanId,
  scannedAt,
  showScanId,
  onBack,
  onNewScan,
}) {
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);
  const [copiedScan, setCopiedScan] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const value = indicatorValue || result?.indicator;

  const copyValue = async (copyText, setter) => {
    if (!copyText) return;
    await navigator.clipboard.writeText(copyText);
    setter(true);
    window.setTimeout(() => setter(false), 1600);
  };

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${title.replace(/\s+/g, "_").toLowerCase()}_report.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleGenerateReport = async () => {
    if (!result) return;
    setGeneratingReport(true);
    try {
      const response = await renderReport(result, "html");
      const htmlContent = response.data;
      navigate("/report-preview", {
        state: {
          htmlContent,
          analysisResult: result,
          returnPath: window.location.pathname,
        },
      });
    } catch (err) {
      console.error("Report rendering error:", err);
      navigate("/report-preview", {
        state: {
          error: err.response?.data?.detail || err.message || "Unable to generate report.",
          analysisResult: result,
          returnPath: window.location.pathname,
        },
      });
    } finally {
      setGeneratingReport(false);
    }
  };

  const verdict = result?.verdict || "CLEAN";
  const severity = result?.severity || "LOW";
  const confidence = result?.confidence || "HIGH";

  const sevSegs = getSeveritySegments(severity);
  const confSegs = getConfidenceSegments(confidence);

  const riskScore = result?.risk_score ?? 0;
  const confidenceScore = result?.confidence_score ?? 80;
  const detections = result?.detections ?? 0;
  const usableEngines = result?.usable_engines ?? result?.total_engines ?? 75;

  return (
    <div className="w-full flex flex-col gap-6">
      {/* BREADCRUMB & HEADER BAR */}
      <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between pb-3 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 tracking-wider uppercase mb-2">
            {onBack ? (
              <button
                type="button"
                onClick={onBack}
                className="inline-flex items-center gap-1.5 text-slate-400 transition hover:text-white"
              >
                <ArrowLeft className="h-4 w-4" />
                Upload Scan
              </button>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-slate-400">
                <ArrowLeft className="h-4 w-4" />
                Scan History
              </span>
            )}
            <span className="text-slate-600">&gt;</span>
            <span className="font-extrabold text-purple-400">Result</span>
          </div>

          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">{title}</h1>
          <p className="mt-2 text-sm text-slate-400 font-medium">Deterministic threat analysis powered by SHADOW Analysis Pipeline.</p>
        </div>

        {/* TOOLBAR BUTTONS */}
        <div className="flex items-center gap-3 shrink-0 flex-wrap sm:flex-nowrap">
          {/* BUTTON 1: EXPORT REPORT */}
          <button
            type="button"
            onClick={handleExport}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-slate-700/80 bg-[#120f24] px-5 py-2.5 text-xs sm:text-sm font-extrabold text-slate-200 whitespace-nowrap shrink-0 transition hover:border-purple-500/60 hover:bg-[#1a1633] hover:text-white shadow-sm"
          >
            <Download className="h-4 w-4 shrink-0 text-purple-400" />
            <span className="whitespace-nowrap">Export Report</span>
          </button>

          {/* BUTTON 2: GENERATE REPORT */}
          <button
            type="button"
            onClick={handleGenerateReport}
            disabled={generatingReport}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-slate-700/80 bg-[#120f24] px-5 py-2.5 text-xs sm:text-sm font-extrabold text-slate-200 whitespace-nowrap shrink-0 transition hover:border-purple-500/60 hover:bg-[#1a1633] hover:text-white shadow-sm disabled:cursor-not-allowed disabled:opacity-50"
          >
            {generatingReport ? (
              <>
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-purple-400" />
                <span className="whitespace-nowrap">Generating...</span>
              </>
            ) : (
              <>
                <FileText className="h-4 w-4 shrink-0 text-purple-400" />
                <span className="whitespace-nowrap">Generate Report</span>
              </>
            )}
          </button>

          {/* BUTTON 3: NEW SCAN */}
          {onNewScan && (
            <button
              type="button"
              onClick={onNewScan}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-xl bg-purple-600 hover:bg-purple-500 px-5 py-2.5 text-xs sm:text-sm font-extrabold text-white whitespace-nowrap shrink-0 transition shadow-md shadow-purple-950/40"
            >
              <RotateCcw className="h-4 w-4 shrink-0" />
              <span className="whitespace-nowrap">New Scan</span>
            </button>
          )}
        </div>
      </div>

      {/* UNIFIED HEADER SUMMARY CARD */}
      <section className={`analysis-card rounded-2xl border border-slate-800/80 border-l-[5px] ${getLeftAccentBorderClass(verdict)} bg-[#0c0a18] shadow-xl`}>
        <div className="grid gap-5 grid-cols-2 md:grid-cols-3 xl:grid-cols-6 divide-y md:divide-y-0 md:divide-x divide-slate-800/80">
          {/* 1. VERDICT */}
          <div className="flex flex-col justify-between min-w-0 md:pr-4 xl:pr-5 max-md:pb-4">
            <p className="text-[11px] font-extrabold uppercase tracking-widest text-slate-400 mb-1">VERDICT</p>
            <div className="flex items-center gap-2.5 my-1.5 min-w-0">
              <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border ${getVerdictBorderClass(verdict)}`}>
                {getVerdictIcon(verdict)}
              </div>
              <p className={`text-sm sm:text-base xl:text-lg font-black uppercase tracking-wider whitespace-nowrap ${getVerdictTextColor(verdict)}`}>
                {present(verdict)}
              </p>
            </div>
            <p className="text-[11px] text-slate-400 font-medium leading-relaxed">
              {getVerdictExplanation(verdict)}
            </p>
          </div>

          {/* 2. SEVERITY */}
          <div className="flex flex-col justify-between min-w-0 max-md:pt-4 md:px-4 xl:px-5">
            <p className="text-[11px] font-extrabold uppercase tracking-widest text-slate-400 mb-1">SEVERITY</p>
            <p className={`my-1.5 text-lg sm:text-xl font-black uppercase tracking-wider ${sevSegs.color.replace('bg-', 'text-')}`}>
              {present(severity)}
            </p>
            <SegmentedBar totalSegments={4} activeSegments={sevSegs.count} activeColor={sevSegs.color} />
          </div>

          {/* 3. CONFIDENCE */}
          <div className="flex flex-col justify-between min-w-0 max-md:pt-4 md:px-4 xl:px-5">
            <p className="text-[11px] font-extrabold uppercase tracking-widest text-slate-400 mb-1">CONFIDENCE</p>
            <p className="my-1.5 text-lg sm:text-xl font-black uppercase tracking-wider text-blue-400">
              {present(confidence)}
            </p>
            <SegmentedBar totalSegments={3} activeSegments={confSegs.count} activeColor={confSegs.color} />
          </div>

          {/* 4. RISK SCORE */}
          <div className="flex flex-col justify-between min-w-0 max-md:pt-4 md:px-4 xl:px-5">
            <p className="text-[11px] font-extrabold uppercase tracking-widest text-slate-400 mb-1">RISK SCORE</p>
            <p className="my-1.5 text-2xl sm:text-3xl font-black tracking-tight text-white flex items-baseline">
              <span className={riskScore > 40 ? "text-red-400" : riskScore > 15 ? "text-amber-400" : "text-emerald-400"}>
                {present(riskScore)}
              </span>
              <span className="text-slate-400/90 text-base sm:text-lg font-extrabold ml-1.5">/ 90</span>
            </p>
            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800/90">
              <div
                className={`h-full rounded-full transition-all duration-700 ease-out ${riskProgressClass(verdict || severity)}`}
                style={{ width: progressWidth(riskScore, 90) }}
              />
            </div>
          </div>

          {/* 5. CONFIDENCE SCORE */}
          <div className="flex flex-col justify-between min-w-0 max-md:pt-4 md:px-4 xl:px-5">
            <p className="text-[11px] font-extrabold uppercase tracking-widest text-slate-400 mb-1">CONFIDENCE SCORE</p>
            <p className="my-1.5 text-2xl sm:text-3xl font-black tracking-tight text-white flex items-baseline">
              <span className="text-blue-400">{present(confidenceScore)}</span>
              <span className="text-slate-400/90 text-base sm:text-lg font-extrabold ml-1.5">/ 100</span>
            </p>
            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800/90">
              <div
                className="h-full rounded-full bg-blue-500 transition-all duration-700 ease-out"
                style={{ width: progressWidth(confidenceScore, 100) }}
              />
            </div>
          </div>

          {/* 6. DETECTION */}
          <div className="flex flex-col justify-between min-w-0 max-md:pt-4 md:pl-4 xl:pl-5">
            <p className="text-[11px] font-extrabold uppercase tracking-widest text-slate-400 mb-1">DETECTION</p>
            <p className="my-1.5 text-2xl sm:text-3xl font-black tracking-tight text-white flex items-baseline">
              <span className={detections > 0 ? "text-red-400" : "text-emerald-400"}>
                {present(detections)}
              </span>
              <span className="text-slate-400/90 text-base sm:text-lg font-extrabold ml-1.5">/ {usableEngines}</span>
            </p>
            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800/90">
              <div
                className={`h-full rounded-full transition-all duration-700 ease-out ${
                  detections > 0 ? "bg-red-500" : "bg-purple-500"
                }`}
                style={{ width: progressWidth(detections, usableEngines) }}
              />
            </div>
          </div>
        </div>
      </section>

      {/* IDENTIFIER BAR */}
      <section className="analysis-card flex flex-wrap items-center gap-6 rounded-2xl border border-slate-800/80 bg-[#0c0a18] shadow-xl lg:flex-nowrap">
        {/* HASH / INDICATOR */}
        <div className="flex-1 min-w-[300px]">
          <p className="mb-2 text-xs font-extrabold uppercase tracking-widest text-slate-400">
            {indicatorLabel} {indicatorType ? `(${present(indicatorType).toUpperCase()})` : ""}
          </p>
          <div className="value-box flex h-11 items-center justify-between gap-3.5 rounded-xl border border-slate-800 bg-[#06040b] transition-colors focus-within:border-purple-500/60">
            <p className="truncate font-mono text-xs sm:text-sm text-purple-300 font-medium">{present(value)}</p>
            <button
              type="button"
              onClick={() => copyValue(value, setCopied)}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition hover:bg-purple-500/20 hover:text-purple-300"
              title={`Copy ${indicatorLabel.toLowerCase()}`}
            >
              {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* SCAN ID */}
        {showScanId && scanId && (
          <div className="flex-1 min-w-[300px]">
            <p className="mb-2 text-xs font-extrabold uppercase tracking-widest text-slate-400">SCAN ID</p>
            <div className="value-box flex h-11 items-center justify-between gap-3.5 rounded-xl border border-slate-800 bg-[#06040b] transition-colors focus-within:border-purple-500/60">
              <p className="truncate font-mono text-xs sm:text-sm text-slate-300 font-medium">{scanId}</p>
              <button
                type="button"
                onClick={() => copyValue(scanId, setCopiedScan)}
                className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition hover:bg-purple-500/20 hover:text-purple-300"
                title="Copy scan ID"
              >
                {copiedScan ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
              </button>
            </div>
          </div>
        )}

        {/* DATES */}
        <div className="flex gap-10 sm:w-auto px-2">
          <div>
            <p className="mb-2 text-xs font-extrabold uppercase tracking-widest text-slate-400">FIRST SEEN</p>
            <p className="text-xs sm:text-sm font-bold text-slate-200">
              {formatTimestamp(result?.first_seen || scannedAt)}
            </p>
          </div>
          <div>
            <p className="mb-2 text-xs font-extrabold uppercase tracking-widest text-slate-400">LAST ANALYSIS</p>
            <p className="text-xs sm:text-sm font-bold text-slate-200">
              {formatTimestamp(result?.last_analysis || scannedAt)}
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

export default ResultHeader;
