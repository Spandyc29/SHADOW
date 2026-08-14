import { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Printer,
  AlertTriangle,
  RotateCcw,
  Loader2,
  Edit3,
  Check,
  RefreshCw,
  Copy,
  CheckCircle2,
  ChevronDown,
  Shield,
  AlertOctagon,
  Activity,
  Award,
  FileText,
} from "lucide-react";
import { renderReport } from "../services/api";
import { useScanContext } from "../context/ScanContext";
import { normalizeScanContext } from "../utils/scanContextAdapter";
import "../styles/report-preview.css";

function isValueEmpty(val) {
  if (val === null || val === undefined) return true;
  const s = String(val).trim().toLowerCase();
  return (
    s === "" ||
    s === "n/a" ||
    s === "not available" ||
    s === "not applicable" ||
    s === "none" ||
    s === "null" ||
    s === "[]" ||
    s === "{}"
  );
}

function getReportId(result) {
  if (result?.scan_id) return result.scan_id;
  if (result?.report?.metadata?.report_id) return result.report.metadata.report_id;
  if (result?.id) return result.id;

  const ind = result?.indicator || result?.file_name || result?.url || result?.domain || result?.ip || "target";
  let hash = 0;
  for (let i = 0; i < ind.length; i++) {
    hash = (hash << 5) - hash + ind.charCodeAt(i);
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, "0").slice(0, 8).toUpperCase();
  return `REP-${hex}`;
}

function getDefault5W1H(result) {
  if (!result) return { who: {}, what: {}, where: {}, when: {}, why: {}, how: {}, recommendations: [] };

  const f5 = result.report?.fivew1h || result.fivew1h || {};
  return {
    who: f5.who
      ? { ...f5.who }
      : { target_system: "Submitted Artifact", submitter: "Analyst / Incident Response", affected_entity: "Internal Infrastructure" },
    what: f5.what
      ? { ...f5.what }
      : {
          artifact_name: result.indicator || result.file_name || "Artifact",
          artifact_type: result.indicator_type || "Artifact",
          threat_classification: result.verdict || "clean",
        },
    where: f5.where
      ? { ...f5.where }
      : { target_identifier: result.indicator || "Target", location_path: result.url_info?.path || "N/A" },
    when: f5.when
      ? { ...f5.when }
      : {
          scan_timestamp: new Date().toISOString().slice(0, 19).replace("T", " "),
          analysis_duration: "Instantaneous",
        },
    why: f5.why
      ? { ...f5.why }
      : {
          risk_score: String(result.risk_score || 0),
          risk_level: String(result.risk_level || result.verdict || "LOW").toUpperCase(),
          confidence_score: String(result.confidence_score || 60),
          confidence_level: String(result.confidence_level || "MEDIUM").toUpperCase(),
        },
    how: f5.how
      ? { ...f5.how }
      : { attack_vectors: "Standard Threat Analysis", recommendations: ["Indicator evaluated against SHADOW rules."] },
    recommendations: Array.isArray(f5.how?.recommendations)
      ? [...f5.how.recommendations]
      : ["Indicator appears clean based on available threat intelligence sources.", "Action: No Action Required"],
  };
}

function cleanAndDedupeCategories(rawVal) {
  if (!rawVal || isValueEmpty(rawVal)) return "N/A";

  let items = [];
  if (Array.isArray(rawVal)) {
    items = rawVal.flatMap((item) => (typeof item === "string" ? item.split(",") : String(item).split(",")));
  } else if (typeof rawVal === "object" && rawVal !== null) {
    const cleanObj = rawVal.value || rawVal.name || rawVal.category || rawVal.label || JSON.stringify(rawVal);
    items = String(cleanObj).split(",");
  } else {
    items = String(rawVal).split(",");
  }

  const categoryMap = new Map();

  items.forEach((rawItem) => {
    let str = String(rawItem).trim();
    if (!str || isValueEmpty(str)) return;

    // Strip source attribution in parentheses e.g. "(alphaMountain.ai)", "(VirusTotal)"
    str = str.replace(/\s*\([^)]*\)/g, "").trim();
    if (!str || isValueEmpty(str)) return;

    // Create normalized comparison key for deduplication
    // e.g., "searchengines", "search engines and portals", "Search Engines/Portals" -> "searchengineportal"
    let normKey = str
      .toLowerCase()
      .replace(/\s+and\s+/g, "")
      .replace(/&/g, "")
      .replace(/[\/\-_,.]/g, "")
      .replace(/\s+/g, "");

    if (normKey.length > 5 && normKey.endsWith("s")) {
      normKey = normKey.slice(0, -1);
    }

    if (!normKey) return;

    // Score original string for best display quality
    let score = 0;
    if (/[A-Z]/.test(str)) score += 10;
    if (/\s/.test(str)) score += 10;
    if (/[\/&]/.test(str)) score += 5;
    if (str.length > 3 && str === str.toLowerCase()) score -= 5;

    // Format display title if raw concatenated lowercase e.g. "computersandsoftware" -> "Computers & Software"
    let cleanTitle = str;
    if (!/\s/.test(str) && !/[\/&]/.test(str) && str === str.toLowerCase()) {
      const knownReplacements = {
        computersandsoftware: "Computers & Software",
        searchengines: "Search Engines",
        informationtechnology: "Information Technology",
        businesseconomy: "Business & Economy",
        personalnetworkstorage: "Personal Network Storage",
        filesharing: "File Sharing",
      };
      const lowKey = str.toLowerCase();
      if (knownReplacements[lowKey]) {
        cleanTitle = knownReplacements[lowKey];
      } else {
        // Fallback: capitalize first letter as a single word (prevents broken mid-word splits)
        cleanTitle = str.charAt(0).toUpperCase() + str.slice(1);
      }
    } else {
      // Capitalize words nicely for strings with spaces/slashes
      cleanTitle = cleanTitle
        .split("/")
        .map((part) =>
          part
            .trim()
            .split(" ")
            .map((w) => (w.length > 0 ? w.charAt(0).toUpperCase() + w.slice(1) : ""))
            .join(" ")
        )
        .join(" / ");
    }

    if (!categoryMap.has(normKey) || score > categoryMap.get(normKey).score) {
      categoryMap.set(normKey, { title: cleanTitle, score });
    }
  });

  const resultList = Array.from(categoryMap.values()).map((v) => v.title);
  return resultList.length > 0 ? resultList.join(", ") : String(rawVal);
}

function formatDisplayVal(val, fieldName = "") {
  if (val === null || val === undefined) return "N/A";

  const keyLower = String(fieldName).toLowerCase();
  const isCategoryField =
    keyLower.includes("attack_vector") ||
    keyLower.includes("threat_category") ||
    keyLower.includes("category") ||
    keyLower.includes("threat_tags") ||
    keyLower.includes("threat_classification");

  if (isCategoryField && (typeof val === "string" || Array.isArray(val) || typeof val === "object")) {
    return cleanAndDedupeCategories(val);
  }

  if (typeof val === "string" && (val.includes("(alphaMountain.ai)") || val.includes("(VirusTotal)"))) {
    return cleanAndDedupeCategories(val);
  }

  if (typeof val === "object" && !Array.isArray(val)) {
    // If object contains hashes, format as clean separate labeled lines (BUG 5 FIX)
    if (val.md5 || val.sha1 || val.sha256) {
      const items = [];
      if (val.md5 && !isValueEmpty(val.md5)) items.push(`MD5: ${val.md5}`);
      if (val.sha1 && !isValueEmpty(val.sha1)) items.push(`SHA1: ${val.sha1}`);
      if (val.sha256 && !isValueEmpty(val.sha256)) items.push(`SHA256: ${val.sha256}`);
      return items.length > 0 ? items.join("\n") : "N/A";
    }
    const clean = val.value || val.category || val.name || val.label || val.tag;
    if (clean !== undefined) return String(clean);
    // Generic object formatting into clean key-value pairs
    const entries = Object.entries(val).filter(([_, v]) => !isValueEmpty(v));
    if (entries.length > 0) {
      return entries.map(([k, v]) => `${k.toUpperCase()}: ${formatDisplayVal(v, k)}`).join("\n");
    }
    return "N/A";
  }
  if (typeof val === "string" && val.startsWith("{") && val.endsWith("}")) {
    try {
      const parsed = JSON.parse(val);
      return formatDisplayVal(parsed, fieldName);
    } catch {
      // Return as is if not valid JSON
    }
  }
  if (Array.isArray(val)) {
    return val.map((item) => formatDisplayVal(item, fieldName)).join(", ");
  }
  return String(val);
}

function getExecutiveSummary(result, editedData) {
  const verdict = (result?.verdict || editedData.why?.risk_level || "clean").toLowerCase();
  const ind = result?.indicator || result?.file_name || editedData.what?.artifact_name || "submitted artifact";
  const indType = result?.indicator_type || editedData.what?.artifact_type || "Artifact";

  const rawExec = result?.executive_summary || result?.report?.executive_summary;
  let text = rawExec?.summary_text;

  if (!text) {
    if (verdict.includes("malicious") || verdict.includes("high") || verdict.includes("critical")) {
      text = `Automated threat intelligence analysis identified critical malicious indicators associated with ${indType} (${ind}). High risk score assigned based on multi-engine detection hits and threat signature matches. Immediate containment and SOC response recommended.`;
    } else if (verdict.includes("suspicious") || verdict.includes("medium")) {
      text = `Threat intelligence evaluation flagged suspicious behavioral indicators for ${indType} (${ind}). Moderate risk score assigned. Further SOC analyst review and endpoint monitoring recommended.`;
    } else {
      text = `Deterministic analysis completed for ${indType} (${ind}). No malicious signatures or active threat vectors detected across integrated intelligence databases. Low risk classification assigned.`;
    }
  }

  const findings = rawExec?.key_findings || [
    `Target Evaluated: ${ind} (${indType})`,
    `Verdict Classification: ${verdict.toUpperCase()}`,
    `Risk Assessment: Score ${result?.risk_score || editedData.why?.risk_score || 0}/100`,
    `Multi-Engine Intelligence Confidence: ${result?.confidence_score || editedData.why?.confidence_score || 60}%`,
  ];

  return { text, findings };
}

function getIOCSummary(result) {
  const rawIocs = result?.ioc_summary?.iocs || result?.report?.ioc_summary?.iocs;

  if (Array.isArray(rawIocs) && rawIocs.length > 0) {
    return rawIocs.map((ioc) => {
      const typeUpper = String(ioc.type || "").toUpperCase();
      if (typeUpper === "FILE NAME" || typeUpper === "FILENAME") {
        const isSubmitted = ioc.value === result?.indicator || ioc.value === result?.file_name;
        return {
          ...ioc,
          type: isSubmitted ? "SUBMITTED FILE NAME" : "ASSOCIATED FILENAME (THREAT INTEL)",
        };
      }
      return ioc;
    });
  }

  const iocs = [];
  const ind = result?.indicator || result?.file_name;
  const indType = result?.indicator_type || "Indicator";

  if (ind) {
    const isFile = indType.toLowerCase().includes("file") || indType.toLowerCase().includes("hash");
    const label = isFile ? "SUBMITTED FILE NAME" : indType.toUpperCase();
    iocs.push({ type: label, value: ind, source: "Submitted Target" });
  }

  // Associated names from VT / threat intel (BUG 7 FIX)
  const vtNames = result?.vt_result?.names || result?.names;
  if (Array.isArray(vtNames)) {
    vtNames.forEach((n) => {
      if (n !== ind) {
        iocs.push({ type: "ASSOCIATED FILENAME (THREAT INTEL)", value: n, source: "VirusTotal Threat Intel" });
      }
    });
  }

  const hashes = result?.hashes || result?.vt_result?.hashes;
  if (hashes) {
    if (hashes.md5 && !isValueEmpty(hashes.md5)) iocs.push({ type: "MD5 HASH", value: hashes.md5, source: "Cryptographic Telemetry" });
    if (hashes.sha1 && !isValueEmpty(hashes.sha1)) iocs.push({ type: "SHA1 HASH", value: hashes.sha1, source: "Cryptographic Telemetry" });
    if (hashes.sha256 && !isValueEmpty(hashes.sha256)) iocs.push({ type: "SHA256 HASH", value: hashes.sha256, source: "Cryptographic Telemetry" });
  }

  const ip = result?.ip_info?.ip || result?.ip;
  if (ip && ip !== ind) {
    iocs.push({ type: "IP ADDRESS", value: ip, source: "Network Telemetry" });
  }

  const domain = result?.domain_info?.domain || result?.domain;
  if (domain && domain !== ind) {
    iocs.push({ type: "DOMAIN NAME", value: domain, source: "DNS Telemetry" });
  }

  return iocs;
}

function getTimeline(result) {
  const rawEvents = result?.timeline?.events || result?.report?.timeline?.events;

  if (Array.isArray(rawEvents) && rawEvents.length > 0) {
    return rawEvents;
  }

  const scanTime = result?.scanned_at || result?.created_at || new Date().toISOString().slice(0, 19).replace("T", " ") + " UTC";

  return [
    {
      timestamp: scanTime,
      title: "Artifact Submitted",
      description: `Indicator (${result?.indicator || result?.file_name || "Target"}) received by SHADOW Analysis Pipeline.`,
    },
    {
      timestamp: scanTime,
      title: "Multi-Engine Threat Scan",
      description: "Queried active threat databases, VirusTotal, WHOIS, and DNS registries.",
    },
    {
      timestamp: scanTime,
      title: "5W1H Framework Normalization",
      description: "Mapped target context, location paths, detection timestamps, and severity rationale.",
    },
    {
      timestamp: scanTime,
      title: "Report Finalized",
      description: `Final Verdict: ${String(result?.verdict || "CLEAN").toUpperCase()} • Risk Score: ${result?.risk_score || 0}/100.`,
    },
  ];
}

function getTechnicalSummary(result) {
  const sections = {};
  const rawTech = result?.technical_summary?.details || result?.report?.technical_summary?.details || {};

  // General Info
  const genInfo = {
    indicator_type: result?.indicator_type || rawTech.general_info?.indicator_type,
    file_size_bytes: result?.file_size || result?.file_info?.size || rawTech.general_info?.file_size_bytes,
    mime_type: result?.file_info?.mime_type || rawTech.general_info?.mime_type,
    scan_id: result?.scan_id || rawTech.general_info?.scan_id,
  };
  const cleanGen = Object.fromEntries(Object.entries(genInfo).filter(([_, v]) => !isValueEmpty(v)));
  if (Object.keys(cleanGen).length > 0) sections["General Information"] = cleanGen;

  // Cryptographic Hashes
  const hashes = result?.hashes || result?.vt_result?.hashes || rawTech.hashes || {};
  const cleanHashes = Object.fromEntries(Object.entries(hashes).filter(([_, v]) => !isValueEmpty(v)));
  if (Object.keys(cleanHashes).length > 0) sections["Cryptographic Hashes"] = cleanHashes;

  // Network & Infrastructure
  const netInfo = {
    ip_address: result?.ip_info?.ip || rawTech.network?.ip_address,
    network_asn: result?.ip_info?.asn || rawTech.network?.network_asn,
    isp_provider: result?.ip_info?.isp || rawTech.network?.isp_provider,
    country: result?.ip_info?.country || rawTech.network?.country,
    open_ports: result?.ip_info?.ports || rawTech.network?.open_ports,
  };
  const cleanNet = Object.fromEntries(Object.entries(netInfo).filter(([_, v]) => !isValueEmpty(v)));
  if (Object.keys(cleanNet).length > 0) sections["Network & Infrastructure"] = cleanNet;

  // WHOIS & Domain
  const whoisInfo = {
    registrar: result?.domain_info?.registrar || rawTech.whois?.registrar,
    creation_date: result?.domain_info?.creation_date || rawTech.whois?.creation_date,
    expiration_date: result?.domain_info?.expiration_date || rawTech.whois?.expiration_date,
    name_servers: result?.domain_info?.name_servers || rawTech.whois?.name_servers,
  };
  const cleanWhois = Object.fromEntries(Object.entries(whoisInfo).filter(([_, v]) => !isValueEmpty(v)));
  if (Object.keys(cleanWhois).length > 0) sections["WHOIS & Domain Information"] = cleanWhois;

  // Threat Intelligence & Detections
  const threatInfo = {
    verdict: result?.verdict || rawTech.threat_intelligence?.verdict,
    malicious_detections: result?.detection_stats?.malicious || result?.vt_result?.stats?.malicious || rawTech.threat_intelligence?.malicious_detections,
    total_engines_scanned: result?.detection_stats?.total || result?.vt_result?.stats?.total || rawTech.threat_intelligence?.total_engines_scanned,
    threat_tags: result?.tags || result?.threat_tags || rawTech.threat_intelligence?.threat_tags,
  };
  const cleanThreat = Object.fromEntries(Object.entries(threatInfo).filter(([_, v]) => !isValueEmpty(v)));
  if (Object.keys(cleanThreat).length > 0) sections["Threat Intelligence & Detections"] = cleanThreat;

  return sections;
}

function ReportPreview() {
  const location = useLocation();
  const navigate = useNavigate();
  const { setScanContext, clearScanContext } = useScanContext();

  const [htmlContent, setHtmlContent] = useState(location.state?.htmlContent || "");
  const [analysisResult, setAnalysisResult] = useState(location.state?.analysisResult || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(location.state?.error || false);

  useEffect(() => {
    if (analysisResult) {
      setScanContext(normalizeScanContext(analysisResult));
    }
    return () => clearScanContext();
  }, [analysisResult]);

  // Edit Mode state
  const [isEditing, setIsEditing] = useState(false);
  const [isEdited, setIsEdited] = useState(false);

  const [initialData, setInitialData] = useState(() => getDefault5W1H(location.state?.analysisResult));
  const [editedData, setEditedData] = useState(() => getDefault5W1H(location.state?.analysisResult));

  // Accordion state (General Info open by default, BUG 6 FIX)
  const [openAccordions, setOpenAccordions] = useState({ "General Information": true });

  // Copy state & Toast
  const [toast, setToast] = useState({ show: false, message: "" });
  const [copiedIocIndex, setCopiedIocIndex] = useState(null);

  useEffect(() => {
    if (!htmlContent && analysisResult && !error) {
      fetchReport(analysisResult);
    } else if (!htmlContent && !analysisResult && !location.state?.error) {
      setError("No investigation result available to generate report.");
    }
  }, [htmlContent, analysisResult]);

  useEffect(() => {
    if (analysisResult) {
      const defaults = getDefault5W1H(analysisResult);
      setInitialData(defaults);
      setEditedData(defaults);
    }
  }, [analysisResult]);

  const showToast = (message) => {
    setToast({ show: true, message });
    setTimeout(() => {
      setToast({ show: false, message: "" });
    }, 3000);
  };

  const fetchReport = async (resultObj) => {
    setLoading(true);
    setError(false);
    try {
      const response = await renderReport(resultObj, "html");
      setHtmlContent(response.data);
    } catch (err) {
      console.error("Failed to render report:", err);
      setError(err.response?.data?.detail || err.message || "Unable to generate report.");
    } finally {
      setLoading(false);
    }
  };

  const handleBackToInvestigation = () => {
    const returnPath = location.state?.returnPath;
    if (returnPath) {
      navigate(returnPath, {
        state: {
          result: analysisResult,
          analysisResult: analysisResult,
        },
      });
    } else {
      navigate(-1);
    }
  };

  const handleRetry = () => {
    if (analysisResult) {
      fetchReport(analysisResult);
    } else {
      handleBackToInvestigation();
    }
  };

  const checkIfDiffers = (current, initial) => {
    return JSON.stringify(current) !== JSON.stringify(initial);
  };

  const handlePrint = () => {
    if (isEditing) {
      setIsEditing(false);
    }
    setTimeout(() => {
      window.print();
    }, 100);
  };

  const handleCopySummary = () => {
    try {
      const text = buildCopyText();
      navigator.clipboard.writeText(text);
      showToast("Report summary copied to clipboard!");
    } catch (err) {
      console.error("Copy failed:", err);
      showToast("Failed to copy report summary.");
    }
  };

  const handleCopyIoc = (iocValue, idx) => {
    try {
      navigator.clipboard.writeText(iocValue);
      setCopiedIocIndex(idx);
      setTimeout(() => setCopiedIocIndex(null), 2000);
      showToast(`Copied IOC: ${iocValue}`);
    } catch (err) {
      console.error("Failed to copy IOC:", err);
    }
  };

  const buildCopyText = () => {
    const reportId = getReportId(analysisResult);
    const meta = {
      id: reportId,
      gen: new Date().toISOString().slice(0, 19).replace("T", " "),
      target: analysisResult?.indicator || analysisResult?.file_name || editedData.what?.artifact_name || "Artifact",
      type: analysisResult?.indicator_type || editedData.what?.artifact_type || "File",
    };
    const exec = getExecutiveSummary(analysisResult, editedData);
    const iocs = getIOCSummary(analysisResult);
    const timeline = getTimeline(analysisResult);

    let text = `==================================================\n`;
    text += `SHADOW CYBER THREAT ANALYSIS REPORT\n`;
    text += `==================================================\n`;
    text += `Report ID: ${meta.id}\n`;
    text += `Target: ${meta.target} (${meta.type})\n`;
    text += `Generated: ${meta.gen} UTC\n`;
    text += `Verdict: ${String(analysisResult?.verdict || editedData.why?.risk_level || "CLEAN").toUpperCase()}\n`;
    text += `Risk Score: ${editedData.why?.risk_score || 0}/100 | Confidence: ${editedData.why?.confidence_score || 60}/100\n`;
    if (isEdited) text += `Status: Manually Reviewed & Edited\n`;
    text += `\n`;

    text += `--------------------------------------------------\n`;
    text += `EXECUTIVE SUMMARY\n`;
    text += `--------------------------------------------------\n`;
    text += `${exec.text}\n\n`;
    if (exec.findings.length > 0) {
      text += `Key Findings:\n`;
      exec.findings.forEach((f) => {
        text += `- ${f}\n`;
      });
      text += `\n`;
    }

    text += `--------------------------------------------------\n`;
    text += `5W1H THREAT INTELLIGENCE BREAKDOWN\n`;
    text += `--------------------------------------------------\n`;
    ["who", "what", "where", "when", "why", "how"].forEach((k) => {
      text += `[${k.toUpperCase()}]\n`;
      const obj = editedData[k] || {};
      Object.entries(obj).forEach(([field, val]) => {
        if (!isValueEmpty(val)) {
          text += `  ${field.replace(/_/g, " ")}: ${formatDisplayVal(val)}\n`;
        }
      });
    });
    text += `\n`;

    if (iocs.length > 0) {
      text += `--------------------------------------------------\n`;
      text += `INDICATORS OF COMPROMISE (IOC SUMMARY)\n`;
      text += `--------------------------------------------------\n`;
      iocs.forEach((ioc) => {
        text += `- [${ioc.type}] ${ioc.value} (${ioc.source})\n`;
      });
      text += `\n`;
    }

    if (timeline.length > 0) {
      text += `--------------------------------------------------\n`;
      text += `INVESTIGATION TIMELINE\n`;
      text += `--------------------------------------------------\n`;
      timeline.forEach((ev) => {
        text += `- [${ev.timestamp}] ${ev.title}: ${ev.description}\n`;
      });
      text += `\n`;
    }

    text += `--------------------------------------------------\n`;
    text += `ACTIONABLE RECOMMENDATIONS\n`;
    text += `--------------------------------------------------\n`;
    (editedData.recommendations || []).forEach((r) => {
      text += `- ${r}\n`;
    });
    text += `\n`;

    text += `==================================================\n`;
    text += `Generated by SHADOW Report Engine v1.0 • CONFIDENTIAL • For Security Investigation Use Only\n`;
    return text;
  };

  const handleFieldChange = (section, key, value) => {
    setEditedData((prev) => {
      const updated = {
        ...prev,
        [section]: {
          ...prev[section],
          [key]: value,
        },
      };
      setIsEdited(checkIfDiffers(updated, initialData));
      return updated;
    });
  };

  const handleRecommendationChange = (index, value) => {
    setEditedData((prev) => {
      const updatedRecs = [...(prev.recommendations || [])];
      updatedRecs[index] = value;
      const updated = { ...prev, recommendations: updatedRecs };
      setIsEdited(checkIfDiffers(updated, initialData));
      return updated;
    });
  };

  const resetSection = (section) => {
    setEditedData((prev) => {
      const updated = {
        ...prev,
        [section]: section === "recommendations" ? [...(initialData.recommendations || [])] : { ...initialData[section] },
      };
      setIsEdited(checkIfDiffers(updated, initialData));
      return updated;
    });
  };

  const resetAllEdits = () => {
    setEditedData(JSON.parse(JSON.stringify(initialData)));
    setIsEdited(false);
  };

  const toggleAccordion = (title) => {
    setOpenAccordions((prev) => ({
      ...prev,
      [title]: !prev[title],
    }));
  };

  const execSummary = getExecutiveSummary(analysisResult, editedData);
  const iocList = getIOCSummary(analysisResult);
  const timelineEvents = getTimeline(analysisResult);
  const techSections = getTechnicalSummary(analysisResult);
  const reportId = getReportId(analysisResult);

  // 4-CARD ACCENTS & ICONS (BUG 3 & 4 FIX)
  const riskLvlStr = String(editedData.why?.risk_level || analysisResult?.verdict || "LOW").toUpperCase();
  const riskScoreNum = Number(editedData.why?.risk_score || analysisResult?.risk_score || 0);
  const confScoreNum = Number(editedData.why?.confidence_score || analysisResult?.confidence_score || 60);
  const confLvlStr = String(editedData.why?.confidence_level || analysisResult?.confidence_level || "MEDIUM").toUpperCase();

  // Risk Level Card Class & Icon Badge
  let riskLevelCardClass = "metric-card-risk-low";
  let riskLevelIconClass = "metric-icon-risk-low";
  if (riskLvlStr.includes("MALICIOUS") || riskLvlStr.includes("HIGH") || riskLvlStr.includes("CRITICAL")) {
    riskLevelCardClass = "metric-card-risk-high";
    riskLevelIconClass = "metric-icon-risk-high";
  } else if (riskLvlStr.includes("SUSPICIOUS") || riskLvlStr.includes("MEDIUM")) {
    riskLevelCardClass = "metric-card-risk-medium";
    riskLevelIconClass = "metric-icon-risk-medium";
  }

  // Risk Score Card Class & Icon Badge
  let riskScoreCardClass = "metric-card-risk-low";
  let riskScoreIconClass = "metric-icon-risk-low";
  if (riskScoreNum >= 70) {
    riskScoreCardClass = "metric-card-risk-high";
    riskScoreIconClass = "metric-icon-risk-high";
  } else if (riskScoreNum >= 30) {
    riskScoreCardClass = "metric-card-risk-medium";
    riskScoreIconClass = "metric-icon-risk-medium";
  }

  // Confidence Score Card Class & Icon Badge (Blue Shades)
  let confScoreCardClass = "metric-card-conf-low";
  let confScoreIconClass = "metric-icon-conf-low";
  if (confScoreNum >= 70) {
    confScoreCardClass = "metric-card-conf-high";
    confScoreIconClass = "metric-icon-conf-high";
  } else if (confScoreNum >= 40) {
    confScoreCardClass = "metric-card-conf-medium";
    confScoreIconClass = "metric-icon-conf-medium";
  }

  // Confidence Level Card Class & Icon Badge (Blue Shades)
  let confLevelCardClass = "metric-card-conf-low";
  let confLevelIconClass = "metric-icon-conf-low";
  if (confLvlStr.includes("HIGH")) {
    confLevelCardClass = "metric-card-conf-high";
    confLevelIconClass = "metric-icon-conf-high";
  } else if (confLvlStr.includes("MEDIUM")) {
    confLevelCardClass = "metric-card-conf-medium";
    confLevelIconClass = "metric-icon-conf-medium";
  }

  return (
    <div className="report-preview-page">
      {/* TOAST NOTIFICATION */}
      {toast.show && (
        <div className="toast-notification">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <span>{toast.message}</span>
        </div>
      )}

      {/* TOP NAVIGATION / ACTION BAR (BUG 2 FIX: SAAS BUTTON STYLING) */}
      <header className="report-action-bar no-print">
        <button
          type="button"
          onClick={handleBackToInvestigation}
          className="toolbar-btn btn-secondary"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Investigation</span>
        </button>

        {htmlContent && !loading && !error && (
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleCopySummary}
              className="toolbar-btn btn-secondary"
              title="Copy plain-text summary to clipboard"
            >
              <Copy className="h-4 w-4" />
              <span>Copy Summary</span>
            </button>

            <button
              type="button"
              onClick={() => setIsEditing(!isEditing)}
              className={`toolbar-btn ${isEditing ? "btn-editing" : "btn-secondary"}`}
            >
              {isEditing ? (
                <>
                  <Check className="h-4 w-4 text-emerald-600" />
                  <span>Done Editing</span>
                </>
              ) : (
                <>
                  <Edit3 className="h-4 w-4" />
                  <span>Edit Report</span>
                </>
              )}
            </button>

            {isEdited && (
              <button
                type="button"
                onClick={resetAllEdits}
                className="toolbar-btn btn-amber"
                title="Reset all sections to auto-generated content"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Reset All</span>
              </button>
            )}

            <button
              type="button"
              onClick={handlePrint}
              className="toolbar-btn btn-primary"
            >
              <Printer className="h-4 w-4" />
              <span>Print / Save PDF</span>
            </button>
          </div>
        )}
      </header>

      {/* MAIN CONTAINER */}
      <main className="report-paper-container">
        {/* LOADING STATE */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <Loader2 className="h-10 w-10 animate-spin text-emerald-600 mb-4" />
            <h3 className="text-xl font-bold text-slate-800">Generating Report...</h3>
            <p className="mt-2 text-sm text-slate-500 max-w-sm">
              SHADOW Report Engine is compiling threat metrics and formatting 5W1H investigation document.
            </p>
          </div>
        )}

        {/* ERROR STATE */}
        {!loading && error && (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-red-50 text-red-600 mb-4 border border-red-100">
              <AlertTriangle className="h-7 w-7" />
            </div>
            <h3 className="text-2xl font-bold text-slate-900">Unable to generate report.</h3>
            <p className="mt-2 text-sm text-slate-600 max-w-md">
              {typeof error === "string" ? error : "An unexpected error occurred while communicating with the SHADOW Report Engine backend."}
            </p>
            <div className="mt-6 flex items-center gap-3">
              <button
                type="button"
                onClick={handleRetry}
                className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-5 py-2.5 text-xs font-semibold text-white transition hover:bg-slate-800 shadow-md"
              >
                <RotateCcw className="h-4 w-4" />
                Try again
              </button>
              <button
                type="button"
                onClick={() => navigate("/dashboard")}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-5 py-2.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
              >
                Go to Dashboard
              </button>
            </div>
          </div>
        )}

        {/* EDIT MODE EDITORS */}
        {!loading && !error && isEditing && (
          <div className="space-y-8 text-left">
            <div className="flex items-center justify-between border-b border-slate-200 pb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-900">Interactive Report Editor</h2>
                <p className="text-xs text-slate-500">Edit any 5W1H investigation section below before exporting to PDF.</p>
              </div>
              {isEdited && (
                <span className="inline-flex items-center rounded-full bg-amber-100 px-3 py-1 text-xs font-semibold text-amber-800">
                  Manually reviewed & edited
                </span>
              )}
            </div>

            {/* EDIT SECTIONS */}
            {["who", "what", "where", "when", "why", "how"].map((secKey) => {
              const secTitle = secKey.toUpperCase();
              const secObj = editedData[secKey] || {};
              return (
                <div key={secKey} className="rounded-xl border border-slate-200 bg-slate-50/50 p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-sm font-bold text-slate-800 uppercase tracking-wide">
                      Section: {secTitle}
                    </h4>
                    <button
                      type="button"
                      onClick={() => resetSection(secKey)}
                      className="text-xs font-semibold text-slate-500 hover:text-slate-800 inline-flex items-center gap-1"
                    >
                      <RefreshCw className="h-3 w-3" /> Reset section
                    </button>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    {Object.entries(secObj).map(([k, val]) => (
                      <div key={k} className="flex flex-col gap-1">
                        <label className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                          {k.replace(/_/g, " ")}
                        </label>
                        <input
                          type="text"
                          value={Array.isArray(val) ? val.join(", ") : String(val || "")}
                          onChange={(e) => handleFieldChange(secKey, k, e.target.value)}
                          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-900 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                        />
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}

            {/* RECOMMENDATIONS EDIT */}
            <div className="rounded-xl border border-slate-200 bg-slate-50/50 p-5">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-sm font-bold text-slate-800 uppercase tracking-wide">
                  Actionable Mitigation Recommendations
                </h4>
                <button
                  type="button"
                  onClick={() => resetSection("recommendations")}
                  className="text-xs font-semibold text-slate-500 hover:text-slate-800 inline-flex items-center gap-1"
                >
                  <RefreshCw className="h-3 w-3" /> Reset section
                </button>
              </div>
              <div className="space-y-3">
                {(editedData.recommendations || []).map((rec, idx) => (
                  <div key={idx} className="flex flex-col gap-1">
                    <label className="text-[11px] font-bold text-slate-500">Recommendation {idx + 1}</label>
                    <textarea
                      rows={2}
                      value={rec}
                      onChange={(e) => handleRecommendationChange(idx, e.target.value)}
                      className="rounded-lg border border-slate-300 bg-white p-2.5 text-xs text-slate-900 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* VIEW MODE REPORT DOCUMENT */}
        {!loading && !error && !isEditing && (
          <div className="light-theme-report relative">
            {/* MANUALLY REVIEWED & EDITED NOTE */}
            {isEdited && (
              <div className="mb-4 inline-flex items-center gap-1.5 rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs font-semibold text-amber-900 shadow-sm">
                <span>ℹ️</span>
                <span>Manually reviewed & edited</span>
              </div>
            )}

            <div className="container">
              {/* HEADER (BUG 1 FIX: REAL GENERATED REPORT ID) */}
              <header>
                <div className="brand">
                  <div className="brand-logo">S</div>
                  <div className="brand-title">SHADOW Security Report</div>
                </div>
                <div className="meta-tag">
                  <div>
                    <strong>Report ID:</strong> {reportId}
                  </div>
                  <div>
                    <strong>Generated:</strong> {new Date().toISOString().slice(0, 19).replace("T", " ")} UTC
                  </div>
                  {isEdited && (
                    <div>
                      <strong style={{ color: "#d97706" }}>Reviewed & Edited</strong>
                    </div>
                  )}
                </div>
              </header>

              {/* METRICS BANNER (BUG 3 & 4 FIX: 4-CARD COLOR ACCENTS & BOLDER ICON BADGES) */}
              <div className="metrics-banner">
                <div className={`metric-card ${riskLevelCardClass}`}>
                  <div className="metric-label flex items-center justify-center gap-1.5">
                    <span className={`metric-icon-badge ${riskLevelIconClass}`}>
                      <Shield className="h-3.5 w-3.5" />
                    </span>
                    <span>Risk Level</span>
                  </div>
                  <div className="metric-value">{editedData.why?.risk_level || "LOW"}</div>
                </div>

                <div className={`metric-card ${riskScoreCardClass}`}>
                  <div className="metric-label flex items-center justify-center gap-1.5">
                    <span className={`metric-icon-badge ${riskScoreIconClass}`}>
                      <AlertOctagon className="h-3.5 w-3.5" />
                    </span>
                    <span>Risk Score</span>
                  </div>
                  <div className="metric-value">{editedData.why?.risk_score || 0} / 100</div>
                </div>

                <div className={`metric-card ${confScoreCardClass}`}>
                  <div className="metric-label flex items-center justify-center gap-1.5">
                    <span className={`metric-icon-badge ${confScoreIconClass}`}>
                      <Activity className="h-3.5 w-3.5" />
                    </span>
                    <span>Confidence Score</span>
                  </div>
                  <div className="metric-value">{editedData.why?.confidence_score || 60} / 100</div>
                </div>

                <div className={`metric-card ${confLevelCardClass}`}>
                  <div className="metric-label flex items-center justify-center gap-1.5">
                    <span className={`metric-icon-badge ${confLevelIconClass}`}>
                      <Award className="h-3.5 w-3.5" />
                    </span>
                    <span>Confidence Level</span>
                  </div>
                  <div className="metric-value">{editedData.why?.confidence_level || "MEDIUM"}</div>
                </div>
              </div>

              {/* EXECUTIVE SUMMARY */}
              <div className="exec-summary-card">
                <div className="section-title" style={{ marginBottom: "10px" }}>
                  <FileText className="h-4 w-4" /> Executive Summary
                </div>
                <p className="exec-text">{execSummary.text}</p>
                {execSummary.findings.length > 0 && (
                  <ul className="exec-findings-list">
                    {execSummary.findings.map((finding, idx) => (
                      <li key={idx} className="exec-finding-item">
                        • {finding}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* 5W1H THREAT BREAKDOWN (FULL-WIDTH STACKED LAYOUT PRESERVED, BUG 5 FIX FOR HASHES) */}
              <div className="section-title">📌 5W1H Threat Intelligence Breakdown</div>

              <div className="grid-5w1h">
                {["who", "what", "where", "when", "why", "how"].map((secKey, idx) => {
                  const secObj = editedData[secKey] || {};
                  const secTitles = [
                    "1. WHO (Target Context)",
                    "2. WHAT (Artifact & Threat)",
                    "3. WHERE (Location & Path)",
                    "4. WHEN (Timestamps)",
                    "5. WHY (Severity & Rationale)",
                    "6. HOW (Vectors & Execution)",
                  ];
                  const validEntries = Object.entries(secObj).filter(([_, v]) => !isValueEmpty(v));
                  return (
                    <div key={secKey} className="card">
                      <div className="card-header">{secTitles[idx]}</div>
                      {validEntries.length > 0 ? (
                        validEntries.map(([k, v]) => {
                          const isHash = ["hash", "md5", "sha1", "sha256"].some((hk) => k.toLowerCase().includes(hk));
                          const valClass = isHash ? "info-value info-value-hash" : "info-value";
                          return (
                            <div key={k} className="info-row">
                              <span className="info-label">{k.replace(/_/g, " ")}</span>
                              <span className={valClass} style={{ whiteSpace: "pre-line" }}>
                                {formatDisplayVal(v, k)}
                              </span>
                            </div>
                          );
                        })
                      ) : (
                        <div className="info-empty-note">
                          Telemetry for {secKey.toUpperCase()} not applicable for this indicator type.
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* IOC SUMMARY TABLE (BUG 7 FIX: CLEAR FILENAME LABELING) */}
              {iocList.length > 0 && (
                <div>
                  <div className="section-title">🎯 Indicators of Compromise (IOC Summary)</div>
                  <div className="ioc-table-container">
                    <table className="ioc-table">
                      <thead>
                        <tr>
                          <th>Type</th>
                          <th>Indicator Value</th>
                          <th>Source / Context</th>
                          <th className="no-print" style={{ width: "80px" }}>
                            Action
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {iocList.map((ioc, idx) => (
                          <tr key={idx}>
                            <td style={{ fontWeight: 700, fontSize: "11px" }}>{ioc.type}</td>
                            <td>
                              <span className="ioc-value-code">{ioc.value}</span>
                            </td>
                            <td>{ioc.source}</td>
                            <td className="no-print">
                              <button
                                type="button"
                                onClick={() => handleCopyIoc(ioc.value, idx)}
                                className="ioc-copy-btn"
                                title="Copy IOC value"
                              >
                                {copiedIocIndex === idx ? (
                                  <>
                                    <Check className="h-3 w-3 text-emerald-600" />
                                    <span className="text-emerald-600">Copied</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="h-3 w-3" />
                                    <span>Copy</span>
                                  </>
                                )}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* INVESTIGATION TIMELINE */}
              {timelineEvents.length > 0 && (
                <div>
                  <div className="section-title">⏱️ Investigation & Detection Timeline</div>
                  <div className="timeline-container">
                    <div className="timeline-list">
                      {timelineEvents.map((ev, idx) => (
                        <div key={idx} className="timeline-item">
                          <div className="timeline-node" />
                          <div className="timeline-time">{ev.timestamp}</div>
                          <div className="timeline-title">{ev.title}</div>
                          <div className="timeline-desc">{ev.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* TECHNICAL SUMMARY ACCORDION (BUG 6 FIX: INTERACTIVE COLLAPSIBLE ACCORDIONS) */}
              {Object.keys(techSections).length > 0 && (
                <div>
                  <div className="section-title">⚙️ Deep Technical Summary</div>
                  <div className="accordion-container">
                    {Object.entries(techSections).map(([secTitle, dataObj]) => {
                      const isOpen = !!openAccordions[secTitle];
                      return (
                        <div key={secTitle} className="accordion-item">
                          <button
                            type="button"
                            onClick={() => toggleAccordion(secTitle)}
                            className="accordion-header"
                          >
                            <span className="flex items-center gap-2">
                              <span>📁</span>
                              <span>{secTitle}</span>
                            </span>
                            <span
                              className={`accordion-chevron no-print transition-transform duration-200 ${
                                isOpen ? "rotate-180" : ""
                              }`}
                            >
                              <ChevronDown className="h-4 w-4 text-slate-500" />
                            </span>
                          </button>
                          <div className={`accordion-body ${isOpen ? "accordion-open" : "accordion-closed"}`}>
                            {Object.entries(dataObj).map(([k, v]) => {
                              const isHash = ["hash", "md5", "sha1", "sha256"].some((hk) => k.toLowerCase().includes(hk));
                              const valClass = isHash ? "info-value info-value-hash" : "info-value";
                              return (
                                <div key={k} className="info-row">
                                  <span className="info-label">{k.replace(/_/g, " ")}</span>
                                  <span className={valClass} style={{ whiteSpace: "pre-line" }}>
                                    {formatDisplayVal(v)}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ACTIONABLE RECOMMENDATIONS */}
              <div className="recommendations-box">
                <div className="section-title" style={{ marginBottom: "12px" }}>
                  🛡️ Actionable Mitigation Recommendations
                </div>
                <ul className="rec-list">
                  {(editedData.recommendations || []).map((rec, i) => (
                    <li key={i} className="rec-item">
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>

              {/* CONFIDENTIAL FOOTER */}
              <footer className="report-confidential-footer">
                Generated by SHADOW Report Engine v1.0 — CONFIDENTIAL — For Security Investigation Use Only
              </footer>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default ReportPreview;
