import { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import AnalysisResult from "../components/analysis/AnalysisResult";
import { getScan } from "../services/api";
import { useAuth } from "../context/AuthContext";
import "../styles/upload.css";

function joinList(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value && typeof value === "object") return Object.keys(value).join(", ");
  return value;
}

function getFileTypeName(value) {
  if (!value) return undefined;
  return typeof value === "object" ? value.type || value.name : value;
}

export function parseAndMergeScanData(scanData) {
  if (!scanData) return null;

  // 1. Defensively parse vt_raw
  let vtRawObj = {};
  if (scanData.vt_raw) {
    if (typeof scanData.vt_raw === "string") {
      try {
        vtRawObj = JSON.parse(scanData.vt_raw);
      } catch (e) {
        console.warn("Failed to parse vt_raw JSON string:", e);
        vtRawObj = {};
      }
    } else if (typeof scanData.vt_raw === "object") {
      vtRawObj = scanData.vt_raw;
    }
  }

  // 2. Extract nested analysis payload if present
  const rawPayload = vtRawObj.result || vtRawObj.analysis || vtRawObj.vt_result || vtRawObj;
  const attrs = rawPayload.data?.attributes || vtRawObj.data?.attributes || {};
  const report = rawPayload.report || {};
  const fivew1h = report.fivew1h || {};

  // 3. Fallbacks for verdict / severity / risk metrics
  const detections = scanData.vt_detections ?? rawPayload.detections ?? rawPayload.positives ?? attrs.last_analysis_stats?.malicious ?? 0;
  const totalEngines = scanData.vt_total_engines ?? rawPayload.total_engines ?? rawPayload.usable_engines ?? rawPayload.total ?? 90;

  const getFallbackVerdict = (dets) => {
    if (dets === 0) return "CLEAN";
    if (dets <= 5) return "SUSPICIOUS";
    return "MALICIOUS";
  };

  const getFallbackSeverity = (dets) => {
    if (dets === 0) return "NONE";
    if (dets <= 5) return "MEDIUM";
    return "HIGH";
  };

  const verdict = rawPayload.verdict || scanData.verdict || getFallbackVerdict(detections);
  const severity = rawPayload.severity || scanData.severity || getFallbackSeverity(detections);
  const confidence = rawPayload.confidence || scanData.confidence || "HIGH";

  const riskScore = rawPayload.risk_score ?? (verdict === "MALICIOUS" ? 85 : verdict === "SUSPICIOUS" ? 38 : 0);
  const confidenceScore = rawPayload.confidence_score ?? 95;

  // SOC Recommendation (Action & Reason)
  const recommendationAction =
    rawPayload.recommendation?.action ||
    rawPayload.recommended_action ||
    fivew1h.how?.recommended_action ||
    (verdict === "MALICIOUS"
      ? "Isolate Host & Block Indicator"
      : verdict === "SUSPICIOUS"
        ? "Investigate Network Activity"
        : "No Action Required");

  const recommendationReason =
    rawPayload.recommendation?.reason ||
    rawPayload.recommendation?.rationale ||
    rawPayload.recommendation_reason ||
    fivew1h.why?.summary ||
    (verdict === "MALICIOUS"
      ? "Malicious activity confirmed across multiple threat intelligence sources."
      : verdict === "SUSPICIOUS"
        ? "Suspicious indicators detected requiring SOC analyst review."
        : "No threat activity detected across security engines.");

  const recommendation = {
    action: recommendationAction,
    reason: recommendationReason,
    priority: rawPayload.recommendation?.priority || rawPayload.recommendation_priority || (verdict === "MALICIOUS" ? "HIGH" : "LOW"),
  };

  // Timestamps
  const firstSeen =
    rawPayload.first_seen ||
    attrs.first_submission_date ||
    attrs.first_seen ||
    scanData.created_at;

  const lastAnalysis =
    rawPayload.last_analysis ||
    rawPayload.last_analysis_date ||
    attrs.last_analysis_date ||
    scanData.created_at;

  // Community Reputation
  const communityReputation =
    rawPayload.community_reputation ??
    rawPayload.reputation ??
    attrs.reputation ??
    scanData.community_reputation;

  // Threat Label & Categories
  const threatLabel =
    rawPayload.threat_label ||
    rawPayload.threat_category ||
    attrs.popular_threat_classification?.suggested_threat_label ||
    (detections > 0 ? "Suspicious Activity" : "No Threat Detected");

  const rawCategories =
    rawPayload.threat_categories ||
    rawPayload.categories ||
    attrs.categories ||
    attrs.popular_threat_classification?.popular_threat_category ||
    [];

  let threatCategories = [];
  if (Array.isArray(rawCategories)) {
    threatCategories = rawCategories.map((cat) => {
      if (typeof cat === "object" && cat !== null) {
        return cat.value || cat.name || cat.category || cat.engine || String(cat);
      }
      return String(cat);
    });
  } else if (typeof rawCategories === "object" && rawCategories !== null) {
    threatCategories = Object.entries(rawCategories).map(([k, v]) => {
      if (typeof v === "object" && v !== null) {
        return `${k}: ${v.value || v.category || v.result || String(v)}`;
      }
      return `${k}: ${v}`;
    });
  }
  if (threatCategories.length === 0 && detections > 0) {
    threatCategories = [threatLabel];
  }

  // Basic File / Hash / Indicator Properties
  const meaningfulName =
    rawPayload.meaningful_name ||
    attrs.meaningful_name ||
    scanData.file_name;

  const rawAssociated =
    rawPayload.associated_names ||
    attrs.names ||
    (scanData.file_name ? [scanData.file_name] : []);

  const associatedNames = Array.isArray(rawAssociated) ? rawAssociated : [rawAssociated];

  const fileType =
    rawPayload.file_type ||
    attrs.type_description ||
    attrs.type_tag ||
    scanData.analysis_type;

  const fileSize =
    rawPayload.file_size ||
    attrs.size ||
    scanData.file_size;

  // Flagged Engines
  let flaggedEngines = rawPayload.flagged_engines || [];
  const lastAnalysisResults = rawPayload.last_analysis_results || attrs.last_analysis_results || rawPayload.scans || attrs.scans || {};
  
  if (!Array.isArray(flaggedEngines) || flaggedEngines.length === 0) {
    flaggedEngines = [];
    if (lastAnalysisResults && typeof lastAnalysisResults === "object") {
      Object.entries(lastAnalysisResults).forEach(([engineName, res]) => {
        if (!res) return;
        const category = res.category || (res.detected ? "malicious" : "harmless");
        const isFlagged = category === "malicious" || category === "suspicious" || res.detected === true;
        if (isFlagged) {
          flaggedEngines.push({
            engine: res.engine_name || engineName,
            category: category,
            result: res.result || "flagged",
          });
        }
      });
    }
  }

  // Unusable Engines & Breakdown
  const lastAnalysisStats = rawPayload.last_analysis_stats || attrs.last_analysis_stats || {};
  const unusableEngines =
    rawPayload.unusable_engines ??
    ((lastAnalysisStats.timeout || 0) +
      (lastAnalysisStats.failure || 0) +
      (lastAnalysisStats["type-unsupported"] || 0) +
      (lastAnalysisStats["confirmed-timeout"] || 0));

  const unusableBreakdown =
    rawPayload.unusable_breakdown || {
      timeout: lastAnalysisStats.timeout || 0,
      failure: lastAnalysisStats.failure || 0,
      type_unsupported: lastAnalysisStats["type-unsupported"] || 0,
      confirmed_timeout: lastAnalysisStats["confirmed-timeout"] || 0,
    };

  // Permalink
  const permalink = scanData.vt_permalink || rawPayload.permalink || attrs.permalink || rawPayload.gui_link;

  // Merge top-level DB columns with rawPayload into ONE unified object matching AnalysisResult expected shape
  const mergedAnalysis = {
    ...rawPayload,
    indicator: scanData.file_name || rawPayload.indicator || rawPayload.file_name || rawPayload.url || rawPayload.domain || rawPayload.ip,
    file_name: scanData.file_name || rawPayload.file_name,
    indicator_type: scanData.analysis_type || rawPayload.indicator_type || rawPayload.analysis_type || "file",
    analysis_type: scanData.analysis_type || rawPayload.analysis_type || rawPayload.indicator_type || "file",
    scan_id: scanData.id || scanData.scan_id,
    created_at: scanData.created_at || scanData.scanned_at,

    verdict: verdict,
    severity: severity,
    confidence: confidence,
    risk_score: riskScore,
    confidence_score: confidenceScore,

    detections: detections,
    total_engines: totalEngines,
    usable_engines: totalEngines,
    unusable_engines: unusableEngines,
    unusable_breakdown: unusableBreakdown,
    flagged_engines: flaggedEngines,
    permalink: permalink,

    positives: detections,
    total: totalEngines,

    recommendation: recommendation,
    recommended_action: recommendation.action,

    first_seen: firstSeen,
    last_analysis: lastAnalysis,
    last_analysis_date: lastAnalysis,

    community_reputation: communityReputation,
    reputation: communityReputation,

    threat_label: threatLabel,
    threat_categories: threatCategories,
    categories: threatCategories,

    meaningful_name: meaningfulName,
    associated_names: associatedNames,
    file_type: fileType,
    file_size: fileSize,

    risk_factors: rawPayload.risk_factors || [],
    confidence_factors: rawPayload.confidence_factors || [],

    ip_info: rawPayload.ip_info || (scanData.analysis_type === "ip" ? {
      ip: scanData.file_name,
      version: attrs.ip_version || "v4",
      asn: attrs.asn,
      as_owner: attrs.as_owner,
      country: attrs.country || attrs.rdap?.country,
      network: attrs.network,
      reverse_dns: attrs.rdap?.name,
    } : undefined),
    url_info: rawPayload.url_info,
    domain_info: rawPayload.domain_info,
    hashes: rawPayload.hashes || { md5: scanData.md5, sha1: scanData.sha1, sha256: scanData.sha256 },
  };

  return mergedAnalysis;
}

export function buildMetadataFromScan(scanData, mergedAnalysis) {
  const type = (scanData.analysis_type || mergedAnalysis.analysis_type || mergedAnalysis.indicator_type || "file").toLowerCase();
  const submitted =
    scanData.file_name ||
    mergedAnalysis.indicator ||
    mergedAnalysis.file_name ||
    mergedAnalysis.url ||
    mergedAnalysis.domain ||
    mergedAnalysis.ip ||
    scanData.sha256 ||
    "Indicator";

  const title =
    type === "file"
      ? "File Intelligence Report"
      : type === "url"
        ? "URL Intelligence Report"
        : type === "domain"
          ? "Domain Intelligence Report"
          : type === "ip"
            ? "IP Intelligence Report"
            : "Hash Intelligence Report";

  const indicatorLabel =
    type === "file"
      ? "File"
      : type === "url"
        ? "URL"
        : type === "domain"
          ? "Domain"
          : type === "ip"
            ? "IP"
            : "Hash";

  const indicatorValue = submitted;
  const indicatorType =
    type === "file"
      ? getFileTypeName(mergedAnalysis.file_type || scanData.file_type) || scanData.mime_type || "File"
      : type === "url"
        ? "URL"
        : type === "domain"
          ? "Domain"
          : type === "ip"
            ? "IP"
            : scanData.hash_type || mergedAnalysis.hash_type || "Hash";

  const scanId = scanData.id || scanData.scan_id;
  const scannedAt = scanData.created_at || scanData.scanned_at;

  return {
    analysisType: type,
    title,
    indicatorLabel,
    indicatorValue,
    indicatorType,
    scanId,
    scannedAt,
    analysis: mergedAnalysis,
  };
}

export function buildBasicPropertiesFromScan(scanData, meta) {
  const analysis = meta.analysis;

  if (meta.analysisType === "file") {
    const hashes = analysis.hashes || {};
    return [
      { label: "File Name", value: scanData.file_name || analysis.file_name || meta.indicatorValue },
      { label: "File Size", value: scanData.file_size || analysis.file_size },
      { label: "File Type", value: getFileTypeName(analysis.file_type || scanData.file_type) },
      { label: "MIME Type", value: scanData.mime_type || analysis.mime_type },
      { label: "MD5", value: scanData.md5 || hashes.md5 || analysis.md5 },
      { label: "SHA1", value: scanData.sha1 || hashes.sha1 || analysis.sha1 },
      { label: "SHA256", value: scanData.sha256 || hashes.sha256 || analysis.sha256 },
    ];
  }

  if (meta.analysisType === "url") {
    const urlInfo = analysis.url_info || {};
    return [
      { label: "URL", value: meta.indicatorValue || analysis.indicator },
      { label: "Protocol", value: urlInfo.protocol },
      { label: "Host", value: urlInfo.host },
      { label: "Domain", value: urlInfo.domain },
      { label: "Path", value: urlInfo.path },
      { label: "Query", value: urlInfo.query },
      { label: "Fragment", value: urlInfo.fragment },
      { label: "Port", value: urlInfo.port },
      { label: "URL Length", value: urlInfo.url_length },
      { label: "Community Reputation", value: analysis.community_reputation },
    ];
  }

  if (meta.analysisType === "ip") {
    const ipInfo = analysis.ip_info || {};
    const attrs = analysis.data?.attributes || {};
    return [
      { label: "IP Address", value: meta.indicatorValue || analysis.indicator },
      { label: "IP Version", value: ipInfo.version || attrs.ip_version || "v4" },
      { label: "ASN", value: ipInfo.asn || attrs.asn },
      { label: "AS Owner", value: ipInfo.as_owner || attrs.as_owner },
      { label: "Country", value: ipInfo.country || attrs.country || attrs.rdap?.country },
      { label: "Network", value: ipInfo.network || attrs.network },
      { label: "Reverse DNS", value: ipInfo.reverse_dns || attrs.rdap?.name },
    ];
  }

  return [
    { label: "Hash", value: meta.indicatorValue || analysis.indicator },
    { label: "Hash Type", value: meta.indicatorType },
    { label: "Meaningful Name", value: analysis.meaningful_name },
    { label: "Associated Names", value: analysis.associated_names },
    { label: "File Type", value: getFileTypeName(analysis.file_type) },
    { label: "File Size", value: analysis.file_size },
  ];
}

function ScanResult() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchScanResult = useCallback(async () => {
    if (!scanId) {
      setError("No scan ID specified.");
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError("");
      const response = await getScan(scanId);
      const data = response.data?.scan;

      if (!data) {
        throw new Error("Scan not found.");
      }

      setScanData(data);
    } catch (err) {
      console.error("Error fetching scan result:", err);
      setError(
        err.response?.data?.detail ||
          err.message ||
          "Scan not found or unable to fetch result."
      );
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchScanResult();
  }, [fetchScanResult]);

  if (loading) {
    return (
      <div className="upload-page result-page" style={{ padding: "2rem" }}>
        <p style={{ color: "#94a3b8" }}>Loading scan result...</p>
      </div>
    );
  }

  if (error || !scanData) {
    return (
      <div className="upload-page result-page" style={{ padding: "2rem" }}>
        <p style={{ color: "#ef4444", marginBottom: "1rem" }}>
          {error || "Scan not found"}
        </p>
        <Link
          to="/upload"
          className="upload-btn"
          style={{ textDecoration: "none", display: "inline-block", textAlign: "center" }}
        >
          Back to Upload
        </Link>
      </div>
    );
  }

  const mergedAnalysis = parseAndMergeScanData(scanData);
  const meta = buildMetadataFromScan(scanData, mergedAnalysis);
  const basicProperties = buildBasicPropertiesFromScan(scanData, meta);

  return (
    <div className="upload-page result-page">
      <AnalysisResult
        result={mergedAnalysis}
        title={meta.title}
        indicatorLabel={meta.indicatorLabel}
        indicatorValue={meta.indicatorValue}
        indicatorType={meta.indicatorType}
        scanId={meta.scanId}
        scannedAt={meta.scannedAt}
        showScanId={Boolean(user)}
        basicProperties={basicProperties}
        onBack={() => navigate("/upload")}
        onNewScan={() => navigate("/upload")}
      />
    </div>
  );
}

export default ScanResult;
