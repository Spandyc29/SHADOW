/**
 * scanContextAdapter.js
 * Normalizes scan data from any Analysis Result page or Report Preview into a clean context object for Shadow AI.
 */

export function normalizeScanContext(result, extraMeta = {}) {
  if (!result) return null;

  const payload = result.result || result.analysis || result.vt_result || result;

  const rawType = (
    extraMeta.indicatorType ||
    result.indicator_type ||
    result.analysis_type ||
    payload.indicator_type ||
    payload.hash_type ||
    "indicator"
  ).toLowerCase();

  const target = (
    extraMeta.indicatorValue ||
    result.indicator ||
    result.file_name ||
    result.url ||
    result.domain ||
    result.ip ||
    payload.indicator ||
    payload.file_name ||
    payload.url ||
    payload.domain ||
    payload.ip ||
    "Unknown Target"
  );

  const verdict = String(result.verdict || payload.verdict || extraMeta.verdict || "CLEAN").toUpperCase();
  const riskScore = result.risk_score ?? payload.risk_score ?? extraMeta.risk_score ?? 0;
  const confidenceScore = result.confidence_score ?? payload.confidence_score ?? extraMeta.confidence_score ?? 95;

  const getRiskLevel = (score) => {
    if (score >= 80) return "HIGH";
    if (score >= 40) return "MEDIUM";
    if (score > 0) return "LOW";
    return "NONE";
  };

  const getConfidenceLevel = (score) => {
    if (score >= 80) return "HIGH";
    if (score >= 40) return "MEDIUM";
    return "LOW";
  };

  const threatLabel = result.threat_label || payload.threat_label || result.threat_category || payload.threat_category || "No Threat Detected";

  const rawRiskFactors = result.risk_factors || payload.risk_factors;
  const riskFactors = Array.isArray(rawRiskFactors)
    ? rawRiskFactors.join(", ")
    : (rawRiskFactors || "None");

  const rawTags = result.tags || payload.tags;
  const tags = Array.isArray(rawTags)
    ? rawTags.join(", ")
    : (rawTags || "verified");

  const scanId = extraMeta.scanId || result.scan_id || result.id || payload.scan_id || payload.id || "N/A";

  // Detections extraction
  let detections = "0 detections";
  if (typeof result.positives === "number" && typeof result.total === "number") {
    detections = `${result.positives}/${result.total} security engines`;
  } else if (typeof payload.positives === "number" && typeof payload.total === "number") {
    detections = `${payload.positives}/${payload.total} security engines`;
  } else if (result.vt_result?.positives !== undefined) {
    detections = `${result.vt_result.positives} security engines`;
  } else if (result.community_reputation !== undefined) {
    detections = `Community Reputation: ${result.community_reputation}`;
  } else if (result.detections) {
    detections = Array.isArray(result.detections) ? result.detections.join(", ") : String(result.detections);
  }

  // Technical details string representation for AI context
  const technicalParts = [];
  if (result.file_type || payload.file_type) {
    const ft = typeof result.file_type === "object" ? result.file_type.type : (result.file_type || payload.file_type);
    if (ft) technicalParts.push(`File Type: ${ft}`);
  }
  if (result.hashes || payload.hashes) {
    const h = result.hashes || payload.hashes;
    if (h?.sha256) technicalParts.push(`SHA256: ${h.sha256}`);
    if (h?.md5) technicalParts.push(`MD5: ${h.md5}`);
  }
  if (result.ip_info || payload.ip_info) {
    const info = result.ip_info || payload.ip_info;
    if (info.country) technicalParts.push(`Country: ${info.country}`);
    if (info.org || info.isp) technicalParts.push(`Org/ISP: ${info.org || info.isp}`);
  }
  if (result.url_info || payload.url_info) {
    const info = result.url_info || payload.url_info;
    if (info.domain) technicalParts.push(`Domain: ${info.domain}`);
  }

  return {
    indicator_type: rawType,
    target: target,
    verdict: verdict,
    risk_score: Number(riskScore),
    risk_max: 100,
    risk_level: result.risk_level || getRiskLevel(Number(riskScore)),
    confidence_score: Number(confidenceScore),
    confidence_max: 100,
    confidence_level: result.confidence_level || getConfidenceLevel(Number(confidenceScore)),
    threat_label: threatLabel,
    detections: detections,
    risk_factors: riskFactors,
    tags: tags,
    scan_id: scanId,
    technical_details: technicalParts.length > 0 ? technicalParts.join("; ") : undefined,
  };
}
