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

  const riskMax = (
    result.risk_max ??
    payload.risk_max ??
    result.max_score ??
    payload.max_score ??
    extraMeta.risk_max ??
    extraMeta.max_score ??
    result.why?.risk_max ??
    payload.why?.risk_max ??
    result.why?.max_score ??
    payload.why?.max_score ??
    90
  );

  return {
    indicator_type: rawType,
    target: target,
    verdict: verdict,
    risk_score: Number(riskScore),
    risk_max: Number(riskMax),
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
