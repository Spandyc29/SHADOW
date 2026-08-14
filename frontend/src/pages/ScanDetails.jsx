import { useState, useEffect, useCallback } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { getScan } from "../services/api";
import { useScanContext } from "../context/ScanContext";
import { normalizeScanContext } from "../utils/scanContextAdapter";
import AnalysisResult from "../components/analysis/AnalysisResult";
import { parseAndMergeScanData, buildMetadataFromScan, buildBasicPropertiesFromScan } from "./ScanResult";
import LoadingState from "../components/scan/LoadingState";
import ErrorState from "../components/scan/ErrorState";
import "../styles/upload.css";

function ScanDetails() {
  const navigate = useNavigate();
  const { id } = useParams();
  const { setScanContext, clearScanContext } = useScanContext();

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchScan = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      const response = await getScan(id);
      const data = response.data?.scan;

      if (!data) {
        throw new Error("No scan data found.");
      }

      setScan(data);
    } catch (err) {
      console.error("Fetch scan error:", err);
      setError(
        err.response?.data?.detail ||
          err.message ||
          "Failed to fetch scan details."
      );
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchScan();
  }, [fetchScan]);

  useEffect(() => {
    if (scan) {
      setScanContext(normalizeScanContext(scan));
    }
    return () => clearScanContext();
  }, [scan, setScanContext, clearScanContext]);

  if (loading) {
    return <LoadingState message="Loading Scan Details..." />;
  }

  if (error || !scan) {
    return (
      <ErrorState
        title="Unable to load scan"
        message={error || "Scan Not Found"}
        onRetry={fetchScan}
      />
    );
  }

  const mergedAnalysis = parseAndMergeScanData(scan);
  const meta = buildMetadataFromScan(scan, mergedAnalysis);
  const basicProperties = buildBasicPropertiesFromScan(scan, meta);

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
        showScanId={true}
        basicProperties={basicProperties}
        onBack={() => navigate("/history")}
        onNewScan={() => navigate("/upload")}
      />
    </div>
  );
}

export default ScanDetails;