import { useEffect } from "react";
import BasicProperties from "./common/BasicProperties";
import ConfidenceCard from "./common/ConfidenceCard";
import RecommendationCard from "./common/RecommendationCard";
import ResultHeader from "./common/ResultHeader";
import RiskCard from "./common/RiskCard";
import TechnicalDetails from "./common/TechnicalDetails";
import ThreatDetails from "./common/ThreatDetails";

import DNSCard from "./domain/DNSCard";
import DNSRecordsCard from "./domain/DNSRecordsCard";
import DomainOverview from "./domain/DomainOverview";
import WhoisCard from "./domain/WhoisCard";

import FileInformation from "./file/FileInformation";
import FilePreview from "./file/FilePreview";
import IOCExtraction from "./file/IOCExtraction";

import URLInformation from "./url/URLInformation";
import IPOverview from "./ip/IPOverview";
import GeolocationCard from "./ip/GeolocationCard";
import NetworkInformationCard from "./ip/NetworkInformationCard";
import { useScanContext } from "../../context/ScanContext";
import { normalizeScanContext } from "../../utils/scanContextAdapter";

function AnalysisResult({
  result,
  title = "Investigation Report",
  indicatorLabel = "Indicator",
  indicatorValue,
  indicatorType,
  scanId,
  scannedAt,
  showScanId = false,
  basicProperties = [],
  threatDetails,
  onBack,
  onNewScan,
}) {
  const { setScanContext, clearScanContext } = useScanContext();

  useEffect(() => {
    if (result) {
      const contextData = normalizeScanContext(result, {
        title,
        indicatorLabel,
        indicatorValue,
        indicatorType,
        scanId,
        scannedAt,
      });
      setScanContext(contextData);
    }
    return () => {
      clearScanContext();
    };
  }, [result, indicatorValue, indicatorType, scanId, title, indicatorLabel, scannedAt, setScanContext, clearScanContext]);

  const normalizedType = (indicatorType || result?.indicator_type || result?.analysis_type || "").toLowerCase();

  const isDomain =
    normalizedType === "domain" ||
    Boolean(result?.domain_info) ||
    Boolean(result?.whois_info);

  const isUrl = normalizedType === "url" || Boolean(result?.url_info);
  const isIp = normalizedType === "ip" || Boolean(result?.ip_info);

  if (isDomain) {
    return (
      <div className="w-full flex flex-col gap-8">
        {/* 1. RESULT HEADER */}
        <ResultHeader
          result={result}
          title={title || "Domain Intelligence Report"}
          indicatorLabel={indicatorLabel || "Domain"}
          indicatorValue={indicatorValue}
          indicatorType={indicatorType || "Domain"}
          scanId={scanId}
          scannedAt={scannedAt}
          showScanId={showScanId}
          onBack={onBack}
          onNewScan={onNewScan}
        />

        {/* 2. DOMAIN OVERVIEW */}
        <DomainOverview result={result} />

        {/* 3. WHOIS INFORMATION */}
        <WhoisCard result={result} />

        {/* 4. DNS INFORMATION */}
        <DNSCard result={result} />

        {/* 5. DNS RECORDS */}
        <DNSRecordsCard result={result} />

        {/* 6. THREAT DETAILS */}
        {threatDetails || <ThreatDetails result={result} />}

        {/* 7 & 8. RISK ASSESSMENT & CONFIDENCE ASSESSMENT */}
        <div className="grid gap-8 lg:grid-cols-2">
          <RiskCard result={result} />
          <ConfidenceCard result={result} />
        </div>

        {/* 9. RECOMMENDATION */}
        <RecommendationCard result={result} />

        {/* 10. TECHNICAL DETAILS */}
        <div className="space-y-6 pt-4">
          <TechnicalDetails result={result} />
        </div>
      </div>
    );
  }

  if (isIp) {
    return (
      <div className="w-full flex flex-col gap-8">
        {/* 1. RESULT HEADER */}
        <ResultHeader
          result={result}
          title={title || "IP Intelligence Report"}
          indicatorLabel={indicatorLabel || "IP"}
          indicatorValue={indicatorValue}
          indicatorType={indicatorType || "IP"}
          scanId={scanId}
          scannedAt={scannedAt}
          showScanId={showScanId}
          onBack={onBack}
          onNewScan={onNewScan}
        />

        {/* 2. IP OVERVIEW */}
        <IPOverview result={result} />

        {/* 3. GEOLOCATION */}
        <GeolocationCard result={result} />

        {/* 4. NETWORK INFORMATION */}
        <NetworkInformationCard result={result} />

        {/* 5. THREAT DETAILS */}
        {threatDetails || <ThreatDetails result={result} />}

        {/* 6 & 7. RISK & CONFIDENCE ASSESSMENT */}
        <div className="grid gap-8 lg:grid-cols-2">
          <RiskCard result={result} />
          <ConfidenceCard result={result} />
        </div>

        {/* 8. RECOMMENDATION */}
        <RecommendationCard result={result} />

        {/* 9. TECHNICAL DETAILS */}
        <div className="space-y-6 pt-4">
          <TechnicalDetails result={result} />
        </div>
      </div>
    );
  }

  if (isUrl) {
    return (
      <div className="w-full flex flex-col gap-8">
        <ResultHeader
          result={result}
          title={title || "URL Intelligence Report"}
          indicatorLabel={indicatorLabel || "URL"}
          indicatorValue={indicatorValue}
          indicatorType={indicatorType || "URL"}
          scanId={scanId}
          scannedAt={scannedAt}
          showScanId={showScanId}
          onBack={onBack}
          onNewScan={onNewScan}
        />
        <div className="grid gap-8 lg:grid-cols-12">
          <div className="lg:col-span-7">
            <URLInformation urlInfo={result?.url_info || { url: indicatorValue }} communityReputation={result?.community_reputation} />
          </div>
          <div className="lg:col-span-5">
            <RecommendationCard result={result} />
          </div>
        </div>
        <div className="grid gap-8 lg:grid-cols-3">
          <RiskCard result={result} />
          <ConfidenceCard result={result} />
          <div className="lg:col-span-1">
            {threatDetails || <ThreatDetails result={result} />}
          </div>
        </div>
        <div className="space-y-6 pt-4">
          <TechnicalDetails result={result} />
        </div>
      </div>
    );
  }

  return (
    <div className="w-full flex flex-col gap-8">
      {/* 1. HEADER SECTION */}
      <ResultHeader
        result={result}
        title={title}
        indicatorLabel={indicatorLabel}
        indicatorValue={indicatorValue}
        indicatorType={indicatorType}
        scanId={scanId}
        scannedAt={scannedAt}
        showScanId={showScanId}
        onBack={onBack}
        onNewScan={onNewScan}
      />

      {/* 2. BASIC PROPERTIES & RECOMMENDED ACTION */}
      <div className="grid gap-8 lg:grid-cols-12">
        <div className="lg:col-span-7">
          <BasicProperties items={basicProperties} />
        </div>
        <div className="lg:col-span-5">
          <RecommendationCard result={result} />
        </div>
      </div>

      <FileInformation fileType={typeof result?.file_type === "object" ? result.file_type : null} />

      <IOCExtraction ioc={result?.ioc} />

      <FilePreview lines={result?.preview} />

      {/* 3. RISK, CONFIDENCE & THREAT DETAILS */}
      <div className="grid gap-8 lg:grid-cols-3">
        <RiskCard result={result} />
        <ConfidenceCard result={result} />
        <div className="lg:col-span-1">
          {threatDetails || <ThreatDetails result={result} />}
        </div>
      </div>

      {/* 4. TECHNICAL DETAILS / ACCORDION SECTION */}
      <div className="space-y-6 pt-4">
        <TechnicalDetails result={result} />
      </div>
    </div>
  );
}

export default AnalysisResult;
