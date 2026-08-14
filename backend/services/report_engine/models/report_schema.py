from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class FiveW1HSchema(BaseModel):
    """5W1H (Who, What, Where, When, Why, How) Framework Schema."""
    who: Dict[str, Any] = Field(
        default_factory=dict,
        description="Target, user, entity, or actor details"
    )
    what: Dict[str, Any] = Field(
        default_factory=dict,
        description="Artifact name, threat type, hash, or category"
    )
    where: Dict[str, Any] = Field(
        default_factory=dict,
        description="Endpoint, URL, file path, IP, or network domain location"
    )
    when: Dict[str, Any] = Field(
        default_factory=dict,
        description="Timestamp of scan, detection, or occurrence"
    )
    why: Dict[str, Any] = Field(
        default_factory=dict,
        description="Severity, risk score, confidence rating, and rationale"
    )
    how: Dict[str, Any] = Field(
        default_factory=dict,
        description="Vectors, behaviors, indicators, and recommended actions"
    )


class ReportMetadata(BaseModel):
    """Metadata for generated report."""
    report_id: str = Field(..., description="Unique ID for the report")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of generation"
    )
    title: str = Field(default="SHADOW Cyber Threat Analysis Report")
    version: str = Field(default="1.0")
    target_type: Optional[str] = Field(default=None, description="file, url, domain, ip, hash")
    target_identifier: Optional[str] = Field(default=None, description="Target name or value")


class ExecutiveSummarySchema(BaseModel):
    """Placeholder for V2 Executive Summary."""
    summary_text: Optional[str] = None
    key_findings: List[str] = Field(default_factory=list)


class IOCSummarySchema(BaseModel):
    """Placeholder for V2 IOC Summary."""
    iocs: List[Dict[str, Any]] = Field(default_factory=list)


class TimelineSchema(BaseModel):
    """Placeholder for V2 Event Timeline."""
    events: List[Dict[str, Any]] = Field(default_factory=list)


class TechnicalSummarySchema(BaseModel):
    """Placeholder for V2 Technical Summary."""
    details: Dict[str, Any] = Field(default_factory=dict)


class ReportSchema(BaseModel):
    """Complete SHADOW Report Data Schema."""
    metadata: ReportMetadata
    fivew1h: FiveW1HSchema
    executive_summary: Optional[ExecutiveSummarySchema] = None
    ioc_summary: Optional[IOCSummarySchema] = None
    timeline: Optional[TimelineSchema] = None
    technical_summary: Optional[TechnicalSummarySchema] = None
