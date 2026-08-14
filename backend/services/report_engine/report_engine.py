import hashlib
import uuid
from typing import Dict, Any, Union
from datetime import datetime, timezone
from services.report_engine.models.report_schema import ReportSchema, ReportMetadata
from services.report_engine.generators.fivew1h import FiveW1HGenerator, format_timestamp
from services.report_engine.generators.executive_summary import ExecutiveSummaryGenerator
from services.report_engine.generators.ioc_summary import IOCSummaryGenerator
from services.report_engine.generators.timeline import TimelineGenerator
from services.report_engine.generators.technical_summary import TechnicalSummaryGenerator
from services.report_engine.renderers.html_renderer import HTMLRenderer
from services.report_engine.renderers.json_renderer import JSONRenderer
from services.report_engine.renderers.pdf_renderer import PDFRenderer


class ReportEngine:
    """
    ⭐ Main Orchestrator for SHADOW Report Engine.

    Coordinates generators and renderers to build comprehensive cybersecurity
    threat analysis reports.

    V1 Supported Capabilities:
    - 5W1H Analysis Generation
    - Executive Summary Generation
    - IOC Summary Generation
    - Timeline Generation
    - Technical Summary Generation
    - HTML Report Rendering
    - JSON Export Rendering
    """

    def __init__(self):
        self.fivew1h_generator = FiveW1HGenerator()
        self.executive_summary_generator = ExecutiveSummaryGenerator()
        self.ioc_summary_generator = IOCSummaryGenerator()
        self.timeline_generator = TimelineGenerator()
        self.technical_summary_generator = TechnicalSummaryGenerator()
        self.html_renderer = HTMLRenderer()
        self.json_renderer = JSONRenderer()
        self.pdf_renderer = PDFRenderer()

    def build_report_schema(self, analysis_data: Dict[str, Any]) -> ReportSchema:
        """
        Builds the unified ReportSchema object from raw/normalized analysis data.
        """
        target_type = (
            analysis_data.get("target_type")
            or analysis_data.get("indicator_type")
            or "scan"
        )
        target_identifier = (
            analysis_data.get("indicator")
            or analysis_data.get("file_name")
            or analysis_data.get("url")
            or analysis_data.get("domain")
            or analysis_data.get("ip")
            or analysis_data.get("hash")
            or "Security Target"
        )

        report_id = analysis_data.get("id")
        if not report_id:
            h = hashlib.md5(f"{target_type}:{target_identifier}".encode("utf-8")).hexdigest()[:8].upper()
            report_id = f"REP-{h}"

        raw_gen_at = (
            analysis_data.get("created_at")
            or analysis_data.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        )
        generated_at = format_timestamp(raw_gen_at)

        metadata = ReportMetadata(
            report_id=report_id,
            generated_at=generated_at,
            target_type=str(target_type),
            target_identifier=str(target_identifier),
            title=f"SHADOW Cyber Threat Analysis Report ({target_identifier})"
        )

        fivew1h_data = self.fivew1h_generator.generate(analysis_data)
        executive_summary_data = self.executive_summary_generator.generate(analysis_data)
        ioc_summary_data = self.ioc_summary_generator.generate(analysis_data)
        timeline_data = self.timeline_generator.generate(analysis_data)
        technical_summary_data = self.technical_summary_generator.generate(analysis_data)

        return ReportSchema(
            metadata=metadata,
            fivew1h=fivew1h_data,
            executive_summary=executive_summary_data,
            ioc_summary=ioc_summary_data,
            timeline=timeline_data,
            technical_summary=technical_summary_data
        )

    def generate(self, analysis_data: Dict[str, Any], output_format: str = "html") -> Union[str, bytes, Dict[str, Any]]:
        """
        Main entry point for report generation.

        :param analysis_data: Dictionary containing normalized scan & analysis results
        :param output_format: Format to render ('html', 'json', 'pdf', 'schema', 'dict')
        :return: Rendered report as str (html/json), bytes (pdf), or dict (schema)
        """
        report_schema = self.build_report_schema(analysis_data)

        fmt = output_format.lower().strip()
        if fmt in ["schema", "dict"]:
            return report_schema.model_dump()
        elif fmt == "html":
            return self.html_renderer.render(report_schema)
        elif fmt == "json":
            return self.json_renderer.render(report_schema)
        elif fmt == "pdf":
            return self.pdf_renderer.render(report_schema)
        else:
            raise ValueError(f"Unsupported report format: {output_format}")
