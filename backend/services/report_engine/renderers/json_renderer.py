import json
from services.report_engine.models.report_schema import ReportSchema


class JSONRenderer:
    """Placeholder Renderer for JSON format (V2)."""

    def render(self, report: ReportSchema) -> str:
        return json.dumps(report.model_dump(), indent=2)
