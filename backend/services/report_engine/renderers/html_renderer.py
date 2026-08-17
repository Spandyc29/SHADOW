import html
from typing import Dict, Any, List
from services.report_engine.models.report_schema import ReportSchema


class HTMLRenderer:
    """
    SHADOW HTML Report Renderer (V1).

    Renders a ReportSchema object into a standalone HTML report
    with embedded CSS styles.
    """

    def render(self, report: ReportSchema) -> str:
        meta = report.metadata
        f5 = report.fivew1h

        def escape(val: Any) -> str:
            if val is None:
                return "N/A"
            if isinstance(val, dict):
                v_clean = val.get("value") or val.get("category") or val.get("name") or val.get("label") or val.get("tag")
                if v_clean is not None and not isinstance(v_clean, (dict, list)):
                    return html.escape(str(v_clean))
            if isinstance(val, (dict, list)):
                return html.escape(str(val))
            return html.escape(str(val))

        def is_empty_val(val: Any) -> bool:
            if val is None:
                return True
            s = str(val).strip().lower()
            if s in ["", "n/a", "not available", "not applicable", "none", "null", "[]", "{}"]:
                return True
            if isinstance(val, list) and not val:
                return True
            if isinstance(val, dict):
                if "value" in val:
                    return is_empty_val(val["value"])
                return all(is_empty_val(v) for v in val.values())
            return False

        def render_kv_list(data_dict: Dict[str, Any], section_name: str = "") -> str:
            items_html = []
            valid_items = [(k, v) for k, v in data_dict.items() if not is_empty_val(v)]
            
            if not valid_items:
                return f"<div class='info-empty-note'>Telemetry for {section_name.lower() or 'this section'} not applicable for this indicator type.</div>"

            for k, v in valid_items:
                label = k.replace("_", " ").title()
                is_hash = any(hk in k.lower() for hk in ["hash", "md5", "sha1", "sha256"])
                val_class = "info-value info-value-hash" if is_hash else "info-value"

                if isinstance(v, list):
                    val_str = "<ul style='margin: 0; padding-left: 18px; text-align: left;'>" + "".join([f"<li>{escape(i)}</li>" for i in v]) + "</ul>"
                elif isinstance(v, dict):
                    if "value" in v:
                        val_str = escape(v["value"])
                    else:
                        val_str = "<div style='font-family: monospace; background: rgba(0,0,0,0.04); padding: 6px 10px; border-radius: 4px; text-align: left;'>" + "".join([f"<div><strong>{html.escape(str(dk))}:</strong> {escape(dv)}</div>" for dk, dv in v.items() if not is_empty_val(dv)]) + "</div>"
                else:
                    val_str = escape(v)

                items_html.append(f"""
                <div class="info-row">
                    <span class="info-label">{html.escape(label)}</span>
                    <span class="{val_class}">{val_str}</span>
                </div>
                """)
            return "".join(items_html)

        risk_score = f5.why.get("risk_score", 0)
        risk_max = f5.why.get("risk_max", 90)
        risk_level = str(f5.why.get("risk_level", "LOW")).upper()
        confidence_score = f5.why.get("confidence_score", 0)
        confidence_level = str(f5.why.get("confidence_level", "NEUTRAL")).upper()

        risk_badge_class = "badge-low"
        if risk_level in ["CRITICAL", "HIGH"]:
            risk_badge_class = "badge-high"
        elif risk_level == "MEDIUM":
            risk_badge_class = "badge-medium"

        recommendations: List[str] = f5.how.get("recommendations", [])
        recs_html = "".join([f"<li class='rec-item'>{escape(rec)}</li>" for rec in recommendations])

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escape(meta.title)} - {escape(meta.report_id)}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --card-border: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --risk-critical: #ef4444;
            --risk-medium: #f59e0b;
            --risk-low: #10b981;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 32px 16px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--card-border);
            padding-bottom: 20px;
            margin-bottom: 28px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .brand-logo {{
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: #fff;
            font-size: 18px;
        }}
        .brand-title {{
            font-size: 24px;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: var(--text-main);
            -webkit-text-fill-color: var(--text-main);
            background: none;
        }}
        .meta-tag {{
            font-size: 13px;
            color: var(--text-muted);
            text-align: right;
        }}
        .metrics-banner {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .metric-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        .metric-value {{
            font-size: 28px;
            font-weight: 800;
        }}
        .badge-high {{ color: var(--risk-critical); }}
        .badge-medium {{ color: var(--risk-medium); }}
        .badge-low {{ color: var(--risk-low); }}

        .section-title {{
            font-size: 18px;
            font-weight: 600;
            color: var(--accent-cyan);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .grid-5w1h {{
            display: flex;
            flex-direction: column;
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            width: 100%;
            box-sizing: border-box;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 18px 24px;
            height: auto;
        }}
        .card-header {{
            font-size: 15px;
            font-weight: 700;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 10px;
            margin-bottom: 14px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-main);
        }}
        .info-row {{
            display: grid;
            grid-template-columns: 180px 1fr;
            align-items: baseline;
            gap: 16px;
            padding: 6px 0;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            text-align: left;
        }}
        .info-row:last-child {{
            border-bottom: none;
        }}
        .info-label {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 700;
            text-align: left;
        }}
        .info-value {{
            font-size: 13px;
            color: var(--text-main);
            overflow-wrap: break-word;
            word-break: normal;
            text-align: left;
        }}
        .info-value-hash {{
            word-break: break-all !important;
            font-family: monospace !important;
        }}
        .info-empty-note {{
            font-size: 12px;
            color: var(--text-muted);
            font-style: italic;
            padding: 6px 0;
            text-align: left;
        }}
        .recommendations-box {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 32px;
        }}
        .rec-list {{
            list-style: disc;
            padding-left: 20px;
        }}
        .rec-item {{
            margin-bottom: 8px;
            color: #d1d5db;
        }}
        footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            border-top: 1px solid var(--card-border);
            padding-top: 20px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .card, .metric-card, .recommendations-box {{ border: 1px solid #ccc; background: #fff; color: #000; }}
            .info-value {{ color: #111; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-logo">S</div>
                <div class="brand-title">SHADOW Security Report</div>
            </div>
            <div class="meta-tag">
                <div><strong>Report ID:</strong> {escape(meta.report_id)}</div>
                <div><strong>Generated:</strong> {escape(meta.generated_at)}</div>
            </div>
        </header>

        <div class="metrics-banner">
            <div class="metric-card">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value {risk_badge_class}">{escape(risk_level)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">{escape(risk_score)} / {escape(risk_max)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Confidence Score</div>
                <div class="metric-value">{escape(confidence_score)} / 100</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Confidence Level</div>
                <div class="metric-value" style="color: var(--accent-cyan);">{escape(confidence_level)}</div>
            </div>
        </div>

        <div class="section-title">📌 5W1H Threat Intelligence Breakdown</div>

        <div class="grid-5w1h">
            <!-- WHO -->
            <div class="card">
                <div class="card-header">1. WHO (Target Context)</div>
                {render_kv_list(f5.who, "WHO")}
            </div>

            <!-- WHAT -->
            <div class="card">
                <div class="card-header">2. WHAT (Artifact & Threat)</div>
                {render_kv_list(f5.what, "WHAT")}
            </div>

            <!-- WHERE -->
            <div class="card">
                <div class="card-header">3. WHERE (Location & Path)</div>
                {render_kv_list(f5.where, "WHERE")}
            </div>

            <!-- WHEN -->
            <div class="card">
                <div class="card-header">4. WHEN (Timestamps)</div>
                {render_kv_list(f5.when, "WHEN")}
            </div>

            <!-- WHY -->
            <div class="card">
                <div class="card-header">5. WHY (Severity & Rationale)</div>
                {render_kv_list(f5.why, "WHY")}
            </div>

            <!-- HOW -->
            <div class="card">
                <div class="card-header">6. HOW (Vectors & Execution)</div>
                {render_kv_list(f5.how, "HOW")}
            </div>
        </div>

        <div class="recommendations-box">
            <div class="section-title" style="margin-bottom: 12px;">🛡️ Actionable Mitigation Recommendations</div>
            <ul class="rec-list">
                {recs_html}
            </ul>
        </div>

        <footer>
            Generated by SHADOW Report Engine V1 • Autonomous Cybersecurity Intelligence Pipeline
        </footer>
    </div>
</body>
</html>
"""
        return html_content
