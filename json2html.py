#!/usr/bin/env python3
# json2html.py
#
# Convert Avi/NSX ALB-style JSON metrics into a self-contained interactive HTML report.
#
# Key features:
# - Accepts a JSON file (-i/--input) and outputs a standalone HTML (-o/--output).
# - Layouts: per-unit (default) to group traces by units, or per-metric (one chart per metric).
# - Interactive Plotly charts: legend toggles, unified hover, range slider for quick zoom.
# - Summary stats table using header.statistics from the JSON.
# - --inline-js embeds Plotly JS for offline viewing; otherwise uses CDN.
#
# Requirements: Python 3.8+, plotly>=5, pandas
#
# ------------------------------------------------------------------------------

import argparse
import json
import logging
from pathlib import Path
from collections import OrderedDict

import pandas as pd
import plotly.graph_objects as go
from plotly.offline import plot as plot_offline

from string import Template

HTML_TEMPLATE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
${plotly_js}
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, "Helvetica Neue", Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji"; margin: 16px; }
  h1 { font-size: 20px; margin: 0 0 12px; }
  h2 { font-size: 16px; margin: 6px 0 8px; }
  .meta { color:#555; margin-bottom: 16px; }
  .tabs { display:flex; flex-wrap: wrap; gap:8px; margin: 16px 0 8px; }
  .tab-btn {
    padding: 6px 10px; border:1px solid #ddd; border-radius:10px; cursor:pointer;
    background:#f7f7f7; user-select:none;
  }
  .tab-btn.active { background:#e9f3ff; border-color:#bcd6ff; }
  .panel { display:none; }
  .panel.active { display:block; }
  table { border-collapse: collapse; width: 100%; margin-top: 10px; }
  th, td { border: 1px solid #e5e5e5; padding: 6px 8px; text-align: left; }
  th { background: #fafafa; }
  .note { font-size: 12px; color:#666; margin-top: 8px; }
</style>
</head>
<body>
  <h1>${title}</h1>
  <div class="meta">
    <div><b>Entity:</b> ${entity_uuid} (${metric_entity})</div>
    <div><b>Window:</b> ${start} → ${stop} | <b>Step:</b> ${step}s</div>
  </div>

  <div class="tabs" id="tabs">
    ${tab_buttons}
  </div>

  ${panels}

<script>
(function(){
  const tabs = document.querySelectorAll('.tab-btn');
  const panels = document.querySelectorAll('.panel');
  function activate(id) {
    tabs.forEach(t => t.classList.toggle('active', t.dataset.target === id));
    panels.forEach(p => p.classList.toggle('active', p.id === id));
  }
  tabs.forEach(t => t.addEventListener('click', () => activate(t.dataset.target)));
  if (tabs.length) activate(tabs[0].dataset.target);
})();
</script>
</body>
</html>
""")

def parse_args():
    epilog = r"""
EXAMPLES
--------

# 1) Basic usage (per-unit charts; CDN Plotly)
python json2html.py -i perfdata.json -o report.html --title "VS Metrics"

# 2) One chart per metric (useful when scales differ even within same unit)
python json2html.py -i perfdata.json -o report_per_metric.html --layout per-metric

# 3) Fully offline HTML (embed Plotly JS)
python json2html.py -i perfdata.json -o report_offline.html --inline-js

# 4) Verbose logs for troubleshooting
python json2html.py -i perfdata.json -o report.html -v

# 5) Windows PowerShell example (your case)
python.exe .\json2html.py -i .\perfdata.json -o upi.html --title UPI --layout per-unit --inline-js

NOTES
-----
- The script expects the JSON shape you posted: a top-level "series" array, and
  each series has "header" (with .name, .units, .statistics, etc.) and "data" (timestamp/value).
- If you see an empty chart, check that "series" has non-empty "data" arrays and timestamps parse correctly.
- If --inline-js fails to embed (rare), we automatically fall back to a CDN script tag.
"""
    p = argparse.ArgumentParser(
        description="Convert metrics JSON to an interactive HTML report (Plotly).",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog
    )
    p.add_argument("-i", "--input", required=True, help="Input JSON file path.")
    p.add_argument("-o", "--output", required=True, help="Output HTML file path.")
    p.add_argument("--title", default="Metrics Report", help="Page title.")
    p.add_argument("--layout", choices=["per-unit", "per-metric"], default="per-unit",
                   help="Chart grouping mode:\n  per-unit    -> one chart per units group (default)\n  per-metric  -> one chart per metric")
    p.add_argument("--inline-js", action="store_true",
                   help="Embed Plotly JS inline (offline HTML). If unavailable, falls back to CDN.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    return p.parse_args()

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def make_dataframe(series_entry):
    header = series_entry.get("header", {}) or {}
    name = header.get("name", "unknown")
    units = header.get("units", "UNKNOWN")
    desc  = header.get("metric_description", "") or name
    data  = series_entry.get("data", []) or []

    df = pd.DataFrame(data)
    if df.empty:
        return pd.DataFrame(columns=["time","value","metric","units","description"])

    df["time"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.drop(columns=["timestamp"], errors="ignore")
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df["metric"] = name
    df["units"] = units
    df["description"] = desc
    df = df.sort_values("time").reset_index(drop=True)
    return df[["time","value","metric","units","description"]]

def collect_stats(series_list):
    rows = []
    for s in series_list:
        h = s.get("header", {}) or {}
        st = h.get("statistics", {}) or {}
        rows.append({
            "metric": h.get("name",""),
            "units": h.get("units",""),
            "description": h.get("metric_description","") or h.get("name",""),
            "mean": st.get("mean", None),
            "min": st.get("min", None),
            "min_ts": st.get("min_ts", None),
            "max": st.get("max", None),
            "max_ts": st.get("max_ts", None),
            "sum": st.get("sum", None),
            "trend": st.get("trend", None),
            "num_samples": st.get("num_samples", None),
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["units","metric"], kind="stable")
    return df

def dataframe_to_html_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "<p class='note'>No statistics available.</p>"
    df2 = df.copy()
    for c in ["mean","min","max","sum","trend"]:
        if c in df2.columns:
            df2[c] = pd.to_numeric(df2[c], errors="coerce").round(6)
    cols = ["metric","units","description","mean","min","min_ts","max","max_ts","sum","trend","num_samples"]
    cols = [c for c in cols if c in df2.columns]
    return df2[cols].to_html(index=False, classes="stats", border=0, escape=False)

def to_label(metric: str, description: str):
    return description or metric

def build_figures(df_all: pd.DataFrame, layout_mode: str):
    panels = OrderedDict()
    if df_all.empty:
        return panels

    if layout_mode == "per-metric":
        for metric, dfx in df_all.groupby("metric", sort=True):
            units = (dfx["units"].iloc[0]) if not dfx.empty else ""
            title = f"{metric} ({units})"
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=dfx["time"], y=dfx["value"], mode="lines+markers",
                name=to_label(metric, dfx["description"].iloc[0] if not dfx.empty else metric),
                hovertemplate="Time: %{x}<br>Value: %{y}<extra></extra>"
            ))
            fig.update_layout(
                title=title,
                xaxis_title="Time (UTC)",
                yaxis_title=units,
                hovermode="x unified",
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
            )
            fig.update_xaxes(rangeslider=dict(visible=True))
            div = plot_offline(fig, include_plotlyjs=False, output_type="div")
            panel_id = f"panel-{len(panels)+1}"
            panels[panel_id] = (title, div)
        return panels

    # per-unit
    for units, dfg in df_all.groupby("units", sort=True):
        title = f"Metrics ({units})"
        fig = go.Figure()
        for metric, dfx in dfg.groupby("metric", sort=True):
            label = to_label(metric, dfx["description"].iloc[0] if not dfx.empty else metric)
            fig.add_trace(go.Scatter(
                x=dfx["time"], y=dfx["value"], mode="lines+markers",
                name=label,
                hovertemplate="Metric: " + label + "<br>Time: %{x}<br>Value: %{y}<extra></extra>"
            ))
        fig.update_layout(
            title=title,
            xaxis_title="Time (UTC)",
            yaxis_title=units,
            hovermode="x unified",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        )
        fig.update_xaxes(rangeslider=dict(visible=True))
        div = plot_offline(fig, include_plotlyjs=False, output_type="div")
        panel_id = f"panel-{len(panels)+1}"
        panels[panel_id] = (title, div)

    return panels

def build_plotly_script_tag(inline: bool) -> str:
    if not inline:
        return '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'
    # Try to embed JS
    try:
        # Available in plotly.offline
        from plotly.offline import get_plotlyjs
        js = get_plotlyjs()
        return f"<script>{js}</script>"
    except Exception:
        logging.warning("Failed to inline Plotly JS; falling back to CDN.")
        return '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'

def main():
    args = parse_args()
    logging.basicConfig(
        level=(logging.DEBUG if args.verbose else logging.INFO),
        format="[%(levelname)s] %(message)s"
    )

    in_path = Path(args.input).expanduser().resolve()
    out_path = Path(args.output).expanduser().resolve()

    if not in_path.exists():
        logging.error("Input file not found: %s", in_path)
        raise SystemExit(2)

    logging.info("Reading: %s", in_path)
    data = load_json(in_path)

    start = data.get("start", "")
    stop  = data.get("stop", "")
    step  = data.get("step", "")
    entity_uuid = data.get("entity_uuid", "")
    metric_entity = data.get("metric_entity", "")

    series_list = data.get("series", []) or []

    # Combine all series into one DataFrame
    frames = [make_dataframe(s) for s in series_list]
    df_all = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=["time","value","metric","units","description"])

    # Stats table
    stats_df = collect_stats(series_list)
    stats_html = dataframe_to_html_table(stats_df)

    # Build figures
    logging.info("Building charts using layout: %s", args.layout)
    panels_map = build_figures(df_all, layout_mode=args.layout)

    # Tabs + Panels HTML
    tab_btns = []
    panel_divs = []

    # Summary first
    tab_btns.append('<div class="tab-btn" data-target="panel-summary">Summary</div>')
    panel_divs.append(f'<div class="panel" id="panel-summary"><h2>Summary Statistics</h2>{stats_html}<div class="note">Tip: Click legend items in charts to hide/show series. Drag on the chart to zoom; use the range slider beneath for quick zooming.</div></div>')

    # Charts next
    for panel_id, (title, div) in panels_map.items():
        tab_btns.append(f'<div class="tab-btn" data-target="{panel_id}">{title}</div>')
        panel_divs.append(f'<div class="panel" id="{panel_id}">{div}</div>')

    # Plotly JS
    plotly_js = build_plotly_script_tag(args.inline_js)

    html = HTML_TEMPLATE.substitute(
        title=args.title,
        plotly_js=plotly_js,
        entity_uuid=entity_uuid,
        metric_entity=metric_entity,
        start=start,
        stop=stop,
        step=step if step is not None else "",
        tab_buttons="\n    ".join(tab_btns),
        panels="\n  ".join(panel_divs),
    )

    logging.info("Writing HTML: %s", out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    logging.info("Done. Open %s in your browser.", out_path)

if __name__ == "__main__":
    main()
