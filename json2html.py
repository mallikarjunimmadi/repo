#!/usr/bin/env python3
# json2html.py — JSON → interactive HTML graphs (Plotly)
#
# Streamlined per your request:
# - ONLY two tabs: Summary + Interactive Select (no static per-metric/per-unit panels)
# - NO Plotly range slider (removed)
#
# Still supports:
#   --chart-height <px>           (default 520)
#   --panel-width full|narrow     (default full; narrow ≈1100px)
#   --interactive-columns <int>   (default 1; # charts per row for Interactive tab)
#   --inline-js                   (embed Plotly JS; otherwise CDN)
#
# Requirements: Python 3.8+, plotly>=5, pandas

import argparse
import json
import logging
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go  # noqa: F401 (kept for future static additions)
from plotly.offline import plot as plot_offline  # noqa: F401 (kept for future static additions)


# ---------------------------- HTML TEMPLATE ----------------------------

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
${plotly_js}
<style>
  :root { --page-max-width: ${page_max_width}; --interactive-cols: ${interactive_cols}; }
  body {
    font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, "Helvetica Neue", Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji";
    margin: 16px;
    max-width: var(--page-max-width);
  }
  h1 { font-size: 20px; margin: 0 0 12px; }
  h2 { font-size: 16px; margin: 10px 0 8px; }
  .meta { color:#555; margin-bottom: 16px; }
  .tabs { display:flex; flex-wrap: wrap; gap:8px; margin: 16px 0 8px; }
  .tab-btn {
    padding: 6px 10px; border:1px solid #ddd; border-radius:10px; cursor:pointer;
    background:#f7f7f7; user-select:none;
  }
  .tab-btn.active { background:#e9f3ff; border-color:#bcd6ff; }
  .panel { display:none; }
  .panel.active { display:block; }
  .panel > div { width: 100%; }
  table { border-collapse: collapse; width: 100%; margin-top: 10px; }
  th, td { border: 1px solid #e5e5e5; padding: 6px 8px; text-align: left; }
  th { background: #fafafa; }
  .note { font-size: 12px; color:#666; margin-top: 8px; }

  .controls { display:flex; gap:8px; align-items: center; flex-wrap: wrap; margin: 8px 0 12px; }
  .controls .group { display:flex; gap:6px; align-items:center; }
  select[multiple] {
    min-width: 380px; min-height: 160px; padding: 6px; border: 1px solid #ddd; border-radius: 8px; background: #fff;
  }
  .warn { color: #b45309; background: #fff7ed; border: 1px solid #fed7aa; padding: 6px 8px; border-radius: 8px; display: none; }

  .charts-wrap { display: grid; grid-template-columns: repeat(var(--interactive-cols), 1fr); gap: 16px; }
  .chart-card { padding: 8px; border: 1px solid #eee; border-radius: 12px; box-shadow: 0 1px 4px rgba(0,0,0,.04); }
  .chart-title { font-weight: 600; margin-bottom: 6px; font-size: 14px; }
  .pill { display:inline-block; padding:2px 8px; border-radius: 999px; border:1px solid #ddd; font-size: 12px; color:#444; background:#fafafa; }
</style>
</head>
<body>
  <h1>${title}</h1>
  <div class="meta">
    <div><b>Entity:</b> ${entity_uuid} (${metric_entity})</div>
    <div><b>Window:</b> ${start} → ${stop} | <b>Step:</b> ${step}s</div>
  </div>

  <div class="tabs" id="tabs">
    <div class="tab-btn" data-target="panel-summary">Summary</div>
    <div class="tab-btn" data-target="panel-interactive">Interactive Select</div>
  </div>

  <!-- Summary -->
  <div class="panel" id="panel-summary">
    <h2>Summary Statistics</h2>
    ${summary_table}
    <div class="note">
      Tip: In charts, click legend items to hide/show a series. Drag to zoom; double-click to reset view.
    </div>
  </div>

  <!-- Interactive Select -->
  <div class="panel" id="panel-interactive">
    <h2>Interactive Select</h2>
    <div class="controls">
      <div class="group">
        <label for="metric-select"><b>Metrics</b></label>
        <select id="metric-select" multiple></select>
      </div>
      <div class="group">
        <button id="btn-plot">Plot</button>
        <button id="btn-select-all">Select All</button>
        <button id="btn-clear">Clear</button>
      </div>
      <div id="warn" class="warn"></div>
    </div>
    <div class="charts-wrap" id="interactive-panels"></div>
  </div>

<script>
// ---- Data for Interactive Select ----
const METRICS_DATA = ${metrics_json};

// Build an index: metricName -> { unit, label, x[], y[] }
const METRIC_NAMES = Object.keys(METRICS_DATA).sort((a,b)=> a.localeCompare(b));

function byUnit(selectedNames) {
  const out = {};
  for (const name of selectedNames) {
    const m = METRICS_DATA[name];
    if (!m) continue;
    const u = m.unit || "UNKNOWN";
    (out[u] ||= []).push(m);
  }
  return out;
}

function populateMetricSelect() {
  const sel = document.getElementById('metric-select');
  if (!sel) return;
  sel.innerHTML = '';
  // group options by unit using <optgroup>
  const unitMap = {};
  for (const name of METRIC_NAMES) {
    const m = METRICS_DATA[name];
    const unit = m.unit || "UNKNOWN";
    (unitMap[unit] ||= []).push(name);
  }
  for (const unit of Object.keys(unitMap).sort((a,b)=>a.localeCompare(b))) {
    const og = document.createElement('optgroup');
    og.label = unit;
    for (const metricName of unitMap[unit]) {
      const opt = document.createElement('option');
      opt.value = metricName;
      opt.textContent = metricName + ' — ' + METRICS_DATA[metricName].label;
      og.appendChild(opt);
    }
    sel.appendChild(og);
  }
}

function getSelectedMetricNames() {
  const sel = document.getElementById('metric-select');
  return sel ? Array.from(sel.selectedOptions).map(o => o.value) : [];
}

function selectAllMetrics() {
  const sel = document.getElementById('metric-select');
  if (!sel) return;
  Array.from(sel.options).forEach(o => o.selected = true);
}

function clearSelection() {
  const sel = document.getElementById('metric-select');
  if (!sel) return;
  Array.from(sel.options).forEach(o => o.selected = false);
}

function showWarn(msg) {
  const w = document.getElementById('warn');
  if (!w) return;
  w.textContent = msg || '';
  w.style.display = msg ? 'block' : 'none';
}

function renderInteractive() {
  const names = getSelectedMetricNames();
  const wrap = document.getElementById('interactive-panels');
  if (!wrap) return;
  wrap.innerHTML = '';

  if (!names.length) {
    showWarn('Select one or more metrics and click Plot.');
    return;
  }
  showWarn('');

  const unitsMap = byUnit(names);
  for (const unit of Object.keys(unitsMap)) {
    const card = document.createElement('div');
    card.className = 'chart-card';
    const title = document.createElement('div');
    title.className = 'chart-title';
    title.innerHTML = 'Selected Metrics <span class="pill">' + unit + '</span>';
    const div = document.createElement('div');
    const chartId = 'chart-' + unit.replace(/[^a-zA-Z0-9_-]/g,'_') + '-' + Math.random().toString(36).slice(2,8);
    div.id = chartId;
    card.appendChild(title);
    card.appendChild(div);
    wrap.appendChild(card);

    const traces = [];
    for (const m of unitsMap[unit]) {
      traces.push({
        type: 'scatter',
        mode: 'lines+markers',
        x: m.x,
        y: m.y,
        name: m.label || m.metric,
        hovertemplate: 'Metric: ' + (m.label || m.metric) + '<br>Time: %{x}<br>Value: %{y}<extra></extra>'
      });
    }

    const layout = {
      title: '',
      xaxis: { title: 'Time (UTC)' }, // rangeslider removed
      yaxis: { title: unit },
      hovermode: 'x unified',
      legend: { orientation: 'h', yanchor: 'bottom', y: 1.02, xanchor: 'left', x: 0 },
      height: ${chart_height}
    };
    Plotly.newPlot(chartId, traces, layout, {responsive: true});
  }
}

(function init(){
  // Tabs
  const tabs = document.querySelectorAll('.tab-btn');
  const panels = document.querySelectorAll('.panel');
  function activate(id) {
    tabs.forEach(t => t.classList.toggle('active', t.dataset.target === id));
    panels.forEach(p => p.classList.toggle('active', p.id === id));
  }
  tabs.forEach(t => t.addEventListener('click', () => activate(t.dataset.target)));
  if (tabs.length) activate(tabs[0].dataset.target);

  // Interactive tab setup
  populateMetricSelect();
  document.getElementById('btn-plot')?.addEventListener('click', renderInteractive);
  document.getElementById('btn-select-all')?.addEventListener('click', () => { selectAllMetrics(); renderInteractive(); });
  document.getElementById('btn-clear')?.addEventListener('click', () => { clearSelection(); renderInteractive(); });
})();
</script>
</body>
</html>
"""

# ---------------------------- HELPER: SAFE RENDER ----------------------------

def render_html(template: str, mapping: dict) -> str:
    """Literal placeholder replacement for ${key} only; won't touch other ${...} in JS you didn't pass."""
    out = template
    for k, v in mapping.items():
        out = out.replace("${" + k + "}", str(v))
    return out


# ---------------------------- ARG PARSING ----------------------------

def parse_args():
    epilog = r"""
EXAMPLES
--------

# 1) Basic run (offline HTML, bigger charts, 2 columns in Interactive)
python json2html.py -i perfdata.json -o report.html --title "UPI" \
  --inline-js --chart-height 650 --panel-width narrow --interactive-columns 2

# 2) Default sizes, CDN Plotly
python json2html.py -i perfdata.json -o report.html --title "VS Metrics"

TIPS
----
- Use Interactive Select to pick any subset of metrics; charts are grouped by their units.
- Click legend items to hide/show traces. Drag to zoom; double-click to reset view.
"""
    p = argparse.ArgumentParser(
        description="Convert metrics JSON to an interactive HTML report (Plotly). Only Summary + Interactive Select tabs (no static metric panels).",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog
    )
    p.add_argument("-i", "--input", required=True, help="Input JSON file path.")
    p.add_argument("-o", "--output", required=True, help="Output HTML file path.")
    p.add_argument("--title", default="Metrics Report", help="Page title.")
    p.add_argument("--inline-js", action="store_true",
                   help="Embed Plotly JS inline (offline HTML). If unavailable, falls back to CDN.")

    # Size controls
    p.add_argument("--chart-height", type=int, default=520,
                   help="Chart height in pixels for charts (default: 520).")
    p.add_argument("--panel-width", choices=["full", "narrow"], default="full",
                   help="Panel content width. 'full' (edge-to-edge) or 'narrow' (~1100px). Default: full.")
    p.add_argument("--interactive-columns", type=int, default=1,
                   help="Number of columns in the Interactive Select tab grid (default: 1).")

    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    return p.parse_args()


# ---------------------------- I/O + TRANSFORM ----------------------------

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

def build_metrics_json_for_js(df_all: pd.DataFrame) -> str:
    """
    Create JSON for client-side plotting:
    {
      "<metric>": {
        "metric": "<metric>",
        "unit": "<units>",
        "label": "<description or metric>",
        "x": ["2025-08-30T...Z", ...],
        "y": [value, ...]
      }, ...
    }
    """
    store = {}
    if df_all.empty:
        return json.dumps(store)
    for metric, dfx in df_all.groupby("metric", sort=True):
        dfx = dfx.sort_values("time")
        times = []
        for t in dfx["time"]:
            if pd.isna(t):
                times.append(None)
            else:
                times.append(pd.Timestamp(t).isoformat())
        store[metric] = {
            "metric": metric,
            "unit": dfx["units"].iloc[0],
            "label": to_label(metric, dfx["description"].iloc[0] if not dfx.empty else metric),
            "x": times,
            "y": [None if pd.isna(v) else float(v) for v in dfx["value"]]
        }
    return json.dumps(store, ensure_ascii=False)


# ---------------------------- MAIN ----------------------------

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

    # Plotly JS
    if args.inline_js:
        try:
            from plotly.offline import get_plotlyjs
            plotly_js = f"<script>{get_plotlyjs()}</script>"
        except Exception:
            logging.warning("Failed to inline Plotly JS; falling back to CDN.")
            plotly_js = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'
    else:
        plotly_js = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'

    # Width + columns CSS variables
    page_max_width = "100%" if args.panel_width == "full" else "1100px"
    interactive_cols = max(1, int(args.interactive_columns))

    # JS data for Interactive Select
    metrics_json = build_metrics_json_for_js(df_all)

    # Render
    html = render_html(HTML_TEMPLATE, {
        "title": args.title,
        "plotly_js": plotly_js,
        "entity_uuid": entity_uuid,
        "metric_entity": metric_entity,
        "start": start,
        "stop": stop,
        "step": (step if step is not None else ""),
        "summary_table": stats_html,
        "metrics_json": metrics_json,
        "chart_height": args.chart_height,
        "page_max_width": page_max_width,
        "interactive_cols": interactive_cols,
    })

    logging.info("Writing HTML: %s", out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    logging.info("Done. Open %s in your browser.", out_path)


if __name__ == "__main__":
    main()
