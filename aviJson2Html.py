#!/usr/bin/env python3
# json2html.py — JSON → interactive HTML graphs (Plotly)
#
# This version:
# - UI checkbox "Individual graphs":
#     • OFF (default): group charts by unit (multi-trace). X-axis title HIDDEN.
#     • ON: one chart per metric. X-axis title = metric label/description.
# - Legend shows metric IDs; zoom/pan sync across all visible charts.
# - Prompts for input & (optional) output name:
#     • If output left blank → defaults to <input_stem>.html
#     • If output has no extension → .html is added
#     • .htm/.html kept as-is; respects folders
# - Input existence check; if "<path>" missing but "<path>.json" exists → use it.
# - IST default YES; inline-JS default YES; human-readable Summary; no range slider.
#
# Requirements: Python 3.8+, plotly>=5, pandas

import argparse
import json
import logging
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go  # noqa: F401
from plotly.offline import plot as plot_offline  # noqa: F401


# ---------------------------- HTML TEMPLATE ----------------------------

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
${plotly_js}
<style>
  :root { --page-max-width: 100%; --interactive-cols: 1; }
  html, body { width: 100%; }
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

  .controls { display:flex; gap:12px; align-items: center; flex-wrap: wrap; margin: 8px 0 12px; }
  .controls .group { display:flex; gap:6px; align-items:center; }
  select[multiple] {
    min-width: 380px; min-height: 160px; padding: 6px; border: 1px solid #ddd; border-radius: 8px; background: #fff;
  }
  .warn { color: #b45309; background: #fff7ed; border: 1px solid #fed7aa; padding: 6px 8px; border-radius: 8px; display: none; }

  .charts-wrap { display: grid; grid-template-columns: repeat(var(--interactive-cols), 1fr); gap: 16px; }
  .chart-card { padding: 8px; border: 1px solid #eee; border-radius: 12px; box-shadow: 0 1px 4px rgba(0,0,0,.04); }
  .chart-title { font-weight: 600; margin-bottom: 6px; font-size: 14px; }
  .pill { display:inline-block; padding:2px 8px; border-radius: 999px; border:1px solid #ddd; font-size: 12px; color:#444; background:#fafafa; }

  /* Make plot containers expand fully */
  .chart-card > div { width: 100%; }
</style>
</head>
<body>
  <h1>${title}</h1>
  <div class="meta">
    <div><b>Entity:</b> ${entity_uuid} (${metric_entity})</div>
    <div><b>Window:</b> ${start} → ${stop} | <b>Step:</b> ${step}s | <b>Time Zone:</b> ${tz_label}</div>
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
      Tip: Use the checkbox below to switch between grouped-by-unit charts and individual charts.
      Zoom/pan any chart to sync the time window across all currently displayed charts.
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
      <div class="group">
        <label><input type="checkbox" id="chk-individual"> Individual graphs</label>
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

function populateMetricSelect() {
  const sel = document.getElementById('metric-select');
  if (!sel) return;
  sel.innerHTML = '';
  // Group options by unit for easier selection
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

function truncateLabel(s, maxLen=140) {
  if (!s) return '';
  return s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s;
}

function groupByUnit(selectedNames) {
  const out = {};
  for (const name of selectedNames) {
    const m = METRICS_DATA[name];
    if (!m) continue;
    const u = m.unit || "UNKNOWN";
    (out[u] ||= []).push(m);
  }
  return out;
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

  const individual = !!document.getElementById('chk-individual')?.checked;

  if (individual) {
    renderPerMetric(names, wrap);
  } else {
    renderGroupedByUnit(names, wrap);
  }
}

function renderPerMetric(names, wrap) {
  const chartIds = [];

  for (const metricName of names) {
    const m = METRICS_DATA[metricName];
    if (!m) continue;
    const unit = m.unit || "UNKNOWN";
    const xTitle = truncateLabel(m.label || m.metric);

    const card = document.createElement('div');
    card.className = 'chart-card';
    const title = document.createElement('div');
    title.className = 'chart-title';
    title.innerHTML = metricName + ' <span class="pill">' + unit + '</span>';
    const div = document.createElement('div');
    const chartId = 'chart-' + metricName.replace(/[^a-zA-Z0-9_-]/g,'_') + '-' + Math.random().toString(36).slice(2,8);
    div.id = chartId;
    card.appendChild(title);
    card.appendChild(div);
    wrap.appendChild(card);

    const traces = [{
      type: 'scatter',
      mode: 'lines+markers',
      x: m.x,
      y: m.y,
      name: metricName, // legend = metric ID (hidden for single trace)
      hovertemplate: 'Metric: ' + (m.label || m.metric) + '<br>Time: %{x}<br>Value: %{y}<extra></extra>'
    }];

    const containerWidth = div.clientWidth || window.innerWidth - 32;
    const layout = {
      title: '',
      xaxis: { title: xTitle },  // title = metric label/desc
      yaxis: { title: '' },      // remove Y-axis title
      hovermode: 'x unified',
      showlegend: false,
      margin: { t: 40, r: 30, b: 60, l: 60 },
      height: ${chart_height},
      autosize: true,
      width: containerWidth
    };

    Plotly.newPlot(chartId, traces, layout, {responsive: true});
    chartIds.push(chartId);

    window.addEventListener('resize', () => {
      const w = div.clientWidth || window.innerWidth - 32;
      Plotly.relayout(chartId, { width: w, height: ${chart_height} });
    });
  }

  if (chartIds.length > 1) {
    setupRangeSync(chartIds);
  }
}

function renderGroupedByUnit(names, wrap) {
  const byU = groupByUnit(names);
  const chartIds = [];

  for (const unit of Object.keys(byU)) {
    const metrics = byU[unit];
    if (!metrics.length) continue;

    // X-axis title hidden in grouped mode (per your request)
    const card = document.createElement('div');
    card.className = 'chart-card';
    const title = document.createElement('div');
    title.className = 'chart-title';
    title.innerHTML = 'Selected Metrics <span class="pill">' + unit + '</span>';
    const div = document.createElement('div');
    const chartId = 'chart-unit-' + unit.replace(/[^a-zA-Z0-9_-]/g,'_') + '-' + Math.random().toString(36).slice(2,8);
    div.id = chartId;
    card.appendChild(title);
    card.appendChild(div);
    wrap.appendChild(card);

    const traces = metrics.map(m => ({
      type: 'scatter',
      mode: 'lines+markers',
      x: m.x,
      y: m.y,
      name: m.metric, // legend shows metric IDs
      hovertemplate: 'Metric: ' + (m.label || m.metric) + '<br>Time: %{x}<br>Value: %{y}<extra></extra>'
    }));

    const containerWidth = div.clientWidth || window.innerWidth - 32;
    const layout = {
      title: '',
      xaxis: { title: '' },        // HIDE x-axis title in grouped mode
      yaxis: { title: '' },        // remove Y-axis title
      hovermode: 'x unified',
      showlegend: true,
      legend: { orientation: 'h', x: 0, xanchor: 'left', y: -0.25, yanchor: 'top', font: { size: 11 } },
      margin: { t: 40, r: 30, b: 150, l: 60 },
      height: ${chart_height},
      autosize: true,
      width: containerWidth
    };

    Plotly.newPlot(chartId, traces, layout, {responsive: true});
    chartIds.push(chartId);

    window.addEventListener('resize', () => {
      const w = div.clientWidth || window.innerWidth - 32;
      Plotly.relayout(chartId, { width: w, height: ${chart_height} });
    });
  }

  if (chartIds.length > 1) {
    setupRangeSync(chartIds);
  }
}

function setupRangeSync(chartIds) {
  let suppressSync = false;

  function parseRangeEvent(ev) {
    let r0 = null, r1 = null, autorange = null, changed = false;

    if (ev && Object.prototype.hasOwnProperty.call(ev, 'xaxis.autorange')) {
      autorange = !!ev['xaxis.autorange'];
      changed = true;
      return { r0, r1, autorange, changed };
    }

    if (Array.isArray(ev?.['xaxis.range'])) {
      r0 = ev['xaxis.range'][0];
      r1 = ev['xaxis.range'][1];
      changed = true;
    } else if (
      Object.prototype.hasOwnProperty.call(ev || {}, 'xaxis.range[0]') &&
      Object.prototype.hasOwnProperty.call(ev || {}, 'xaxis.range[1]')
    ) {
      r0 = ev['xaxis.range[0]'];
      r1 = ev['xaxis.range[1]'];
      changed = true;
    }
    return { r0, r1, autorange, changed };
  }

  function applyRangeToAll(sourceId, r0, r1, autorange) {
    suppressSync = true;
    for (const id of chartIds) {
      if (id === sourceId) continue;
      if (autorange) {
        Plotly.relayout(id, { 'xaxis.autorange': true });
      } else if (r0 != null && r1 != null) {
        Plotly.relayout(id, { 'xaxis.range': [r0, r1], 'xaxis.autorange': false });
      }
    }
    setTimeout(() => { suppressSync = false; }, 0);
  }

  for (const id of chartIds) {
    const div = document.getElementById(id);
    div.on('plotly_relayout', (ev) => {
      if (suppressSync) return;
      const { r0, r1, autorange, changed } = parseRangeEvent(ev);
      if (!changed) return;
      applyRangeToAll(id, r0, r1, autorange);
    });
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

# ---------------------------- SAFE REPLACER ----------------------------

def render_html(template: str, mapping: dict) -> str:
    """Literal placeholder replacement for ${key} only."""
    out = template
    for k, v in mapping.items():
        out = out.replace("${" + k + "}", str(v))
    return out


# ---------------------------- ARG PARSING + PROMPTS ----------------------------

def prompt_str(prompt: str, default: str = "") -> str:
    msg = f"{prompt}"
    if default:
        msg += f" [{default}]"
    msg += ": "
    ans = input(msg).strip()
    return ans or default

def prompt_yes_no(prompt: str, default_yes: bool = True) -> bool:
    default = "Y" if default_yes else "N"
    ans = input(f"{prompt} (Y/N) [{default}]: ").strip().lower()
    if not ans:
        return default_yes
    return ans.startswith("y")

def parse_args():
    p = argparse.ArgumentParser(
        description="Convert metrics JSON to an interactive HTML (Summary + Interactive Select). Wide plots by default; bidirectional zoom/pan sync.",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
    )
    # We prompt if missing
    p.add_argument("-i", "--input", help="Input JSON file path ('.json' extension optional).")
    p.add_argument("-o", "--output", help="Output HTML file name/path (optional). If blank, uses <input_stem>.html")
    p.add_argument("--title", help='Page title (default: "Metrics Report").')

    # Flags that can be supplied non-interactively; if omitted, we will prompt Y/N
    p.add_argument("--inline-js", action="store_true", help="Embed Plotly JS inline (offline HTML).")
    p.add_argument("--ist", action="store_true", help="Shortcut for Asia/Kolkata timezone.")

    # Hidden defaults we do NOT prompt for
    p.add_argument("--chart-height", type=int, default=520, help=argparse.SUPPRESS)
    p.add_argument("--interactive-columns", type=int, default=1, help=argparse.SUPPRESS)
    p.add_argument("--narrow", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--timezone", "--tz", dest="timezone", default=None, help=argparse.SUPPRESS)
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    args = p.parse_args()

    # Prompt for required args if missing
    if not args.input:
        args.input = prompt_str("Enter input JSON file path")

    # Prompt for optional output name; empty means default to input_stem.html
    if args.output is None:
        args.output = prompt_str("Output HTML file name/path (optional)", "")

    # Title optional
    if not args.title:
        args.title = prompt_str("Title (optional)", "Metrics Report")

    # Decide IST if user didn't explicitly pass --ist (default YES)
    if "--ist" not in sys.argv:
        args.ist = prompt_yes_no("Render times in IST (Asia/Kolkata)?", default_yes=True)

    # Decide inline JS if user didn't explicitly pass --inline-js (default YES)
    if "--inline-js" not in sys.argv:
        args.inline_js = prompt_yes_no("Embed Plotly JS in the HTML (works fully offline)?", default_yes=True)

    # Timezone resolution (no custom tz prompt)
    args.timezone = "Asia/Kolkata" if args.ist else "UTC"
    return args


# ---------------------------- FILE HELPERS ----------------------------

def resolve_input_path(raw: str) -> Path:
    """Return an existing Path for input; if raw doesn't exist and raw+'.json' does, use that."""
    p = Path(raw).expanduser()
    if p.exists():
        return p.resolve()
    if p.suffix.lower() != ".json":
        p_json = p.with_suffix(".json")
        if p_json.exists():
            return p_json.resolve()
    return p.resolve()

def _ensure_html_suffix(p: Path) -> Path:
    """If path has neither .html nor .htm, append .html."""
    suf = p.suffix.lower()
    if suf in (".html", ".htm"):
        return p
    return p.with_suffix(".html")

def resolve_output_path(input_path: Path, raw_out: str | None) -> Path:
    """
    Determine output path:
      - If raw_out is empty/blank: use input_path.stem + '.html' in the same directory.
      - If raw_out has no .html/.htm suffix: append '.html'.
      - If directory parts are present, respect them.
    """
    if not raw_out:
        out = input_path.with_suffix(".html")
    else:
        p = Path(raw_out).expanduser()
        if p.parent == Path(""):  # just a filename
            p = Path.cwd() / p.name
        p = _ensure_html_suffix(p)
        out = p
    return out.resolve()


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

def _human_number(x):
    """Return a human-readable string: no scientific notation; K/M/B/T suffix; tidy decimals."""
    if pd.isna(x):
        return ""
    try:
        x = float(x)
    except Exception:
        return str(x)
    neg = x < 0
    x = abs(x)
    for unit, thresh in [("T", 1e12), ("B", 1e9), ("M", 1e6), ("K", 1e3)]:
        if x >= thresh:
            val = x / thresh
            s = f"{val:,.2f}".rstrip("0").rstrip(".") + unit
            return "-" + s if neg else s
    if x != int(x):
        s = f"{x:,.6f}".rstrip("0").rstrip(".")
    else:
        s = f"{int(x):,d}"
    return "-" + s if neg else s

def _fmt_ts(ts_str: str, tz_name: str) -> str:
    """Format a timestamp string into the given timezone; fallback to original if parse fails."""
    if not ts_str:
        return ""
    try:
        t = pd.to_datetime(ts_str, utc=True, errors="coerce")
        if pd.isna(t):
          return str(ts_str)
        t = t.tz_convert(tz_name)
        return t.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return str(ts_str)

def dataframe_to_html_table(df: pd.DataFrame, tz_name: str) -> str:
    if df.empty:
        return "<p class='note'>No statistics available.</p>"
    df2 = df.copy()
    for c in ["mean","min","max","sum","trend","num_samples"]:
        if c in df2.columns:
            df2[c] = df2[c].apply(_human_number)
    for c in ["min_ts","max_ts"]:
        if c in df2.columns:
            df2[c] = df2[c].apply(lambda s: _fmt_ts(s, tz_name))
    cols = ["metric","units","description","mean","min","min_ts","max","max_ts","sum","trend","num_samples"]
    cols = [c for c in cols if c in df2.columns]
    return df2[cols].to_html(index=False, classes="stats", border=0, escape=False)

def to_label(metric: str, description: str):
    return description or metric

def build_metrics_json_for_js(df_all: pd.DataFrame, tz_name: str) -> str:
    """
    JSON for client-side plotting in requested timezone:
    { "<metric>": { "metric": ..., "unit": ..., "label": ..., "x": [...], "y": [...] }, ... }
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
                tt = pd.Timestamp(t).tz_convert(tz_name)
                times.append(tt.isoformat())
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

    # Resolve input path (allow implicit ".json")
    in_raw = args.input
    in_path = resolve_input_path(in_raw)
    if not in_path.exists():
        logging.error(
            "Input file not found: %s\nHint: If your file is named '%s.json', you can pass '%s' (without .json) or the full name.",
            in_raw, Path(in_raw).name, in_raw
        )
        raise SystemExit(2)

    # Resolve output path (handle optional prompt value)
    out_path = resolve_output_path(in_path, (args.output or "").strip())

    tz_name = "Asia/Kolkata" if args.ist else "UTC"
    tz_label = "IST" if tz_name == "Asia/Kolkata" else tz_name

    logging.info("Reading: %s", in_path)
    data = load_json(in_path)

    # Header window times (convert for display)
    start_raw = data.get("start", "")
    stop_raw  = data.get("stop", "")
    start_disp = _fmt_ts(start_raw, tz_name) if start_raw else ""
    stop_disp  = _fmt_ts(stop_raw, tz_name) if stop_raw else ""
    step  = data.get("step", "")
    entity_uuid = data.get("entity_uuid", "")
    metric_entity = data.get("metric_entity", "")

    series_list = data.get("series", []) or []

    # Combine all series into one DataFrame
    frames = [make_dataframe(s) for s in series_list]
    if frames:
        df_all = pd.concat(frames, ignore_index=True)
    else:
        df_all = pd.DataFrame(columns=["time","value","metric","units","description"])

    # Stats table
    stats_df = collect_stats(series_list)
    stats_html = dataframe_to_html_table(stats_df, tz_name)

    # Plotly JS (inline if requested, else CDN)
    if args.inline_js:
        try:
            from plotly.offline import get_plotlyjs
            plotly_js = f"<script>{get_plotlyjs()}</script>"
        except Exception:
            logging.warning("Failed to inline Plotly JS; falling back to CDN.")
            plotly_js = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'
    else:
        plotly_js = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'

    # JS data for Interactive Select (X values converted to tz)
    metrics_json = build_metrics_json_for_js(df_all, tz_name)

    # Render
    html = render_html(HTML_TEMPLATE, {
        "title": args.title or "Metrics Report",
        "plotly_js": plotly_js,
        "entity_uuid": entity_uuid,
        "metric_entity": metric_entity,
        "start": start_disp,
        "stop": stop_disp,
        "step": (step if step is not None else ""),
        "summary_table": stats_html,
        "metrics_json": metrics_json,
        "tz_label": tz_label,
        "chart_height": args.chart_height,
    })

    logging.info("Writing HTML: %s", out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    logging.info("Done. Open %s in your browser.", out_path)


if __name__ == "__main__":
    main()
