#!/usr/bin/env python3
# json2html.py — JSON → interactive HTML graphs (Plotly)
#
# - Multiple JSON files or directories; ignores non-JSON.
# - Validates/loads JSON; one HTML per JSON.
# - Top-level entity fields supported.
# - Interactive select; live plot/unplot by checking items.
# - Chevron collapse for left pane (handle stays visible, centered on divider).
# - Global & per-chart Legend toggle; synced zoom across charts; Reset Zoom.
# - Export CSV (global + per-chart) with "timestamp" + metric columns.
# - Jump to Top/Bottom (prefers right pane scroll).
# - Light/Dark theme + relayout of existing charts on toggle.

import argparse, json, logging, sys
from pathlib import Path
import pandas as pd
from plotly.offline import get_plotlyjs

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
${plotly_js}
<style>
  :root{
    --left-pane-width: 420px;   /* adjust to widen/narrow the selector */
    --gap: 16px;

    /* light */
    --bg:#f7f8fb; --card:#ffffff; --text:#0b1020; --muted:#5b6475; --border:#d9dee8;
    --chip:#eef2f8; --chip-text:#0b1020; --chip-border:#d9dee8;
    --chip-active:#2563eb; --chip-active-text:#ffffff; --chip-active-border:#2563eb;
    --pill:#eef2f8; --pill-text:#0b1020; --shadow:0 6px 16px rgba(0,0,0,.08);
  }
  [data-theme="dark"]{
    --bg:#0b1020; --card:#111a2d; --text:#e6e9f0; --muted:#98a3b8; --border:#1d2740;
    --chip:#182037; --chip-text:#e6e9f0; --chip-border:#263255;
    --chip-active:#2b66f8; --chip-active-text:#ffffff; --chip-active-border:#2b66f8;
    --pill:#1a233b; --pill-text:#e6e9f0; --shadow:0 6px 16px rgba(0,0,0,.25);
  }
  html,body{height:100%;margin:0}
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial;background:var(--bg);color:var(--text)}

  .header{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--card);position:sticky;top:0;z-index:50}
  h1{margin:0;font-size:18px}
  .meta{font-size:12px;color:var(--muted)}
  .meta b{color:var(--text)}
  .theme-toggle{
    margin-left:auto;border:1px solid var(--chip-border);background:var(--chip);color:var(--chip-text);
    width:36px;height:36px;border-radius:10px;display:grid;place-items:center;cursor:pointer;
  }

  .top-controls{
    display:flex;gap:10px;align-items:center;flex-wrap:wrap;
    padding:10px 16px;border-bottom:1px solid var(--border);background:var(--card);position:sticky;top:50px;z-index:40
  }
  .spacer{flex:1}

  .chip-btn{
    appearance:none;border:1px solid var(--chip-border);background:var(--chip);color:var(--chip-text);
    padding:8px 14px;border-radius:22px;font-size:13px;font-weight:600;cursor:pointer;transition:filter .15s ease;
  }
  .chip-btn:hover{filter:brightness(0.97)}
  .chip-btn.is-active{background:var(--chip-active);border-color:var(--chip-active-border);color:var(--chip-active-text)}

  /* MAIN GRID */
  .main{
    --lp: var(--left-pane-width);
    position:relative;
    display:grid;
    grid-template-columns: var(--lp) minmax(0,1fr);
    gap:var(--gap); padding:var(--gap)
  }
  .main.collapsed{ --lp: 0px; grid-template-columns: minmax(0,1fr); }
  .main.collapsed #left-pane{ display:none; }

  .pane{background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow)}
  .left{min-height:60vh;max-height:calc(100vh - 170px);overflow:auto}
  .right{min-height:60vh;max-height:calc(100vh - 170px);overflow:auto}

  /* Chevron handle: positioned on the divider; always visible */
  .chevron{
    position:absolute; top:50%; transform:translateY(-50%);
    left: calc(var(--gap) + var(--lp) - 12px);   /* center on divider; visible even when collapsed */
    width:42px;height:64px;border-radius:14px;border:1px solid var(--border);
    background:var(--card); color:var(--text); display:grid; place-items:center; cursor:pointer;
    box-shadow:var(--shadow); z-index:60; user-select:none;
  }
  .chevron span{font-size:20px;line-height:1}

  .section-title{padding:12px 14px;border-bottom:1px solid var(--border);font-weight:700}
  .controls-row{display:flex;gap:10px;align-items:center;padding:12px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap}
  .search{flex:1 1 260px;border:1px solid var(--border);border-radius:8px;padding:8px 10px;background:transparent;color:var(--text)}
  .list{padding:0 6px 10px 6px}

  .row{display:grid;grid-template-columns:20px 1fr auto;column-gap:10px;align-items:start;padding:9px 6px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none}
  .row:last-child{border-bottom:none}
  .row input[type="checkbox"]{margin-top:3px}
  .row > div{min-width:0}
  .name{font-size:13px;font-weight:400;line-height:1.25;overflow-wrap:anywhere}
  .desc{font-size:12px;color:var(--muted);overflow-wrap:anywhere}
  .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--border);background:var(--pill);color:var(--pill-text);font-size:11px;white-space:nowrap;margin-top:2px}

  .warn{display:none;margin:8px 14px;padding:6px 10px;border:1px solid #f4cf7b;border-radius:8px;background:#fff7e0;color:#664d03}
  [data-theme="dark"] .warn{border-color:#8b6d2d;background:#2a2210;color:#f6e7b0}

  .chart-card{padding:14px;border-top:1px dashed var(--border)}
  .chart-title{display:flex;gap:8px;align-items:center;font-size:14px;font-weight:600;margin-bottom:6px}
  .title-actions{margin-left:auto;display:flex;gap:6px}
  .mini-btn{border:1px solid var(--chip-border);background:var(--chip);color:var(--chip-text);padding:4px 8px;border-radius:999px;font-size:12px;cursor:pointer}
  .mini-btn.is-active{background:var(--chip-active);border-color:var(--chip-active-border);color:#fff}

  .jump{position:fixed;right:18px;bottom:22px;display:flex;flex-direction:column;gap:10px;z-index:70}
  .jump button{border:1px solid var(--chip-border);background:var(--chip);color:var(--chip-text);width:38px;height:38px;border-radius:10px;display:grid;place-items:center;cursor:pointer}

  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{border:1px solid var(--border);padding:6px 8px;text-align:left}
  th{background:var(--chip)}
</style>
</head>
<body data-theme="light">
  <div class="header">
    <h1>${title}</h1>
    <div class="meta">
      <div><b>Entity:</b> ${entity_uuid} (${metric_entity})</div>
      <div><b>Window:</b> ${start} → ${stop} &nbsp; | &nbsp; <b>Step:</b> ${step}s &nbsp; | &nbsp; <b>Time Zone:</b> ${tz_label}</div>
    </div>
    <button id="theme-toggle" class="theme-toggle" title="Toggle theme">🌓</button>
  </div>

  <div class="top-controls">
    <button id="tab-interactive" class="chip-btn is-active" type="button">Interactive Select</button>
    <button id="tab-summary"     class="chip-btn"           type="button">Summary</button>

    <button id="btn-plot"       class="chip-btn" type="button">Plot</button>
    <button id="btn-clear"      class="chip-btn" type="button">Clear Charts</button>
    <button id="btn-reset"      class="chip-btn" type="button">Reset Zoom</button>
    <button id="btn-individual" class="chip-btn" type="button">Individual graphs</button>

    <span class="spacer"></span>

    <button id="btn-legend"  class="chip-btn is-active" type="button">Legend</button>
    <button id="btn-export"  class="chip-btn"           type="button">Export CSV</button>
  </div>

  <div id="interactive-main" class="main">
    <div class="pane left" id="left-pane">
      <div class="section-title">Select Metrics</div>

      <div class="controls-row">
        <input id="search" class="search" placeholder="Search metrics or units..."/>
      </div>

      <div class="controls-row" style="border-bottom:none">
        <button id="btn-select-all"    class="chip-btn" type="button">Select All</button>
        <button id="btn-clear-metrics" class="chip-btn" type="button">Clear</button>
        <button id="btn-show-all"      class="chip-btn is-active" type="button">Show All</button>
        <button id="btn-show-selected" class="chip-btn" type="button">Show Selected (0)</button>
        <div style="margin-left:auto;color:var(--muted);font-size:12px"><span id="sel-count">0</span> selected</div>
      </div>

      <div id="warn" class="warn"></div>
      <div class="list" id="ms-body"></div>
    </div>

    <!-- Chevron handle on the divider (always visible) -->
    <div id="chevron" class="chevron" title="Hide/Show metrics"><span>❮</span></div>

    <div class="pane right" id="right-pane">
      <div class="chart-card" style="border-top:none">
        <div id="interactive-panels"></div>
      </div>
    </div>
  </div>

  <div id="summary-main" class="main" style="display:none">
    <div class="pane" style="grid-column:1 / -1; padding:14px">
      <h3 style="margin:4px 0 10px">Summary Statistics</h3>
      ${summary_table}
    </div>
  </div>

  <div class="jump">
    <button id="jump-up" title="Go to top">▲</button>
    <button id="jump-down" title="Go to bottom">▼</button>
  </div>

<script>
const METRICS_DATA = ${metrics_json};
const METRIC_NAMES = Object.keys(METRICS_DATA).sort((a,b)=> a.localeCompare(b));
const THEME_KEY = 'json2html-theme';
const PlotH = ${chart_height};

let legendDefaultOn = true;   // global legend baseline
let currentCharts = [];       // ids of currently-rendered Plotly divs

/* Helpers */
function esc(s){ return (s||'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
function themeColors(){
  const cs = getComputedStyle(document.body);
  const panel = cs.getPropertyValue('--card').trim();
  const text  = cs.getPropertyValue('--text').trim();
  const grid  = document.body.getAttribute('data-theme')==='dark' ? '#2d3a5d' : '#e3e7f3';
  return {panel,text,grid};
}
function applyThemeToCharts(){
  const t = themeColors();
  (currentCharts || []).forEach(id => {
    Plotly.relayout(id, {
      'paper_bgcolor': t.panel,
      'plot_bgcolor' : t.panel,
      'font.color'   : t.text,
      'legend.font.color': t.text,
      'xaxis.gridcolor': t.grid,
      'yaxis.gridcolor': t.grid,
      'xaxis.title.font.color': t.text,
      'yaxis.title.font.color': t.text,
      'xaxis.tickfont.color'  : t.text,
      'yaxis.tickfont.color'  : t.text
    });
  });
}

/* THEME BOOTSTRAP */
function setTheme(t){ document.body.setAttribute('data-theme',t); localStorage.setItem(THEME_KEY,t); }
(function(){
  setTheme(localStorage.getItem(THEME_KEY) || 'light');
  const btn = document.getElementById('theme-toggle');
  btn.onclick = () => {
    const next = document.body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    setTheme(next);
    applyThemeToCharts(); // reflect instantly on existing charts
  };
})();

/* TABS */
document.getElementById('tab-interactive').onclick = ()=> setActiveTab(true);
document.getElementById('tab-summary').onclick     = ()=> setActiveTab(false);
function setActiveTab(toInteractive){
  const a = document.getElementById('tab-interactive');
  const b = document.getElementById('tab-summary');
  a.classList.toggle('is-active', toInteractive);
  b.classList.toggle('is-active', !toInteractive);
  document.getElementById('interactive-main').style.display = toInteractive ? '' : 'none';
  document.getElementById('summary-main').style.display     = toInteractive ? 'none' : '';
}

/* CHEVRON (collapse) */
(function(){
  const main = document.getElementById('interactive-main');
  const chev = document.getElementById('chevron');
  function setArrow(){ chev.querySelector('span').textContent = main.classList.contains('collapsed') ? '❯' : '❮'; }
  chev.onclick = ()=>{ main.classList.toggle('collapsed'); setArrow(); };
  setArrow();
})();

/* JUMP buttons (prefer right pane, else page) */
function scrollTarget(){
  const rp = document.getElementById('right-pane');
  if (rp && rp.scrollHeight > rp.clientHeight) return rp;
  return document.scrollingElement || document.documentElement;
}
document.getElementById('jump-up').onclick   = ()=>{ const t=scrollTarget(); t.scrollTo({top:0,behavior:'smooth'}); };
document.getElementById('jump-down').onclick = ()=>{ const t=scrollTarget(); t.scrollTo({top:t.scrollHeight,behavior:'smooth'}); };

/* Left multi-select */
const MS = (() => {
  const state = { selected:new Set(), showOnlySelected:false, els:{} };
  const qs = id=>document.getElementById(id);

  function renderList(){
    const body = state.els.body; body.innerHTML='';
    const q = (state.els.search.value||'').toLowerCase();

    const names = METRIC_NAMES.filter(name=>{
      const m = METRICS_DATA[name]; const unit=(m.unit||'').toLowerCase();
      const hay=(name+' '+(m.label||'')+' '+unit).toLowerCase();
      const passQ=!q || hay.includes(q);
      const passSel = state.showOnlySelected ? state.selected.has(name) : true;
      return passQ && passSel;
    });

    for(const name of names){
      const m = METRICS_DATA[name];
      const row = document.createElement('div'); row.className='row';
      row.innerHTML =
        '<input type="checkbox" '+(state.selected.has(name)?'checked':'')+' data-name="'+name+'"/>' +
        '<div><div class="name">'+esc(name)+'</div><div class="desc">'+esc(m.label||m.metric||'')+'</div></div>' +
        '<span class="pill">'+esc(m.unit||'')+'</span>';

      row.addEventListener('click', (ev)=>{ if(ev.target.tagName==='INPUT') return; const cb=row.querySelector('input'); cb.checked=!cb.checked; toggle(name, cb.checked); });
      row.querySelector('input').addEventListener('change', e=> toggle(name, e.target.checked));
      body.appendChild(row);
    }
  }

  function toggle(name, checked){
    if(checked) state.selected.add(name); else state.selected.delete(name);
    updateCounts(); renderInteractive(); // live plot/unplot
  }

  function updateCounts(){
    qs('sel-count').textContent = state.selected.size;
    qs('btn-show-selected').textContent = `Show Selected (${state.selected.size})`;
  }

  function selectAllVisible(){
    state.els.body.querySelectorAll('input[type="checkbox"]').forEach(cb=>{ cb.checked=true; state.selected.add(cb.getAttribute('data-name')); });
    updateCounts(); renderInteractive();
  }
  function clearAll(){
    state.selected.clear();
    state.els.body.querySelectorAll('input[type="checkbox"]').forEach(cb=> cb.checked=false);
    updateCounts(); renderInteractive();
  }

  function init(){
    state.els = { body:qs('ms-body'), search:qs('search') };
    state.els.search.addEventListener('input', renderList);

    qs('btn-select-all').onclick    = selectAllVisible;
    qs('btn-clear-metrics').onclick = clearAll;
    qs('btn-show-all').onclick      = ()=>{ state.showOnlySelected=false; qs('btn-show-all').classList.add('is-active'); qs('btn-show-selected').classList.remove('is-active'); renderList(); };
    qs('btn-show-selected').onclick = ()=>{ state.showOnlySelected=!state.showOnlySelected; qs('btn-show-selected').classList.toggle('is-active',state.showOnlySelected); qs('btn-show-all').classList.toggle('is-active', !state.showOnlySelected); renderList(); };

    renderList(); updateCounts();
  }

  function getSelected(){ return Array.from(state.selected); }
  return { init, getSelected, _render:renderList };
})();
MS.init();

/* Plotly layout helpers */
function baseLayout(xTitle, showLegend, legendRows){
  const t = themeColors();
  const b = showLegend ? (legendRows>1?120:80) : 60;
  return {
    paper_bgcolor:t.panel, plot_bgcolor:t.panel, font:{color:t.text},
    margin:{t:24,r:18,b:b,l:54},
    xaxis:{title:xTitle, gridcolor:t.grid, automargin:true, titlefont:{color:t.text}, tickfont:{color:t.text}},
    yaxis:{title:'', gridcolor:t.grid, automargin:true, titlefont:{color:t.text}, tickfont:{color:t.text}},
    showlegend:showLegend,
    legend:{orientation:'h', x:0, xanchor:'left', y:-0.25, yanchor:'top', font:{size:11, color:t.text}}
  };
}

/* Sync X-range across all charts */
function setupRangeSync(ids){
  if(ids.length<=1) return;
  let suppress = false;

  function parse(ev){
    let r0=null,r1=null,auto=null,changed=false;
    if(ev && Object.prototype.hasOwnProperty.call(ev,'xaxis.autorange')){ auto=!!ev['xaxis.autorange']; changed=true; return {r0,r1,auto,changed}; }
    if(Array.isArray(ev?.['xaxis.range'])){ r0=ev['xaxis.range'][0]; r1=ev['xaxis.range'][1]; changed=true; }
    else if('xaxis.range[0]' in (ev||{}) && 'xaxis.range[1]' in (ev||{})){ r0=ev['xaxis.range[0]']; r1=ev['xaxis.range[1]']; changed=true; }
    return {r0,r1,auto,changed};
  }
  function apply(src,r0,r1,auto){
    suppress=true;
    for(const id of ids){ if(id===src) continue;
      if(auto) Plotly.relayout(id, {'xaxis.autorange':true});
      else if(r0!=null && r1!=null) Plotly.relayout(id, {'xaxis.range':[r0,r1],'xaxis.autorange':false});
    }
    setTimeout(()=>{suppress=false;},0);
  }

  for(const id of ids){
    const el=document.getElementById(id);
    el.on('plotly_relayout', ev => { if(suppress) return; const {r0,r1,auto,changed}=parse(ev); if(!changed) return; apply(id,r0,r1,auto); });
    el.on('plotly_doubleclick', () => { if(suppress) return; apply(id,null,null,true); });
  }
}

/* Render charts (called on selection changes, plot button, layout toggles) */
function renderInteractive(){
  const names = MS.getSelected();
  const wrap = document.getElementById('interactive-panels');
  wrap.innerHTML=''; currentCharts=[];

  if(!names.length) return;

  const individual = document.getElementById('btn-individual').classList.contains('is-active');

  if(individual){
    for(const metric of names){
      const m = METRICS_DATA[metric]; if(!m) continue;

      const card=document.createElement('div'); card.className='chart-card';
      const title=document.createElement('div'); title.className='chart-title';
      title.innerHTML = esc(metric)+' <span class="pill">'+esc(m.unit||'')+'</span>';
      const actions=document.createElement('div'); actions.className='title-actions';
      const btnCSV=document.createElement('button'); btnCSV.className='mini-btn'; btnCSV.textContent='CSV'; btnCSV.dataset.metrics=metric;
      const btnLeg=document.createElement('button'); btnLeg.className='mini-btn legend-mini'; btnLeg.textContent='Legend'; btnLeg.classList.toggle('is-active', legendDefaultOn);
      actions.appendChild(btnCSV); actions.appendChild(btnLeg); title.appendChild(actions);

      const div=document.createElement('div'); div.id='chart-'+Math.random().toString(36).slice(2,8); div.className='chart-host';
      card.appendChild(title); card.appendChild(div); wrap.appendChild(card);

      const traces=[{type:'scatter', mode:'lines+markers', x:m.x, y:m.y, name:metric, hovertemplate:(m.label||m.metric)+'<br>%{x}<br>%{y}<extra></extra>'}];
      Plotly.newPlot(div.id, traces, baseLayout(m.label||m.metric, legendDefaultOn, 1), {responsive:true,displaylogo:false}).then(()=>{
        Plotly.relayout(div.id,{height:PlotH}); currentCharts.push(div.id);
        if(currentCharts.length === names.length) { setupRangeSync(currentCharts); applyThemeToCharts(); }
      });
    }
  }else{
    const traces = names.map(n=>{
      const m = METRICS_DATA[n]; if(!m) return null;
      return {type:'scatter', mode:'lines+markers', x:m.x, y:m.y, name:n, hovertemplate:(m.label||m.metric)+'<br>%{x}<br>%{y}<extra></extra>'};
    }).filter(Boolean);

    const card=document.createElement('div'); card.className='chart-card';
    const title=document.createElement('div'); title.className='chart-title'; title.innerHTML='Selected Metrics';
    const actions=document.createElement('div'); actions.className='title-actions';
    const btnCSV=document.createElement('button'); btnCSV.className='mini-btn'; btnCSV.textContent='CSV'; btnCSV.dataset.metrics=names.join('|');
    const btnLeg=document.createElement('button'); btnLeg.className='mini-btn legend-mini'; btnLeg.textContent='Legend'; btnLeg.classList.toggle('is-active', legendDefaultOn);
    actions.appendChild(btnCSV); actions.appendChild(btnLeg); title.appendChild(actions);

    const div=document.createElement('div'); div.id='chart-'+Math.random().toString(36).slice(2,8); div.className='chart-host';
    card.appendChild(title); card.appendChild(div); wrap.appendChild(card);

    const rows = Math.ceil(traces.length/6);
    Plotly.newPlot(div.id, traces, baseLayout('', legendDefaultOn, rows), {responsive:true,displaylogo:false}).then(()=>{
      Plotly.relayout(div.id,{height:PlotH}); currentCharts.push(div.id);
      setupRangeSync(currentCharts); applyThemeToCharts();
    });
  }

  // per-chart CSV & per-chart legend buttons
  wrap.querySelectorAll('.mini-btn').forEach(btn=>{
    if(btn.dataset.metrics){
      btn.onclick = ()=> exportCSV(btn.dataset.metrics.split('|'));
    }else if(btn.classList.contains('legend-mini')){
      btn.onclick = (e)=>{
        const host = e.target.closest('.chart-card').querySelector('.chart-host').id;
        const makeOn = !(e.target.classList.contains('is-active'));
        e.target.classList.toggle('is-active', makeOn);
        Plotly.relayout(host, {'showlegend': makeOn});
      };
    }
  });
}

/* Top bar buttons */
document.getElementById('btn-plot').onclick  = renderInteractive;
document.getElementById('btn-clear').onclick = ()=>{ document.getElementById('interactive-panels').innerHTML=''; currentCharts=[]; };
document.getElementById('btn-reset').onclick = ()=>{ currentCharts.forEach(id => Plotly.relayout(id, {'xaxis.autorange':true, 'yaxis.autorange':true})); };
document.getElementById('btn-individual').onclick = (e)=>{ e.currentTarget.classList.toggle('is-active'); renderInteractive(); };

/* Global legend: sets baseline for current charts; mini toggles still allow per-chart changes after */
document.getElementById('btn-legend').onclick = (e)=>{
  legendDefaultOn = !legendDefaultOn;
  e.currentTarget.classList.toggle('is-active', legendDefaultOn);
  currentCharts.forEach(id => Plotly.relayout(id, {'showlegend': legendDefaultOn}));
  document.querySelectorAll('.legend-mini').forEach(b => b.classList.toggle('is-active', legendDefaultOn));
};

/* Global CSV */
document.getElementById('btn-export').onclick = ()=>{
  const names = MS.getSelected();
  if(!names.length){ alert('Select at least one metric to export.'); return; }
  exportCSV(names);
};

/* CSV helpers (timestamp + metric columns) */
function buildAlignedTable(metricNames){
  const ts = new Set(), map={};
  for(const name of metricNames){
    const m = METRICS_DATA[name]; if(!m) continue;
    const mp={}; for(let i=0;i<m.x.length;i++){ mp[m.x[i]] = m.y[i]; ts.add(m.x[i]); }
    map[name]=mp;
  }
  const timestamps = Array.from(ts).sort((a,b)=> new Date(a)-new Date(b));
  const header = ['timestamp', ...metricNames];
  const rows=[header];
  for(const t of timestamps){
    const row=[t];
    for(const name of metricNames){ const v = map[name]?.[t]; row.push((v==null||!isFinite(v))?'':v); }
    rows.push(row);
  }
  return rows;
}
function toCSV(rows){
  return rows.map(r => r.map(cell => {
    if (cell == null) return '';
    const s = String(cell);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
  }).join(',')).join('\n');
}
function downloadCSV(csv, base='metrics'){
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const ts = new Date().toISOString().replace(/[:T]/g,'-').slice(0,19);
  a.href = url; a.download = `${base}_${ts}.csv`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
function exportCSV(metricNames){
  if(!metricNames || !metricNames.length){ alert('No metrics selected/visible to export.'); return; }
  const csv = toCSV(buildAlignedTable(metricNames));
  downloadCSV(csv, 'metrics');
}
</script>
</body>
</html>
"""

def render_html(tmpl: str, mapping: dict) -> str:
    out = tmpl
    for k, v in mapping.items():
        out = out.replace("${" + k + "}", str(v))
    return out

def prompt_str(prompt: str, default: str = "") -> str:
    msg = f"{prompt}"
    if default: msg += f" [{default}]"
    msg += ": "
    ans = input(msg).strip()
    return ans or default

def prompt_yes_no(prompt: str, default_yes: bool = True) -> bool:
    default = "Y" if default_yes else "N"
    ans = input(f"{prompt} (Y/N) [{default}]: ").strip().lower()
    if not ans: return default_yes
    return ans.startswith("y")

def parse_args():
    p = argparse.ArgumentParser(description="JSON → interactive HTML graphs (Summary + Interactive Select).",
                                formatter_class=argparse.RawTextHelpFormatter, add_help=True)
    p.add_argument("-i","--input", nargs="+", help="Input .json files or directories.")
    p.add_argument("-o","--output", help="Output HTML path (optional). Defaults to input stem.")
    p.add_argument("--title", help='Page title (default: "Metrics Report").')
    p.add_argument("--inline-js", action="store_true", help="Embed Plotly JS for offline HTML.")
    p.add_argument("--ist", action="store_true", help="Use Asia/Kolkata timezone.")
    # hidden
    p.add_argument("--chart-height", type=int, default=520, help=argparse.SUPPRESS)
    p.add_argument("--timezone", "--tz", dest="timezone", default=None, help=argparse.SUPPRESS)
    p.add_argument("-v","--verbose", action="store_true", help="Verbose logging.")
    args = p.parse_args()

    if not args.input:
        args.input = [prompt_str("Enter input JSON file(s) or directory path(s)")]
        if not args.input[0]:
            p.error("Input path is required.")
    if args.output is None:
        args.output = ""
    if not args.title:
        args.title = prompt_str("Title (optional)", "Metrics Report")
    if "--ist" not in sys.argv:
        args.ist = prompt_yes_no("Render times in IST (Asia/Kolkata)?", default_yes=True)
    if "--inline-js" not in sys.argv:
        args.inline_js = prompt_yes_no("Embed Plotly JS in the HTML (works fully offline)?", default_yes=True)
    args.timezone = "Asia/Kolkata" if args.ist else "UTC"
    return args

def find_json_files(paths):
    files=[]
    for raw in paths:
        p=Path(raw).expanduser()
        if p.is_dir():
            logging.info(f"Searching for JSON files in directory: {p}")
            files.extend(p.rglob("*.json"))
        elif p.is_file():
            if p.suffix.lower()==".json": files.append(p)
            else: logging.warning(f"Skipping non-JSON: {p}")
        else:
            logging.error(f"Path does not exist: {p}")
    return sorted({f.resolve() for f in files})

def resolve_output_path(input_path: Path, raw_out: str|None) -> Path:
    if not raw_out: return input_path.with_suffix(".html").resolve()
    out=Path(raw_out).expanduser()
    if out.parent == Path(""): out = Path.cwd()/out.name
    if out.suffix.lower() not in (".html",".htm"): out = out.with_suffix(".html")
    return out.resolve()

def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read/parse {path}: {e}")
        return None

def make_dataframe(series_entry):
    header = series_entry.get("header", {}) or {}
    name = header.get("name","unknown")
    units= header.get("units","UNKNOWN")
    desc = header.get("metric_description","") or name
    data = series_entry.get("data", []) or []

    df = pd.DataFrame(data)
    if df.empty:
        logging.warning(f"Empty data for metric '{name}'")
        return pd.DataFrame(columns=["time","value","metric","units","description"])

    df["time"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df.drop(columns=["timestamp"], inplace=True, errors="ignore")
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df["metric"] = name; df["units"]=units; df["description"]=desc
    df.sort_values("time", inplace=True); df.reset_index(drop=True, inplace=True)
    return df[["time","value","metric","units","description"]]

def collect_stats(series_list):
    rows=[]
    for s in series_list:
        h=s.get("header",{}) or {}; st=h.get("statistics",{}) or {}
        rows.append({
            "metric":h.get("name",""), "units":h.get("units",""),
            "description":h.get("metric_description","") or h.get("name",""),
            "mean":st.get("mean"), "min":st.get("min"), "min_ts":st.get("min_ts"),
            "max":st.get("max"), "max_ts":st.get("max_ts"), "sum":st.get("sum"),
            "trend":st.get("trend"), "num_samples":st.get("num_samples")
        })
    df=pd.DataFrame(rows)
    if not df.empty: df.sort_values(["units","metric"], kind="stable", inplace=True)
    return df

def _fmt_ts(ts_str: str, tz: str) -> str:
    if not ts_str: return ""
    t=pd.to_datetime(ts_str, utc=True, errors="coerce")
    if pd.isna(t): return str(ts_str)
    return t.tz_convert(tz).strftime('%Y-%m-%d %H:%M:%S')

def _human_number(x):
    if pd.isna(x): return ""
    try: x=float(x)
    except Exception: return str(x)
    neg = x<0; x=abs(x)
    for u,th in [("T",1e12),("B",1e9),("M",1e6),("K",1e3)]:
        if x>=th: s=f"{x/th:,.2f}".rstrip("0").rstrip(".")+u; return ("-" if neg else "")+s
    s=f"{x:,.6f}".rstrip("0").rstrip(".") if x!=int(x) else f"{int(x):,d}"
    return ("-" if neg else "")+s

def process_file(file_path: Path, args):
    logging.info(f"Processing: {file_path}")
    data=load_json(file_path)
    if not data: return

    entity_uuid=data.get("entity_uuid","N/A")
    metric_entity=data.get("metric_entity","N/A")
    series=data.get("series",[])
    if not isinstance(series,list):
        logging.warning(f"Series in {file_path} is not a list; skipping.")
        return

    dfs=[make_dataframe(s) for s in series]
    all_df=pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame(columns=["time","value","metric","units","description"])
    all_df.dropna(subset=["time","value"], inplace=True)
    all_df.sort_values("time", inplace=True)
    if all_df.empty:
        logging.error(f"No data found in {file_path}; skipping.")
        return

    metrics_json={}
    for metric_id, g in all_df.groupby("metric"):
        g=g.sort_values("time")
        times=g["time"].dt.tz_convert(args.timezone).dt.strftime('%Y-%m-%d %H:%M:%S').tolist()
        metrics_json[metric_id]={
            "metric":metric_id,
            "unit":g["units"].iloc[0],
            "label":g["description"].iloc[0],
            "x":times,
            "y":g["value"].tolist()
        }

    stats_df=collect_stats(series)
    if not stats_df.empty:
        stats_df["min_ts"]=stats_df["min_ts"].apply(lambda x:_fmt_ts(x,args.timezone))
        stats_df["max_ts"]=stats_df["max_ts"].apply(lambda x:_fmt_ts(x,args.timezone))
        stats_html=stats_df.to_html(index=False, na_rep="",
                                    float_format=lambda v:f"{v:,.2f}",
                                    formatters={"min":_human_number,"max":_human_number,
                                                "mean":_human_number,"sum":_human_number,
                                                "num_samples":"{:,.0f}".format})
    else:
        stats_html="<table><tr><td>No summary statistics available.</td></tr></table>"

    start=all_df["time"].min().tz_convert(args.timezone).strftime('%Y-%m-%d %H:%M:%S')
    stop =all_df["time"].max().tz_convert(args.timezone).strftime('%Y-%m-%d %H:%M:%S')
    if len(all_df)>1:
        diffs=all_df["time"].diff().dropna()
        diffs=diffs[diffs.dt.total_seconds()>0]
        step=diffs.median().total_seconds() if not diffs.empty else "N/A"
    else:
        step="N/A"

    plotly_js = get_plotlyjs() if args.inline_js else None
    replacements={
        "title":args.title,
        "entity_uuid":entity_uuid,
        "metric_entity":metric_entity,
        "start":start,"stop":stop,
        "step": f"{step:.0f}" if isinstance(step,(float,int)) else step,
        "tz_label":args.timezone,
        "summary_table":stats_html,
        "metrics_json":json.dumps(metrics_json, indent=2),
        "plotly_js": f"<script>{plotly_js}</script>" if plotly_js else '<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>',
        "chart_height":args.chart_height
    }
    html=render_html(HTML_TEMPLATE, replacements)
    out=resolve_output_path(file_path, args.output)
    out.write_text(html, encoding="utf-8")
    logging.info(f"✔ wrote {out}")

def main():
    args=parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='[%(levelname)s] %(message)s')
    files=find_json_files(args.input)
    if not files:
        logging.error("No JSON files found."); sys.exit(1)
    logging.info(f"Found {len(files)} JSON file(s).")
    for p in files: process_file(p, args)

if __name__=="__main__":
    main()
