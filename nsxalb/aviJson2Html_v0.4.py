#!/usr/bin/env python3
# json2html.py — JSON → interactive HTML graphs (Plotly)
#
# Merge-by-UUID edition:
# - Reads multiple JSON files or dirs; ignores non-JSON.
# - Groups by (entity_uuid, metric_entity) → one HTML per group.
# - Merges per metric across files; de-dup by timestamp choosing the
#   value from the file with the NEWER file mtime (most recent file wins).
# - Recomputes Summary on merged data (can --no-summary to skip).
# - UI: chevron collapse, search/select, live plot/unplot, sync zoom,
#       global/per-chart legend, global/per-chart CSV (timestamp + metric columns),
#       jump top/bottom, light/dark theme (charts update).
# - ✅ FIX: Charts now resize on chevron collapse/expand and other layout changes.

import argparse, json, logging, sys
from collections import defaultdict
from pathlib import Path

import pandas as pd
from plotly.offline import get_plotlyjs

# ------------------------------ HTML TEMPLATE ------------------------------
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
${plotly_js}
<style>
  :root{
    --left-pane-width: 420px;
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
    /* optional smoothness:
    transition: grid-template-columns .18s ease;
    */
  }
  .main.collapsed{ --lp: 0px; grid-template-columns: minmax(0,1fr); }
  .main.collapsed #left-pane{ display:none; }

  .pane{background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow)}
  .left{min-height:60vh;max-height:calc(100vh - 170px);overflow:auto}
  .right{min-height:60vh;max-height:calc(100vh - 170px);overflow:auto}

  /* Ensure chart hosts fill their container width */
  .chart-host{width:100%}

  /* Chevron handle */
  .chevron{
    position:absolute; top:50%; transform:translateY(-50%);
    left: calc(var(--gap) + var(--lp) - 12px);
    width:42px;height:64px;border-radius:14px;border:1px solid var(--border);
    background:var(--card); color:var(--text); display:grid; place-items:center; cursor:pointer;
    box-shadow:var(--shadow); z-index:60; user-select:none;
    /* optional smoothness:
    transition: left .18s ease;
    */
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

    <!-- Chevron handle -->
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

let legendDefaultOn = true;
let currentCharts = []; // array of chart div ids

/* Utils */
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
    const el = document.getElementById(id);
    if(!el) return;
    Plotly.relayout(el, {
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

/* === Robust resizing === */
function fitChartsToHosts(){
  (currentCharts || []).forEach(id => {
    const el = document.getElementById(id);
    if(!el) return;
    const host = el.parentElement; // .chart-host
    if(!host) return;
    const w = Math.floor(host.getBoundingClientRect().width);
    if(w > 0){
      Plotly.relayout(el, {autosize: true, width: w}).then(() => {
        Plotly.Plots.resize(el);
      }).catch(() => {
        try { Plotly.Plots.resize(el); } catch(e){}
      });
    }
  });
}
function resizeCharts(){
  cancelAnimationFrame(resizeCharts._raf || 0);
  resizeCharts._raf = requestAnimationFrame(fitChartsToHosts);
}

/* THEME */
function setTheme(t){ document.body.setAttribute('data-theme',t); localStorage.setItem(THEME_KEY,t); }
(function(){
  setTheme(localStorage.getItem(THEME_KEY) || 'light');
  document.getElementById('theme-toggle').onclick = () => {
    const next = document.body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    setTheme(next);
    applyThemeToCharts();
    resizeCharts();
  };
})();

/* TABS */
document.getElementById('tab-interactive').onclick = ()=> { setActiveTab(true); resizeCharts(); };
document.getElementById('tab-summary').onclick     = ()=> { setActiveTab(false); };
function setActiveTab(toInteractive){
  const a = document.getElementById('tab-interactive');
  const b = document.getElementById('tab-summary');
  a.classList.toggle('is-active', toInteractive);
  b.classList.toggle('is-active', !toInteractive);
  document.getElementById('interactive-main').style.display = toInteractive ? '' : 'none';
  document.getElementById('summary-main').style.display     = toInteractive ? 'none' : '';
}

/* CHEVRON collapse */
(function(){
  const main = document.getElementById('interactive-main');
  const chev = document.getElementById('chevron');
  function setArrow(){ chev.querySelector('span').textContent = main.classList.contains('collapsed') ? '❯' : '❮'; }
  chev.onclick = ()=>{
    main.classList.toggle('collapsed');
    setArrow();
    // Resize after grid reflows
    requestAnimationFrame(resizeCharts);
    setTimeout(resizeCharts, 150);
  };
  setArrow();
})();

/* Observe layout changes to trigger resizes */
(function(){
  const rp = document.getElementById('right-pane');
  if ('ResizeObserver' in window && rp){
    let t=null;
    const ro = new ResizeObserver(() => { clearTimeout(t); t=setTimeout(resizeCharts, 60); });
    ro.observe(rp);
  }
  const grid = document.getElementById('interactive-main');
  if (grid && 'MutationObserver' in window){
    const mo = new MutationObserver(() => resizeCharts());
    mo.observe(grid, {attributes:true, attributeFilter:['class']});
  }
  window.addEventListener('resize', resizeCharts);
})();

/* Jump controls */
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
  return { init, getSelected };
})();
MS.init();

/* Plotly layout helpers */
function baseLayout(xTitle, showLegend, legendRows){
  const t = themeColors();
  const b = showLegend ? (legendRows>1?120:80) : 60;
  return {
    autosize:true,  // important for responsive width
    paper_bgcolor:t.panel, plot_bgcolor:t.panel, font:{color:t.text},
    margin:{t:24,r:18,b:b,l:54},
    xaxis:{title:xTitle, gridcolor:t.grid, automargin:true, titlefont:{color:t.text}, tickfont:{color:t.text}},
    yaxis:{title:'', gridcolor:t.grid, automargin:true, titlefont:{color:t.text}, tickfont:{color:t.text}},
    showlegend:showLegend,
    legend:{orientation:'h', x:0, xanchor:'left', y:-0.25, yanchor:'top', font:{size:11, color:t.text}}
  };
}

/* Sync X-range across charts */
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
      const el = document.getElementById(id);
      if(!el) continue;
      if(auto) Plotly.relayout(el, {'xaxis.autorange':true});
      else if(r0!=null && r1!=null) Plotly.relayout(el, {'xaxis.range':[r0,r1],'xaxis.autorange':false});
    }
    setTimeout(()=>{suppress=false;},0);
  }

  for(const id of ids){
    const el=document.getElementById(id);
    el.on('plotly_relayout', ev => { if(suppress) return; const {r0,r1,auto,changed}=parse(ev); if(!changed) return; apply(id,r0,r1,auto); });
    el.on('plotly_doubleclick', () => { if(suppress) return; apply(id,null,null,true); });
  }
}

/* Render */
function renderInteractive(){
  const names = MS.getSelected();
  const wrap = document.getElementById('interactive-panels');
  wrap.innerHTML=''; currentCharts=[];

  if(!names.length){ resizeCharts(); return; }

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
        if(currentCharts.length === names.length) { setupRangeSync(currentCharts); applyThemeToCharts(); resizeCharts(); }
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
      setupRangeSync(currentCharts); applyThemeToCharts(); resizeCharts();
    });
  }

  // per-chart CSV & legend mini buttons
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
document.getElementById('btn-plot').onclick  = ()=> { renderInteractive(); resizeCharts(); };
document.getElementById('btn-clear').onclick = ()=>{ document.getElementById('interactive-panels').innerHTML=''; currentCharts=[]; resizeCharts(); };
document.getElementById('btn-reset').onclick = ()=>{ currentCharts.forEach(id => { const el=document.getElementById(id); if(el){ Plotly.relayout(el, {'xaxis.autorange':true, 'yaxis.autorange':true}); }}); };
document.getElementById('btn-individual').onclick = (e)=>{ e.currentTarget.classList.toggle('is-active'); renderInteractive(); };

/* Global legend baseline (mini toggles remain independent after) */
document.getElementById('btn-legend').onclick = (e)=>{
  legendDefaultOn = !legendDefaultOn;
  e.currentTarget.classList.toggle('is-active', legendDefaultOn);
  currentCharts.forEach(id => { const el=document.getElementById(id); if(el){ Plotly.relayout(el, {'showlegend': legendDefaultOn}); }});
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

# ------------------------------ Python helpers ------------------------------
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

# ------------------------------ CLI ------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Merge JSON metrics by entity_uuid → interactive HTML",
        formatter_class=argparse.RawTextHelpFormatter, add_help=True,
    )
    p.add_argument("-i","--input", nargs="+", help="Input .json files or directories.")
    p.add_argument("-o","--output", help="Output HTML path (used only if exactly one group).")
    p.add_argument("--title", help='Page title (default: "Metrics Report").')
    p.add_argument("--inline-js", action="store_true", help="Embed Plotly JS for offline HTML.")
    p.add_argument("--ist", action="store_true", help="Use Asia/Kolkata timezone.")
    p.add_argument("--no-summary", action="store_true", help="Skip summary table generation.")
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

# ------------------------------ IO ------------------------------
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

def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read/parse {path}: {e}")
        return None

# ------------------------------ Merge logic ------------------------------
def group_files_by_uuid(files):
    """
    Returns dict keyed by (entity_uuid, metric_entity) -> list[Path]
    Files with missing entity fields are grouped under ('N/A','N/A').
    """
    groups = defaultdict(list)
    for p in files:
        data = load_json(p)
        if not data:
            continue
        entity_uuid = data.get("entity_uuid", "N/A")
        metric_entity = data.get("metric_entity", "N/A")
        groups[(entity_uuid, metric_entity)].append(p)
    return groups

def build_merged_metrics(paths, tz_name):
    """
    Read all JSONs in paths and merge per metric name.
    Most-recent duplicate policy: if two points share the same timestamp,
    prefer the one from the file with the NEWER file modification time.
    Returns:
      metrics_map: { metric_name: { 'unit','label','x','y' } } (times in tz_name)
      all_df: concatenated dataframe of all metrics (tz-aware)
    """
    per_metric = {}
    frames = []

    for p in paths:
        data = load_json(p)
        if not data:
            continue
        series = data.get("series", [])
        if not isinstance(series, list):
            logging.warning(f"{p}: 'series' is not a list, skipping.")
            continue

        file_mtime = p.stat().st_mtime  # <-- used for recency in tie-breaks

        for s in series:
            h = s.get("header", {}) or {}
            name = h.get("name", "unknown")
            unit = h.get("units", "UNKNOWN")
            label = h.get("metric_description", "") or name
            rows = s.get("data", []) or []

            df = pd.DataFrame(rows)
            if df.empty or "timestamp" not in df or "value" not in df:
                continue
            df["time"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
            df["value"] = pd.to_numeric(df["value"], errors="coerce")
            df = df.drop(columns=["timestamp"], errors="ignore")
            df = df.dropna(subset=["time","value"]).sort_values("time")

            df["src_mtime"] = file_mtime   # <-- stamp every row with file mtime

            slot = per_metric.setdefault(name, {"unit": unit, "label": label, "chunks": []})
            if slot["unit"] != unit:
                logging.warning(f"Unit mismatch for metric '{name}': '{slot['unit']}' vs '{unit}'. Keeping first.")
            if slot["label"] != label and label:
                logging.warning(f"Label differs for metric '{name}'. Keeping earliest '{slot['label']}'.")
            slot["chunks"].append(df)

    # Consolidate per metric (concat, sort by time then mtime, dedup keep newest, sort by time)
    metrics_map = {}
    for name, meta in per_metric.items():
        if not meta["chunks"]:
            continue
        g = pd.concat(meta["chunks"], ignore_index=True)
        g = g.dropna(subset=["time","value"])
        g = g.sort_values(["time", "src_mtime"])  # time asc, older files first
        g = g.drop_duplicates(subset=["time"], keep="last").reset_index(drop=True)  # keep newest mtime per timestamp
        g = g.sort_values("time")
        frames.append(g.assign(metric=name, units=meta["unit"], description=meta["label"]))

        # Convert times to selected tz for HTML payload
        times = g["time"].dt.tz_convert(tz_name).dt.strftime('%Y-%m-%d %H:%M:%S').tolist()
        metrics_map[name] = {
            "metric": name,
            "unit": meta["unit"],
            "label": meta["label"],
            "x": times,
            "y": g["value"].tolist()
        }

    all_df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=["time","value","metric","units","description"])
    return metrics_map, all_df

def compute_summary_from_all_df(all_df, tz_name):
    """
    Build summary dataframe per metric from the merged all_df.
    """
    if all_df.empty:
        return pd.DataFrame()

    rows=[]
    for metric, g in all_df.groupby("metric"):
        g = g.dropna(subset=["value", "time"]).sort_values("time")
        if g.empty:
            continue
        # min/max with timestamps
        idx_min = g["value"].idxmin()
        idx_max = g["value"].idxmax()
        min_val = g.loc[idx_min, "value"]
        max_val = g.loc[idx_max, "value"]
        min_ts  = g.loc[idx_min, "time"].tz_convert(tz_name).strftime('%Y-%m-%d %H:%M:%S')
        max_ts  = g.loc[idx_max, "time"].tz_convert(tz_name).strftime('%Y-%m-%d %H:%M:%S')

        rows.append({
            "metric": metric,
            "units": g["units"].iloc[0],
            "description": g["description"].iloc[0],
            "mean": g["value"].mean(),
            "min":  min_val, "min_ts": min_ts,
            "max":  max_val, "max_ts": max_ts,
            "sum":  g["value"].sum(),
            "num_samples": int(g.shape[0]),
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["units","metric"], kind="stable")
    return df

# ------------------------------ Emit one HTML for group ------------------------------
def emit_group_html(entity_uuid, metric_entity, files, args):
    logging.info(f"Merging {len(files)} file(s) for entity_uuid={entity_uuid}")

    metrics_map, all_df = build_merged_metrics(files, args.timezone)

    if all_df.empty or not metrics_map:
        logging.error("No data after merge; skipping.")
        return None

    # Build summary
    if not args.no_summary:
        stats_df = compute_summary_from_all_df(all_df, args.timezone)
        if not stats_df.empty:
            stats_html = stats_df.to_html(
                index=False, na_rep="",
                float_format=lambda v: f"{v:,.2f}",
                formatters={
                    "min": lambda v: f"{v:,.6f}".rstrip("0").rstrip("."),
                    "max": lambda v: f"{v:,.6f}".rstrip("0").rstrip("."),
                    "mean": lambda v: f"{v:,.6f}".rstrip("0").rstrip("."),
                    "sum": lambda v: f"{v:,.6f}".rstrip("0").rstrip("."),
                    "num_samples": "{:,.0f}".format
                }
            )
        else:
            stats_html = "<table><tr><td>No summary statistics available.</td></tr></table>"
    else:
        stats_html = "<table><tr><td>Summary disabled.</td></tr></table>"

    # Time window and step
    start = all_df["time"].min().tz_convert(args.timezone).strftime('%Y-%m-%d %H:%M:%S')
    stop  = all_df["time"].max().tz_convert(args.timezone).strftime('%Y-%m-%d %H:%M:%S')
    if len(all_df)>1:
        diffs = all_df["time"].diff().dropna()
        diffs = diffs[diffs.dt.total_seconds()>0]
        step  = diffs.median().total_seconds() if not diffs.empty else "N/A"
    else:
        step = "N/A"

    plotly_js = get_plotlyjs() if args.inline_js else None
    replacements = {
        "title": args.title,
        "entity_uuid": entity_uuid,
        "metric_entity": metric_entity,
        "start": start, "stop": stop,
        "step": f"{step:.0f}" if isinstance(step,(float,int)) else step,
        "tz_label": args.timezone,
        "summary_table": stats_html,
        "metrics_json": json.dumps(metrics_map, indent=2),
        "plotly_js": f"<script>{plotly_js}</script>" if plotly_js else '<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>',
        "chart_height": args.chart_height
    }

    html = render_html(HTML_TEMPLATE, replacements)
    return html

# ------------------------------ Main ------------------------------
def main():
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='[%(levelname)s] %(message)s')

    files = find_json_files(args.input)
    if not files:
        logging.error("No JSON files found.")
        sys.exit(1)

    logging.info(f"Found {len(files)} JSON file(s). Grouping by entity_uuid ...")

    groups = group_files_by_uuid(files)
    logging.info(f"Formed {len(groups)} group(s).")

    # Emit one HTML per group
    outputs = []
    for (entity_uuid, metric_entity), paths in groups.items():
        html = emit_group_html(entity_uuid, metric_entity, paths, args)
        if html is None:
            continue

        # Decide output path
        if len(groups) == 1 and args.output:
            out_path = Path(args.output).expanduser()
            if out_path.suffix.lower() not in (".html",".htm"):
                out_path = out_path.with_suffix(".html")
        else:
            safe_uuid = (entity_uuid or "NA").replace("/", "_").replace("\\","_").replace(":", "_")
            out_path = Path.cwd() / f"{safe_uuid}.html"

        out_path.write_text(html, encoding="utf-8")
        logging.info(f"✔ wrote {out_path}")
        outputs.append(out_path)

    if not outputs:
        logging.error("No reports were generated.")
        sys.exit(2)

if __name__ == "__main__":
    main()
