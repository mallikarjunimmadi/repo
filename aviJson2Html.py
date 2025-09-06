#!/usr/bin/env python3
# json2html.py — JSON → interactive HTML graphs (Plotly)
#
# This drop-in version:
# - Uniform design for Plot / Clear Charts / Reset Zoom / Individual graphs.
# - Individual graphs is a toggle (same look, colored when active).
# - Auto-plots / removes charts on metric check/uncheck.
# - Left + right panes handle their own scrolling; page scrollbar avoided.
# - Accepts multiple JSON files or directories; validates JSON; extended logging.

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, List

import pandas as pd
import plotly.graph_objects as go  # noqa: F401

try:
    from plotly.offline.offline import get_plotlyjs as _get_plotlyjs
except Exception:
    try:
        from plotly.offline import get_plotlyjs as _get_plotlyjs
    except Exception:
        _get_plotlyjs = None


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
${plotly_js}
<style>
  :root {
    --bg:#f9fafb; --fg:#1f2937; --fg-muted:#6b7280; --border:#e5e7eb;
    --pill:#e5e7eb; --card-bg:#ffffff; --shadow:0 4px 6px -1px rgba(0,0,0,.08),0 2px 4px -2px rgba(0,0,0,.04);
    --primary:#2563eb; --primary-hover:#1d4ed8;
    /* Space for header/meta/controls; tweak to avoid page scrollbar */
    --chrome-height: 190px;
  }
  [data-theme="dark"] {
    --bg:#111827; --fg:#f3f4f6; --fg-muted:#9ca3af; --border:#374151;
    --pill:#374151; --card-bg:#1f2937; --shadow:0 4px 6px -1px rgba(0,0,0,.10),0 2px 4px -2px rgba(0,0,0,.08);
    --primary:#60a5fa; --primary-hover:#3b82f6;
  }
  html,body{width:100%;height:100%;margin:0;padding:0}
  body{
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    color:var(--fg); background:var(--bg); transition:background .3s,color .3s; font-size:14px;
    overflow:hidden; /* panes will scroll */
  }
  h1{font-size:20px;margin:0;font-weight:600} h2{font-size:16px;margin:0 0 10px;font-weight:600}
  .header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border)}
  .theme-toggle{background:transparent;border:1px solid var(--border);border-radius:10px;padding:6px;cursor:pointer;color:var(--fg)}
  .theme-toggle:hover{background:var(--card-bg)}
  .meta{color:var(--fg-muted);font-size:12px;margin:10px 16px}

  .top-controls-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--border)}
  .tabs{display:flex;gap:8px}
  .tab-btn{padding:8px 12px;border:1px solid var(--border);border-radius:999px;cursor:pointer;background:#f8fafc;font-weight:600;font-size:13px}
  .tab-btn:hover{background:#eef2ff} .tab-btn.active{background:#e9f3ff;border-color:#bcd6ff}
  [data-theme="dark"] .tab-btn{background:#1f2937;border-color:#374151;color:#d1d5db}
  [data-theme="dark"] .tab-btn.active{background:#163e71;border-color:#3b82f6;color:#fff}

  /* --- Unified command buttons (Plot/Clear/Reset/Individual) --- */
  .cmd-btn{
    display:inline-flex; align-items:center; justify-content:center;
    gap:8px; padding:8px 14px;
    border:1px solid var(--border); border-radius:10px;
    background:var(--card-bg); color:var(--fg);
    min-height:36px; font-weight:600; font-size:13px;
    cursor:pointer; transition:background .15s, border-color .15s, color .15s, box-shadow .15s;
    box-shadow:none; min-width:130px;
  }
  .cmd-btn:hover{ background:var(--bg); }
  .cmd-btn.is-toggle[aria-pressed="true"]{
    background:var(--primary); border-color:var(--primary); color:#fff;
  }
  .cmd-btn:active{ transform: translateY(0.5px); }

  /* Working area */
  .main-container{
    display:flex; gap:16px; padding:16px;
    height: calc(100dvh - var(--chrome-height));
    box-sizing:border-box;
  }
  .left-pane{flex:0 0 360px;border-radius:12px;padding:16px;background:var(--card-bg);box-shadow:var(--shadow);overflow:hidden}
  .right-pane{flex:1 1 auto;border-radius:12px;padding:16px;background:var(--card-bg);box-shadow:var(--shadow);overflow:auto}

  .btn{appearance:none;border:1px solid var(--border);background:var(--card-bg);color:var(--fg);padding:6px 10px;border-radius:8px;cursor:pointer;transition:all .15s ease;font-size:12px}
  .btn:hover{background:var(--bg)}
  .btn-filter.active{background:var(--primary);border-color:var(--primary);color:#fff}

  .ms-list-container{height:100%;display:flex;flex-direction:column}
  .ms-search-header{display:flex;flex-direction:column;gap:10px;margin-bottom:12px}
  .ms-search{width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--fg)}
  .ms-list-body{flex:1;overflow-y:auto;border:0;border-radius:0}
  .ms-item{display:flex;gap:10px;padding:8px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;align-items:flex-start}
  .ms-item:last-of-type{border-bottom:none}
  .ms-item input{margin-top:3px}
  .ms-item-text{line-height:1.35}.ms-item-text .main-text{font-weight:600}.ms-item-text .sub-text{font-size:12px;color:var(--fg-muted)}
  .badge{margin-left:auto;font-size:11px;padding:1px 6px;border-radius:999px;background:rgba(127,127,127,.12);color:var(--fg-muted)}

  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{border:1px solid var(--border);padding:6px 8px;text-align:left}
  [data-theme="dark"] th{background:#1f2937}

  .charts-wrap{display:grid;grid-template-columns:1fr;gap:16px}
  .chart-card{padding:12px;border:1px solid var(--border);border-radius:12px;background:var(--card-bg);box-shadow:var(--shadow)}
  .chart-title{font-weight:600;margin-bottom:6px;font-size:14px;display:flex;gap:8px;align-items:center}
  .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--border);font-size:12px;background:var(--pill)}

  .fab{position:fixed;right:16px;bottom:16px;display:none;flex-direction:column;gap:8px;z-index:2000}
  .fab-btn{width:44px;height:44px;border-radius:999px;border:1px solid var(--border);background:var(--primary);color:#fff;box-shadow:var(--shadow);cursor:pointer;font-size:18px;line-height:44px;text-align:center}
  .fab-btn:hover{background:var(--primary-hover)}
</style>
</head>
<body data-theme="light">
  <div class="header">
    <h1>${title}</h1>
    <button id="theme-toggle" class="theme-toggle" title="Toggle theme">🌞/🌙</button>
  </div>

  <div class="meta">
    <div><b>Entity:</b> ${entity_display}</div>
    <div><b>Window:</b> ${start} → ${stop} | <b>Step:</b> ${step}s | <b>Time Zone:</b> ${tz_label}</div>
  </div>

  <div class="top-controls-bar">
    <div class="tabs" id="tabs">
      <div class="tab-btn active" data-target="panel-interactive">Interactive Select</div>
      <div class="tab-btn" data-target="panel-summary">Summary</div>
    </div>

    <div class="chip-bar">
      <button id="btn-plot" class="cmd-btn" type="button">Plot</button>
      <button id="btn-clear" class="cmd-btn" type="button">Clear Charts</button>
      <button id="btn-reset-range" class="cmd-btn" type="button">Reset Zoom</button>

      <!-- Toggle -->
      <button id="chip-individual" class="cmd-btn is-toggle" type="button"
              aria-pressed="false" title="Toggle: Individual graphs">
        Individual graphs
      </button>
    </div>
  </div>

  <div class="main-container">
    <div class="left-pane content-panel" id="panel-interactive" style="display:block">
      <h2>Select Metrics</h2>
      <div class="ms-list-container">
        <div class="ms-search-header">
          <input type="text" id="ms-search" class="ms-search" placeholder="Search metrics or units..."/>
          <div class="ms-actions" style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn" id="ms-select-all" type="button">Select All</button>
            <button class="btn" id="ms-clear" type="button">Clear</button>
            <button class="btn btn-filter active" id="btn-show-all" data-filter="all" type="button">Show All</button>
            <button class="btn btn-filter" id="btn-show-selected" data-filter="selected" type="button">Show Selected (<span id="ms-count">0</span>)</button>
          </div>
        </div>
        <div class="ms-list-body" id="ms-body"></div>
      </div>
    </div>

    <div class="right-pane content-panel" id="right-pane-interactive" style="display:block">
      <div class="charts-wrap" id="interactive-panels"></div>
    </div>

    <div class="right-pane content-panel" id="panel-summary" style="display:none">
      <h2>Summary Statistics</h2>
      ${summary_table}
    </div>
  </div>

  <div id="fab-nav" class="fab">
    <button id="btn-scroll-top" class="fab-btn" title="Jump to top">↑</button>
    <button id="btn-scroll-bottom" class="fab-btn" title="Jump to bottom">↓</button>
  </div>

<script>
if (!Element.prototype.matches) {
  Element.prototype.matches = Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector;
}
if (!Element.prototype.closest) {
  Element.prototype.closest = function (s) { var el=this; if(!document.documentElement.contains(el)) return null; do{ if(el.matches(s)) return el; el=el.parentElement||el.parentNode; }while(el&&el.nodeType===1); return null; };
}

var METRICS_DATA = ${metrics_json};
var METRIC_NAMES = Object.keys(METRICS_DATA).sort(function(a,b){ return a.localeCompare(b); });
var THEME_KEY='plot_theme', DEFAULT_THEME='light';
var FONT_FAMILY='-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
var showSelectedMode=false;
var SHOW_UNIT_HEADERS=false;

function debounce(fn,ms){var t;return function(){var args=arguments,ctx=this;clearTimeout(t);t=setTimeout(function(){fn.apply(ctx,args);},ms||120);};}

function updatePlotlyTheme(theme){
  var isDark = theme==='dark';
  var fontColor = isDark?'#f3f4f6':'#1f2937';
  var gridColor = isDark?'#374151':'#e5e7eb';
  var paperBg  = isDark?'#1f2937':'#ffffff';
  var plotBg   = isDark?'#111827':'#f9fafb';
  var divs = document.querySelectorAll('#interactive-panels .chart-card > div[id^="chart"]');
  for (var i=0;i<divs.length;i++){
    var id=divs[i].id;
    if (window.Plotly && id) {
      window.Plotly.relayout(id,{
        paper_bgcolor:paperBg, plot_bgcolor:plotBg,
        font:{color:fontColor,family:FONT_FAMILY},
        'xaxis.gridcolor':gridColor,'yaxis.gridcolor':gridColor
      });
    }
  }
}
function setTheme(t){ document.body.setAttribute('data-theme',t); try{localStorage.setItem(THEME_KEY,t);}catch(e){} updatePlotlyTheme(t); }
function toggleTheme(){ setTheme(document.body.getAttribute('data-theme')==='light'?'dark':'light'); }

function setupTabs(){
  var tabs=document.querySelectorAll('.tab-btn');
  var left=document.getElementById('panel-interactive');
  var rightInt=document.getElementById('right-pane-interactive');
  var rightSum=document.getElementById('panel-summary');
  function activate(id){
    for (var i=0;i<tabs.length;i++){ var t=tabs[i]; t.classList.toggle('active', t.getAttribute('data-target')===id); }
    left.style.display='block';
    if(id==='panel-interactive'){ rightInt.style.display='block'; rightSum.style.display='none'; }
    else { rightInt.style.display='none'; rightSum.style.display='block'; }
    setTimeout(function(){
      var divs=document.querySelectorAll('#interactive-panels .chart-card > div[id^="chart"]');
      for (var j=0;j<divs.length;j++){ if (window.Plotly) window.Plotly.relayout(divs[j].id,{autosize:true}); }
    },80);
  }
  for (var i=0;i<tabs.length;i++){ tabs[i].addEventListener('click', function(){ activate(this.getAttribute('data-target')); }); }
  if (tabs.length) activate(tabs[0].getAttribute('data-target'));
}

var msBody, msSearch, btnAll, btnSel, btnSelectAll, btnClear, countSpan;

function escapeHTML(s){ return (s||"").replace(/[&<>'"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c];}); }

function buildMetricList(){
  msBody.innerHTML="";
  var currentUnit=null;

  for (var i=0;i<METRIC_NAMES.length;i++){
    var name=METRIC_NAMES[i];
    var m=METRICS_DATA[name]||{};
    var unit=m.unit||'UNKNOWN';

    if (unit!==currentUnit){
      currentUnit=unit;
      if (SHOW_UNIT_HEADERS) {
        var gt=document.createElement('div'); gt.className='ms-group-title'; gt.textContent=unit; msBody.appendChild(gt);
      }
    }

    // Use native label-toggle behavior (no extra click handler)
    var lab=document.createElement('label'); lab.className='ms-item'; lab.setAttribute('data-metric', name);
    var cb=document.createElement('input'); cb.type='checkbox'; cb.setAttribute('data-name', name);
    var txt=document.createElement('div'); txt.className='ms-item-text';
    txt.innerHTML="<div class='main-text'>"+escapeHTML(name)+"</div><div class='sub-text'>"+escapeHTML(m.label||m.metric||'')+"</div>";
    var badge=document.createElement('span'); badge.className='badge'; badge.textContent=unit;

    lab.appendChild(cb); lab.appendChild(txt); lab.appendChild(badge);
    msBody.appendChild(lab);
  }

  var onChange = debounce(function(){
    updateSelectedCount();
    if (showSelectedMode) applyFilter();
    renderInteractive();  // Auto plot/remove
  }, 120);

  // Only listen to checkbox changes; label click toggles natively
  msBody.addEventListener('change', function(e){
    if (e.target && e.target.matches('input[type="checkbox"][data-name]')) onChange();
  });
}

function getCheckedMetricNames(){
  var out=[], boxes=msBody.querySelectorAll('input[type="checkbox"][data-name]:checked');
  for (var i=0;i<boxes.length;i++){ out.push(boxes[i].getAttribute('data-name')); }
  return out;
}
function updateSelectedCount(){
  var n = msBody.querySelectorAll('input[type="checkbox"][data-name]:checked').length;
  countSpan.textContent = String(n);
}
function applyFilter(){
  var q=(msSearch.value||"").trim().toLowerCase();
  var rows=msBody.querySelectorAll('.ms-item');
  for (var i=0;i<rows.length;i++){
    var row=rows[i];
    var name=row.getAttribute('data-metric')||"";
    var checked=row.querySelector('input[type="checkbox"]').checked;
    var matchesSearch = !q || name.toLowerCase().indexOf(q)!==-1;
    var passes = matchesSearch && (showSelectedMode ? checked : true);
    row.style.display = passes ? 'flex' : 'none';
  }
  if (SHOW_UNIT_HEADERS) {
    var headers=msBody.querySelectorAll('.ms-group-title');
    for (var h=0; h<headers.length; h++){
      var header=headers[h], next=header.nextElementSibling, anyVisible=false;
      while(next && !next.classList.contains('ms-group-title')){
        if (next.style.display !== 'none'){ anyVisible=true; break; }
        next=next.nextElementSibling;
      }
      header.style.display = anyVisible ? 'block' : 'none';
    }
  }
}
function selectAllVisible(){
  var rows=msBody.querySelectorAll('.ms-item');
  for (var i=0;i<rows.length;i++){
    var r=rows[i]; if (r.style.display==='none') continue;
    var cb=r.querySelector('input[type="checkbox"]'); if (cb) cb.checked=true;
  }
  updateSelectedCount(); renderInteractive();
}
function clearAll(){
  var boxes=msBody.querySelectorAll('input[type="checkbox"]');
  for (var i=0;i<boxes.length;i++){ boxes[i].checked=false; }
  updateSelectedCount(); if (showSelectedMode) applyFilter(); renderInteractive();
}
function wireMetricUI(){
  msBody = document.getElementById('ms-body');
  msSearch = document.getElementById('ms-search');
  btnAll = document.getElementById('btn-show-all');
  btnSel = document.getElementById('btn-show-selected');
  btnSelectAll = document.getElementById('ms-select-all');
  btnClear = document.getElementById('ms-clear');
  countSpan = document.getElementById('ms-count');

  buildMetricList(); updateSelectedCount(); applyFilter();
  msSearch.addEventListener('input', applyFilter);
  btnAll.addEventListener('click', function(){ showSelectedMode=false; btnAll.classList.add('active'); btnSel.classList.remove('active'); applyFilter(); });
  btnSel.addEventListener('click', function(){ showSelectedMode=true;  btnSel.classList.add('active'); btnAll.classList.remove('active'); applyFilter(); });
  btnSelectAll.addEventListener('click', selectAllVisible);
  btnClear.addEventListener('click', clearAll);
}

function truncateLabel(s,n){ if(!s) return ''; return s.length>n? s.slice(0,n-1)+'…' : s; }
function groupByUnit(names){ var out={}; for(var i=0;i<names.length;i++){ var name=names[i]; var m=METRICS_DATA[name]; if(!m) continue; var u=m.unit||'UNKNOWN'; if(!out[u]) out[u]=[]; out[u].push(m); } return out; }
function getLayout(xTitle,showLegend){
  var isDark = document.body.getAttribute('data-theme')==='dark';
  var fontColor=isDark?'#f3f4f6':'#1f2937', gridColor=isDark?'#374151':'#e5e7eb';
  var paperBg=isDark?'#1f2937':'#ffffff', plotBg=isDark?'#111827':'#f9fafb';
  return {paper_bgcolor:paperBg,plot_bgcolor:plotBg,title:'',
    xaxis:{title:xTitle,gridcolor:gridColor,automargin:true}, yaxis:{title:'',gridcolor:gridColor,automargin:true},
    font:{family:FONT_FAMILY,color:fontColor,size:12}, hovermode:'x unified', showlegend:showLegend,
    legend:{orientation:'h',x:0,xanchor:'left',y:-0.25,yanchor:'top',font:{size:11}},
    margin:{t:40,r:30,b:showLegend?150:60,l:60}, height:${chart_height}, autosize:true};
}
function setupRangeSync(ids){
  var suppress=false;
  function apply(src,r0,r1,auto){
    suppress=true;
    for (var i=0;i<ids.length;i++){ var id=ids[i]; if(id===src) continue;
      if(auto) window.Plotly.relayout(id,{'xaxis.autorange':true});
      else window.Plotly.relayout(id,{'xaxis.range':[r0,r1],'xaxis.autorange':false});
    }
    setTimeout(function(){suppress=false;},0);
  }
  for (var j=0;j<ids.length;j++){
    var id=ids[j]; var div=document.getElementById(id); if(!div || !div.on) continue;
    div.on('plotly_relayout',function(ev){
      if(suppress) return;
      var auto = Object.prototype.hasOwnProperty.call(ev,'xaxis.autorange') ? !!ev['xaxis.autorange'] : false;
      var r0=null,r1=null;
      if(Array.isArray(ev['xaxis.range'])){ r0=ev['xaxis.range'][0]; r1=ev['xaxis.range'][1]; }
      else if(Object.prototype.hasOwnProperty.call(ev,'xaxis.range[0]')){ r0=ev['xaxis.range[0]']; r1=ev['xaxis.range[1]']; }
      if(auto || (r0!=null && r1!=null)) apply(this.id,r0,r1,auto);
    });
  }
}
function updateFabVisibility(){
  var wrap=document.getElementById('interactive-panels');
  var many = wrap.querySelectorAll('.chart-card').length > 1;
  var fab=document.getElementById('fab-nav');
  fab.style.display = many ? 'flex' : 'none';
}
function renderPerMetric(names,wrap){
  var ids=[];
  for (var i=0;i<names.length;i++){
    var metricName=names[i]; var m=METRICS_DATA[metricName]; if(!m) continue;
    var unit=m.unit||'UNKNOWN', xTitle=truncateLabel(m.label||m.metric||metricName,140);
    var card=document.createElement('div'); card.className='chart-card';
    var title=document.createElement('div'); title.className='chart-title'; title.innerHTML=metricName+' <span class="pill">'+unit+'</span>';
    var div=document.createElement('div'); var cid='chart-'+metricName.replace(/[^a-zA-Z0-9_-]/g,'_')+'-'+Math.random().toString(36).slice(2,7);
    div.id=cid; card.appendChild(title); card.appendChild(div); wrap.appendChild(card);
    var traces=[{type:'scatter',mode:'lines+markers',x:m.x,y:m.y,name:metricName,hovertemplate:'Metric: '+(m.label||m.metric||metricName)+'<br>Time: %{x}<br>Value: %{y}<extra></extra>'}];
    window.Plotly.newPlot(cid,traces,getLayout(xTitle,false),{responsive:true}); ids.push(cid);
  }
  if(ids.length>1) setupRangeSync(ids);
}
function renderGroupedByUnit(names,wrap){
  var byU=groupByUnit(names), ids=[], units=Object.keys(byU);
  for (var ui=0; ui<units.length; ui++){
    var unit=units[ui]; var metrics=byU[unit]; if(!metrics || !metrics.length) continue;
    var card=document.createElement('div'); card.className='chart-card';
    var title=document.createElement('div'); title.className='chart-title'; title.innerHTML='Selected Metrics <span class="pill">'+unit+'</span>';
    var div=document.createElement('div'); var cid='chart-unit-'+unit.replace(/[^a-zA-Z0-9_-]/g,'_')+'-'+Math.random().toString(36).slice(2,7);
    div.id=cid; card.appendChild(title); card.appendChild(div); wrap.appendChild(card);
    var traces=[]; for (var mi=0; mi<metrics.length; mi++){ var m=metrics[mi];
      traces.push({type:'scatter',mode:'lines+markers',x:m.x,y:m.y,name:m.metric,
        hovertemplate:'Metric: '+(m.label||m.metric)+'<br>Time: %{x}<br>Value: %{y}<extra></extra>'});
    }
    window.Plotly.newPlot(cid,traces,getLayout('',true),{responsive:true}); ids.push(cid);
  }
  if(ids.length>1) setupRangeSync(ids);
}
function renderInteractive(){
  var names=getCheckedMetricNames();
  var wrap=document.getElementById('interactive-panels'); if(!wrap) return;
  wrap.innerHTML='';
  if(!names.length){ updateFabVisibility(); return; }
  if(window.__individualMode__) renderPerMetric(names,wrap); else renderGroupedByUnit(names,wrap);
  updatePlotlyTheme(document.body.getAttribute('data-theme'));
  updateFabVisibility();
}
function resetZoomAll(){
  var divs=document.querySelectorAll('#interactive-panels .chart-card > div[id^="chart"]');
  for (var i=0;i<divs.length;i++){ if (window.Plotly) window.Plotly.relayout(divs[i].id,{'xaxis.autorange':true,'yaxis.autorange':true}); }
}

(function init(){
  var saved=DEFAULT_THEME; try{ saved=localStorage.getItem(THEME_KEY)||DEFAULT_THEME; }catch(e){}
  setTheme(saved);
  var el=document.getElementById('theme-toggle'); if(el) el.addEventListener('click', toggleTheme);

  setupTabs();
  wireMetricUI();

  // Unified toggle button wiring for "Individual graphs"
  window.__individualMode__ = window.__individualMode__ || false;
  const indBtn = document.getElementById('chip-individual');
  function syncIndBtn(){ indBtn.setAttribute('aria-pressed', window.__individualMode__ ? 'true' : 'false'); }
  if (indBtn){
    indBtn.addEventListener('click', () => { window.__individualMode__ = !window.__individualMode__; syncIndBtn(); renderInteractive(); });
    syncIndBtn();
  }

  // Action buttons
  el=document.getElementById('btn-plot'); if(el) el.addEventListener('click', renderInteractive);
  el=document.getElementById('btn-clear'); if(el) el.addEventListener('click', function(){ document.getElementById('interactive-panels').innerHTML=''; updateFabVisibility(); });
  el=document.getElementById('btn-reset-range'); if(el) el.addEventListener('click', resetZoomAll);

  // Floating nav
  var pane=document.getElementById('right-pane-interactive');
  el=document.getElementById('btn-scroll-top'); if(el) el.addEventListener('click', function(){ if (pane.scrollTo) pane.scrollTo({top:0, behavior:'smooth'}); else pane.scrollTop=0; });
  el=document.getElementById('btn-scroll-bottom'); if(el) el.addEventListener('click', function(){ if (pane.scrollTo) pane.scrollTo({top:pane.scrollHeight, behavior:'smooth'}); else pane.scrollTop=pane.scrollHeight; });
})();
</script>
</body>
</html>
"""

# ---------------- Python helpers ----------------

def render_html(template: str, mapping: dict) -> str:
    out = template
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
    p = argparse.ArgumentParser(
        description="Convert metrics JSON → interactive HTML (Summary + Interactive Select).",
        formatter_class=argparse.RawTextHelpFormatter, add_help=True,
    )
    p.add_argument("-i","--input",nargs='+',help="Input JSON file(s) or directory path(s).")
    p.add_argument("-o","--output",help="Output path. If directory or ends with '/', writes <stem>.html inside.")
    p.add_argument("--title",help='Page title (default: "Metrics Report").')
    p.add_argument("--inline-js",action="store_true",help="Embed Plotly JS inline (offline HTML).")
    p.add_argument("--ist",action="store_true",help="Use Asia/Kolkata timestamps.")
    p.add_argument("--chart-height",type=int,default=520,help=argparse.SUPPRESS)
    p.add_argument("--interactive-columns",type=int,default=1,help=argparse.SUPPRESS)
    p.add_argument("--narrow",action="store_true",help=argparse.SUPPRESS)
    p.add_argument("--timezone","--tz",dest="timezone",default=None,help=argparse.SUPPRESS)
    p.add_argument("-v","--verbose",action="store_true",help="Verbose logging.")
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

def find_json_files(paths: List[str]) -> List[Path]:
    out: List[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            logging.info(f"Searching for JSON files in directory: {p}")
            out.extend(list(p.rglob("*.json")))
        elif p.is_file():
            if p.suffix.lower()==".json": out.append(p)
            else: logging.warning(f"Skipping non-JSON: {p}")
        else:
            logging.error(f"Path does not exist: {p}")
    return sorted({q.resolve() for q in out})

def _looks_like_dir_string(raw_out: str) -> bool:
    return raw_out.endswith("/") or raw_out.endswith("\\") or raw_out.strip() in (".","./",".\\")

def resolve_output_path(input_path: Path, raw_out: Optional[str], multi_inputs: bool) -> Path:
    if not raw_out:
        return input_path.with_suffix(".html").resolve()
    out = Path(raw_out).expanduser()
    if out.exists() and out.is_dir():
        return (out / f"{input_path.stem}.html").resolve()
    if _looks_like_dir_string(raw_out):
        return (out / f"{input_path.stem}.html").resolve()
    if out.suffix.lower() not in (".html",".htm"):
        out = out.with_suffix(".html")
    if multi_inputs:
        parent = out.parent if out.parent != Path("") else Path.cwd()
        parent.mkdir(parents=True, exist_ok=True)
        return (parent / f"{input_path.stem}.html").resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    return out.resolve()

def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read or decode JSON from {path}: {e}")
        return None

def _parse_timestamp_series(ts: pd.Series) -> pd.Series:
    dt = pd.to_datetime(ts, utc=True, errors="coerce")
    if dt.isna().all():
        nums = pd.to_numeric(ts, errors="coerce")
        if nums.notna().any():
            mx = nums.max()
            unit = "ms" if mx >= 1e11 else "s"
            dt = pd.to_datetime(nums, unit=unit, utc=True, errors="coerce")
    return dt

def _to_tz_series(s: pd.Series, tz: str) -> pd.Series:
    if hasattr(s, "dt"):
        try:
            return s.dt.tz_convert(tz)
        except Exception:
            return pd.to_datetime(s, errors="coerce", utc=True).dt.tz_convert(tz)
    return pd.to_datetime(s, errors="coerce", utc=True).dt.tz_convert(tz)

def make_dataframe(series_entry):
    header = series_entry.get("header", {}) or {}
    name = header.get("name", "unknown")
    units = header.get("units", "UNKNOWN")
    desc  = header.get("metric_description", "") or name
    data  = series_entry.get("data", []) or []

    df = pd.DataFrame(data)
    if df.empty or "timestamp" not in df.columns or "value" not in df.columns:
        return pd.DataFrame(columns=["time","value","metric","units","description"])

    df["time"] = _parse_timestamp_series(df["timestamp"])
    df.drop(columns=["timestamp"], inplace=True, errors="ignore")
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df["metric"] = name; df["units"] = units; df["description"] = desc
    df = df.sort_values("time").reset_index(drop=True)
    return df[["time","value","metric","units","description"]]

def collect_stats(series_list):
    rows=[]
    for s in series_list:
        h=s.get("header",{}) or {}; st=h.get("statistics",{}) or {}
        rows.append({"metric":h.get("name",""),"units":h.get("units",""),
                     "description":h.get("metric_description","") or h.get("name",""),
                     "mean":st.get("mean"),"min":st.get("min"),"min_ts":st.get("min_ts"),
                     "max":st.get("max"),"max_ts":st.get("max_ts"),"sum":st.get("sum"),
                     "trend":st.get("trend"),"num_samples":st.get("num_samples")})
    df=pd.DataFrame(rows)
    if not df.empty: df=df.sort_values(["units","metric"],kind="stable")
    return df

def _human_number(x):
    if pd.isna(x): return ""
    try: x=float(x)
    except Exception: return str(x)
    neg=x<0; ax=abs(x)
    for unit,th in [("T",1e12),("B",1e9),("M",1e6),("K",1e3)]:
        if ax>=th:
            s=f"{ax/th:,.2f}".rstrip("0").rstrip(".")+unit
            return "-"+s if neg else s
    s=f"{x:,.6f}".rstrip("0").rstrip(".") if x!=int(x) else f"{int(x):,d}"
    return "-"+s if neg else s

def _fmt_ts(ts_str: str, tz_name: str) -> str:
    if not ts_str: return ""
    try:
        t=pd.to_datetime(ts_str, utc=True, errors="coerce")
        if pd.isna(t): return str(ts_str)
        return t.tz_convert(tz_name).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts_str)

def extract_entity_meta(data, series):
    root=data if isinstance(data,dict) else {}
    top=data.get("header") or {}
    series_headers=[]
    if isinstance(series,list):
        for s in series:
            h=(s or {}).get("header") or {}
            if isinstance(h,dict) and h: series_headers.append(h)
    metric_names={(h.get("name") or "").strip() for h in series_headers if isinstance(h.get("name"),str)}
    metric_names.discard("")
    def first_nonempty(dicts, keys, disallow=()):
        for d in dicts:
            for k in keys:
                if k in d:
                    v=d[k]
                    if v not in (None,"","N/A"):
                        if isinstance(v,str) and v.strip() in disallow: continue
                        return v
        return ""
    entity_uuid = first_nonempty([root,top]+series_headers, ["entity_uuid","entityUuid","uuid","vs_uuid","pool_uuid","se_uuid"])
    metric_entity = first_nonempty([root,top]+series_headers, ["metric_entity","metricEntity","entity_type","entityType","type"])
    entity_name = (first_nonempty([root],["entity_name","entityName","display_name","name","vs_name","pool_name","se_name"],metric_names)
                   or first_nonempty([top],["entity_name","entityName","display_name","vs_name","pool_name","se_name"],metric_names)
                   or first_nonempty(series_headers,["entity_name","entityName","display_name","vs_name","pool_name","se_name"],metric_names))
    return {"entity_uuid":entity_uuid,"metric_entity":metric_entity,"entity_name":entity_name}

def build_entity_display(meta: dict) -> str:
    name=meta.get("entity_name") or ""; uuid=meta.get("entity_uuid") or ""; et=meta.get("metric_entity") or ""
    parts=[]
    if name: parts.append(str(name))
    if uuid: parts.append(f"({uuid})")
    if et: parts.append(("– " if (name or uuid) else "")+et)
    return " ".join(parts) if parts else "N/A"

def process_file(file_path: Path, args, multi_inputs: bool):
    logging.info(f"Processing: {file_path}")
    data=load_json(file_path)
    if data is None: return
    series=data.get("series",[])
    if not isinstance(series,list):
        logging.warning(f"'series' is not a list in {file_path}. Skipping.")
        return

    meta=extract_entity_meta(data,series)
    entity_display=build_entity_display(meta)

    frames=[make_dataframe(s) for s in series]
    frames=[f for f in frames if not f.empty]
    if not frames:
        logging.error(f"No usable data rows in {file_path}.")
        return
    all_df=pd.concat(frames, ignore_index=True)
    all_df.dropna(subset=["time","value"], inplace=True)
    all_df.sort_values("time", inplace=True)
    if all_df.empty:
        logging.error(f"All rows are NaN after parsing in {file_path}.")
        return

    metrics_json={}
    for metric_id, group in all_df.groupby('metric'):
        group=group.sort_values('time')
        t_local = _to_tz_series(group['time'], args.timezone)
        times = t_local.dt.strftime('%Y-%m-%d %H:%M:%S').tolist()
        metrics_json[str(metric_id)] = {
            "metric": str(metric_id),
            "unit": str(group['units'].iloc[0]) if not group.empty else "",
            "label": str(group['description'].iloc[0]) if not group.empty else str(metric_id),
            "x": times,
            "y": group['value'].tolist()
        }

    stats_df=collect_stats(series)
    if not stats_df.empty:
        stats_df['min_ts']=stats_df['min_ts'].apply(lambda x:_fmt_ts(x,args.timezone))
        stats_df['max_ts']=stats_df['max_ts'].apply(lambda x:_fmt_ts(x,args.timezone))
        stats_html=stats_df.to_html(index=False, classes='metrics-table', na_rep="",
                                    float_format=lambda x:f"{x:,.2f}",
                                    formatters={'min':_human_number,'max':_human_number,'mean':_human_number,'sum':_human_number,
                                                'num_samples':'{:,}'.format})
    else:
        stats_html="<table><tr><td>No summary statistics available.</td></tr></table>"

    if args.inline_js and _get_plotlyjs:
        plotly_js="<script>"+_get_plotlyjs()+"</script>"
    else:
        plotly_js='<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'

    start_time=_to_tz_series(all_df['time'], args.timezone).min().strftime('%Y-%m-%d %H:%M:%S')
    stop_time =_to_tz_series(all_df['time'], args.timezone).max().strftime('%Y-%m-%d %H:%M:%S')
    if len(all_df)>1:
        diffs=all_df['time'].diff().dropna()
        diffs=diffs[diffs.dt.total_seconds()>0]
        step_sec=diffs.median().total_seconds() if not diffs.empty else "N/A"
    else:
        step_sec="N/A"

    mapping={
        "title": args.title,
        "entity_display": entity_display,
        "start": start_time, "stop": stop_time,
        "step": f"{step_sec:.0f}" if isinstance(step_sec,(float,int)) else step_sec,
        "tz_label": args.timezone,
        "summary_table": stats_html,
        "metrics_json": json.dumps(metrics_json, ensure_ascii=False),
        "plotly_js": plotly_js,
        "chart_height": args.chart_height,
    }
    html=render_html(HTML_TEMPLATE, mapping)
    out_path=resolve_output_path(file_path, args.output, multi_inputs)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
        logging.info(f"Wrote: {out_path}")
    except IOError as e:
        logging.error(f"Write failed for {out_path}: {e}")

def main():
    args=parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='[%(levelname)s] %(message)s')
    inputs=find_json_files(args.input)
    if not inputs:
        logging.error("No valid JSON files found.")
        sys.exit(1)
    logging.info(f"Found {len(inputs)} JSON file(s).")
    multi=len(inputs)>1
    for p in inputs:
        process_file(p, args, multi_inputs=multi)

if __name__=="__main__":
    main()
