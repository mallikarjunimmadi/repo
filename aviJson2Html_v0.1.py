#!/usr/bin/env python3
# json2html.py — JSON → interactive HTML graphs (Plotly)
#
# Features:
# - Accepts multiple JSON files and/or directories (recurses).
# - Validates JSON; ignores non-JSON.
# - Generates a separate HTML per JSON.
# - Extended, readable logging (use -v for DEBUG).
# - Robust entity metadata extraction (TOP-LEVEL → header → series headers),
#   never using metric ids as entity names.
# - Entity line shows: <entity_name> (<entity_uuid>) – <metric_entity>.
# - Inline Plotly JS option for fully offline HTML.
# - Interactive "Select metrics" UI, grouped-by-unit or per-metric, with synced zoom.

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, List

import pandas as pd
import plotly.graph_objects as go  # noqa: F401
from plotly.offline import plot as plot_offline  # noqa: F401

# Robust get_plotlyjs import across Plotly versions
try:
    from plotly.offline.offline import get_plotlyjs as _get_plotlyjs  # plotly>=4
except Exception:
    try:
        from plotly.offline import get_plotlyjs as _get_plotlyjs
    except Exception:
        _get_plotlyjs = None  # fall back to CDN

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
${plotly_js}
<style>
  :root {
    --page-max-width: 100%;
    --interactive-cols: ${interactive_columns};
    --primary:#2563eb; --primary-600:#1d4ed8;
    --success:#16a34a; --success-600:#15803d;
    --warn:#ea580c; --warn-600:#c2410c;
    --muted:#6b7280; --muted-600:#52525b;
    --border:#e5e7eb; --bg:#ffffff;
    --pill:#f3f4f6; --shadow:0 10px 20px rgba(0,0,0,.12);
  }
  html, body { width:100%; }
  body {
    font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, "Helvetica Neue", Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji";
    margin: 16px; max-width: var(--page-max-width); background: var(--bg);
  }
  h1 { font-size: 20px; margin: 0 0 12px; }
  h2 { font-size: 16px; margin: 10px 0 8px; }
  .meta { color:#555; margin-bottom: 16px; }

  /* Tab chips */
  .tabs { display:flex; flex-wrap:wrap; gap:8px; margin: 16px 0 8px; }
  .tab-btn {
    padding: 8px 12px; border:1px solid var(--border); border-radius:999px; cursor:pointer;
    background:#f8fafc; user-select:none; transition:all .15s ease; font-weight:600; font-size:13px;
  }
  .tab-btn:hover { background:#eef2ff; }
  .tab-btn.active { background:#e9f3ff; border-color:#bcd6ff; }

  .panel { display:none; }
  .panel.active { display:block; }
  .panel > div { width: 100%; }

  /* Table */
  table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }
  th, td { border: 1px solid #eee; padding: 6px 8px; text-align: left; }
  th { background: #fafafa; }
  .note { font-size: 12px; color:#666; margin-top: 8px; }

  .controls { display:flex; gap:12px; align-items:flex-start; flex-wrap:wrap; margin: 8px 0 12px; }

  /* Small buttons */
  .btn { appearance:none; border:1px solid var(--border); background:#fff; padding:6px 10px; border-radius:8px; cursor:pointer; transition:all .15s ease; font-size:12px; }
  .btn:hover { background:#f3f4f6; }
  .btn-primary { background: var(--primary); border-color: var(--primary); color:#fff; }
  .btn-primary:hover { background: var(--primary-600); border-color: var(--primary-600); }

  /* Chip-style action buttons */
  .chip-bar { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .chip-btn {
    display:inline-flex; align-items:center; gap:8px;
    padding:8px 12px; border:1px solid var(--border); border-radius:999px; cursor:pointer;
    background:#f8fafc; user-select:none; transition:all .15s ease; font-weight:600; font-size:13px;
  }
  .chip-btn:hover { background:#eef2ff; }
  .chip-primary { background:#e9f3ff; border-color:#bcd6ff; color:#0f172a; }
  .chip-primary:hover { background:#dbeafe; }
  .chip-warn { background:#fff7ed; border-color:#fed7aa; color:#7c2d12; }
  .chip-warn:hover { background:#ffedd5; }
  .chip-muted { background:#f4f4f5; border-color:#e4e4e7; color:#27272a; }
  .chip-muted:hover { background:#e9e9eb; }

  /* Toggle chip for Individual graphs */
  .chip-toggle {
    display:inline-flex; align-items:center; gap:8px;
    padding:8px 12px; border:1px solid var(--border); border-radius:999px; cursor:pointer;
    background:#f8fafc; transition:all .15s ease; font-weight:600; font-size:13px;
  }
  .chip-toggle.active { background:#ecfdf5; border-color:#a7f3d0; color:#065f46; }
  .chip-toggle:hover { filter:brightness(0.98); }
  .sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }

  /* MultiSelect */
  .ms { position: relative; width: 520px; max-width: 90vw; }
  .ms-toggle {
    min-height: 42px; border:1px solid var(--border); border-radius:10px; padding:6px 36px 6px 10px;
    display:flex; align-items:center; gap:6px; background:#fff; cursor:pointer;
    overflow:hidden; white-space:nowrap;
  }
  .ms-placeholder { color:#9ca3af; font-size:13px; }
  .ms-tags { display:flex; gap:6px; align-items:center; white-space:nowrap; overflow-x:auto; overflow-y:hidden; scrollbar-width: thin; }
  .ms-tags::-webkit-scrollbar { height: 8px; }
  .ms-tags::-webkit-scrollbar-thumb { background:#d1d5db; border-radius:8px; }
  .ms-tag { display:inline-flex; align-items:center; gap:6px; background: var(--pill); border:1px solid var(--border); border-radius:999px; padding:3px 8px; font-size:12px; }
  .ms-tag button { border:none; background:transparent; cursor:pointer; font-size:14px; line-height:1; }
  .ms-counter { margin-left:auto; font-size:12px; color:#374151; background:#eef2ff; border:1px solid #c7d2fe; padding:2px 8px; border-radius:999px; }
  .ms-caret { position:absolute; right:10px; top:50%; transform: translateY(-50%); pointer-events:none; opacity:.7; }

  .ms-panel {
    position:absolute; z-index:1000; left:0; width:100%;
    background:#fff; border:1px solid var(--border); border-radius:12px; box-shadow: var(--shadow);
    display:none;
  }
  .ms.open .ms-panel { display:block; }
  .ms-panel.down { top: calc(100% + 6px); bottom:auto; }
  .ms-panel.up { bottom: calc(100% + 6px); top:auto; }

  .ms-header { display:flex; gap:8px; align-items:center; padding:8px; border-bottom:1px solid var(--border); }
  .ms-search { flex:1; display:flex; align-items:center; gap:6px; border:1px solid var(--border); border-radius: 8px; padding:6px 8px; }
  .ms-search input { border:none; outline:none; flex:1; font-size:13px; }
  .ms-actions .btn { padding:6px 10px; border-radius:8px; font-size:12px; }

  .ms-body { overflow:auto; }
  .ms-group { border-top:1px solid var(--border); }
  .ms-group:first-child { border-top:none; }
  .ms-group-title { position: sticky; top: 0; background:#f9fafb; font-weight:600; font-size:12px; padding:6px 8px; color:#374151; border-bottom:1px solid var(--border); z-index:1; }
  .ms-item { display:flex; align-items:center; gap:8px; padding:8px; cursor:pointer; user-select:none; }
  .ms-item:hover { background:#f9fafb; }
  .ms-item input { cursor:pointer; }
  .ms-item .sub { color:#6b7280; font-size:12px; }

  .ms-footer { display:flex; justify-content:space-between; align-items:center; padding:8px; border-top:1px solid var(--border); font-size:12px; color:#muted; }
  .ms-count { font-weight:600; color:#111827; }

  .charts-wrap { display:grid; grid-template-columns: repeat(var(--interactive-cols), 1fr); gap:16px; }
  .chart-card { padding:8px; border:1px solid #eee; border-radius:12px; box-shadow:0 1px 4px rgba(0,0,0,.04); background:#fff; }
  .chart-title { font-weight:600; margin-bottom:6px; font-size:14px; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid #ddd; font-size:12px; color:#444; background:#fafafa; }
  .chart-card > div { width:100%; }

  .warn { color:#b45309; background:#fff7ed; border:1px solid #fed7aa; padding:6px 8px; border-radius:8px; display:none; }
</style>
</head>
<body>
  <h1>${title}</h1>
  <div class="meta">
    <div><b>Entity:</b> ${entity_display}</div>
    <div><b>Window:</b> ${start} → ${stop} | <b>Step:</b> ${step}s | <b>Time Zone:</b> ${tz_label}</div>
  </div>

  <div class="tabs" id="tabs">
    <div class="tab-btn" data-target="panel-summary">Summary</div>
    <div class="tab-btn" data-target="panel-interactive">Interactive Select</div>
  </div>

  <div class="panel" id="panel-summary">
    <h2>Summary Statistics</h2>
    ${summary_table}
    <div class="note">
      Tip: Use the toggle to switch between grouped-by-unit charts and individual charts.
      Zoom/pan any chart to sync the time window across all currently displayed charts.
    </div>
  </div>

  <div class="panel" id="panel-interactive">
    <h2>Interactive Select</h2>
    <div class="controls">
      <div class="ms" id="ms">
        <div class="ms-toggle" id="ms-toggle" aria-haspopup="listbox" aria-expanded="false" title="Click to select metrics">
          <span class="ms-placeholder" id="ms-placeholder">Select metrics…</span>
          <div class="ms-tags" id="ms-tags" style="display:none;"></div>
          <span class="ms-counter" id="ms-counter" style="display:none;">0</span>
          <svg class="ms-caret" width="16" height="16" viewBox="0 0 24 24" fill="none">
            <path d="M6 9l6 6 6-6" stroke="#6b7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>

        <div class="ms-panel down" id="ms-panel" role="listbox">
          <div class="ms-header">
            <div class="ms-search">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M21 21l-4.3-4.3M10 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Z" stroke="#6b7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              <input id="ms-search" type="text" placeholder="Search metrics or units..." />
            </div>
            <div class="ms-actions">
              <button class="btn" id="ms-select-all" type="button">Select All</button>
              <button class="btn" id="ms-clear" type="button">Clear</button>
              <button class="btn btn-primary" id="ms-show" type="button">Show Selected</button>
            </div>
          </div>
          <div class="ms-body" id="ms-body"></div>
          <div class="ms-footer">
            <div><span class="ms-count" id="ms-count">0</span> selected</div>
            <div class="note">Legend shows metric IDs</div>
          </div>
        </div>
      </div>

      <div class="chip-bar">
        <button id="btn-plot" class="chip-btn chip-primary" type="button">Plot</button>
        <button id="btn-clear" class="chip-btn chip-warn" type="button">Clear Charts</button>
        <button id="btn-reset-range" class="chip-btn chip-muted" type="button">Reset Zoom</button>

        <input type="checkbox" id="chk-individual" class="sr-only" aria-hidden="true"/>
        <button id="chip-individual" class="chip-toggle" type="button" aria-pressed="false" title="Toggle: Individual graphs">Individual graphs</button>
      </div>

      <div id="warn" class="warn"></div>
    </div>

    <div class="charts-wrap" id="interactive-panels"></div>
  </div>

<script>
const METRICS_DATA = ${metrics_json};
const METRIC_NAMES = Object.keys(METRICS_DATA).sort((a,b)=> a.localeCompare(b));

const MS = (() => {
  const state = { open:false, groups:{}, selected:new Set(), showOnlySelected:false, els:{} };
  function qs(id){ return document.getElementById(id); }
  function esc(s){ return (s||"").replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
  function buildGroups() {
    state.groups = {};
    for (const name of METRIC_NAMES) {
      const m = METRICS_DATA[name];
      const unit = (m && m.unit) ? m.unit : "UNKNOWN";
      (state.groups[unit] ||= []).push(name);
    }
    for (const u of Object.keys(state.groups)) state.groups[u].sort((a,b)=>a.localeCompare(b));
  }
  function renderList(filter="") {
    const body = state.els.body; body.innerHTML = "";
    const f = filter.trim().toLowerCase();
    for (const unit of Object.keys(state.groups).sort((a,b)=>a.localeCompare(b))) {
      let base = state.groups[unit];
      if (state.showOnlySelected) base = base.filter(n => state.selected.has(n));
      const names = base.filter(n=>{
        if (!f) return true;
        const m = METRICS_DATA[n];
        const hay = (n + " " + ((m && (m.label||m.metric))||"") + " " + unit).toLowerCase();
        return hay.includes(f);
      });
      if (!names.length) continue;
      const g = document.createElement('div'); g.className = 'ms-group';
      const gt = document.createElement('div'); gt.className = 'ms-group-title'; gt.textContent = unit;
      g.appendChild(gt);
      for (const name of names) {
        const m = METRICS_DATA[name] || {};
        const row = document.createElement('label'); row.className = 'ms-item';
        const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = state.selected.has(name); cb.setAttribute('data-name', name);
        const textWrap = document.createElement('span'); textWrap.className = 'ms-text';
        textWrap.innerHTML = "<div><b>"+esc(name)+"</b></div><div class='sub'>"+esc(m.label||m.metric||"")+"</div>";
        row.appendChild(cb); row.appendChild(textWrap);
        cb.addEventListener('change', (e)=>{ e.stopPropagation(); toggle(name, cb.checked); if (state.showOnlySelected) renderList(state.els.search.value); });
        g.appendChild(row);
      }
      body.appendChild(g);
    }
    adjustPanelPositionAndSize();
  }
  function renderTagsAndCounter() {
    const tags = state.els.tags, placeholder = state.els.placeholder, counter = state.els.counter;
    tags.innerHTML = "";
    const arr = Array.from(state.selected).sort((a,b)=> a.localeCompare(b));
    if (!state.selected.size) { tags.style.display = "none"; counter.style.display = "none"; placeholder.style.display = ""; return; }
    placeholder.style.display = "none"; tags.style.display = "flex";
    const SHOW = 3;
    for (const name of arr.slice(0, SHOW)) {
      const t = document.createElement('span'); t.className = 'ms-tag';
      t.innerHTML = "<span>"+esc(name)+"</span>";
      const x = document.createElement('button'); x.type="button"; x.innerHTML = "&times;";
      x.addEventListener('click', (e)=>{ e.stopPropagation(); state.selected.delete(name); syncChecks(); renderTagsAndCounter(); updateCount(); if (state.showOnlySelected) renderList(state.els.search.value); });
      t.appendChild(x); tags.appendChild(t);
    }
    counter.textContent = state.selected.size + " selected"; counter.style.display = "";
  }
  function updateCount(){ state.els.count.textContent = state.selected.size; }
  function syncChecks() {
    const boxes = state.els.body.querySelectorAll('input[type="checkbox"][data-name]');
    boxes.forEach(cb => { cb.checked = state.selected.has(cb.getAttribute('data-name')); });
  }
  function toggle(name, val) { if (val) state.selected.add(name); else state.selected.delete(name); renderTagsAndCounter(); updateCount(); updateShowButtonState(); }
  function selectAll() { for (const n of METRIC_NAMES) state.selected.add(n); syncChecks(); renderTagsAndCounter(); updateCount(); updateShowButtonState(); if (state.showOnlySelected) renderList(state.els.search.value); }
  function clearAll() { state.selected.clear(); syncChecks(); renderTagsAndCounter(); updateCount(); updateShowButtonState(); if (state.showOnlySelected) renderList(state.els.search.value); }

  function open()  { if (state.open) return; state.open  = true; }
  function close() { if (!state.open) return; state.open = false; }
  function toggleOpen(){ state.open ? close() : open(); }

  function adjustPanelPositionAndSize() {
    const panel = state.els.panel; if (!panel) return; panel.classList.remove('up','down');
    const rootRect = state.els.root.getBoundingClientRect(); const viewportH = window.innerHeight || document.documentElement.clientHeight;
    const spaceBelow = viewportH - rootRect.bottom - 12; const spaceAbove = rootRect.top - 12; const HEADER_FOOTER = 92;
    if (spaceBelow >= 220 || spaceBelow >= spaceAbove) { panel.classList.add('down'); const maxH = Math.max(180, Math.min(420, spaceBelow)); panel.style.maxHeight = (maxH) + "px"; const bodyMax = Math.max(120, maxH - HEADER_FOOTER); state.els.body.style.maxHeight = bodyMax + "px"; }
    else { panel.classList.add('up'); const maxH = Math.max(180, Math.min(420, spaceAbove)); panel.style.maxHeight = (maxH) + "px"; const bodyMax = Math.max(120, maxH - HEADER_FOOTER); state.els.body.style.maxHeight = bodyMax + "px"; }
  }
  function updateShowButtonState(){ const btn = document.getElementById('ms-show'); if (!btn) return; btn.disabled = state.showOnlySelected ? false : (state.selected.size === 0); btn.textContent = state.showOnlySelected ? "Show All" : "Show Selected"; }
  function setupDOM() {
    function g(id){ return document.getElementById(id); }
    state.els.root = g('ms'); state.els.toggle = g('ms-toggle'); state.els.panel = g('ms-panel'); state.els.placeholder = g('ms-placeholder');
    state.els.tags = g('ms-tags'); state.els.counter = g('ms-counter'); state.els.body = g('ms-body'); state.els.count = g('ms-count'); state.els.search = g('ms-search');
    state.els.toggle.addEventListener('click', (e)=> { e.stopPropagation(); state.open = !state.open; state.els.root.classList.toggle('open', state.open); state.els.toggle.setAttribute('aria-expanded', state.open ? 'true':'false'); if (state.open){ renderList(state.els.search.value); syncChecks(); setTimeout(()=> state.els.search.focus(), 0);} });
    document.addEventListener('click', (e)=>{ if (!state.els.root.contains(e.target)) { state.open = false; state.els.root.classList.remove('open'); state.els.toggle.setAttribute('aria-expanded','false'); } });
    g('ms-select-all').addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); selectAll(); });
    g('ms-clear').addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); clearAll(); });
    const btnShow = g('ms-show');
    btnShow.addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); state.showOnlySelected = !state.showOnlySelected; renderList(state.els.search.value); updateShowButtonState(); });
    state.els.search.addEventListener('input', ()=> renderList(state.els.search.value));
    window.addEventListener('resize', ()=> { if (state.open) adjustPanelPositionAndSize(); });
    window.addEventListener('scroll', ()=> { if (state.open) adjustPanelPositionAndSize(); }, true);
  }
  function init() { setupDOM(); buildGroups(); renderTagsAndCounter(); updateCount(); updateShowButtonState(); }
  function getSelected(){ return Array.from(state.selected); }
  return { init, getSelected, selectAll, clear: clearAll };
})();

function truncateLabel(s, maxLen=140){ if(!s) return ''; return s.length>maxLen ? s.slice(0,maxLen-1)+'…' : s; }
function groupByUnit(selectedNames){
  const out={};
  for(const name of selectedNames){
    const m = METRICS_DATA[name]; if(!m) continue;
    const u = m.unit || "UNKNOWN";
    (out[u] ||= []).push(m);
  }
  return out;
}
function showWarn(msg){ const w=document.getElementById('warn'); if(!w) return; w.textContent=msg||''; w.style.display=msg?'block':'none'; }

function renderInteractive(){
  const names = MS.getSelected();
  const wrap = document.getElementById('interactive-panels'); if(!wrap) return;
  wrap.innerHTML = '';
  if(!names.length){ showWarn('Select one or more metrics and click Plot.'); return; }
  showWarn('');

  const individual = document.getElementById('chk-individual')?.checked;
  if (individual) renderPerMetric(names, wrap);
  else renderGroupedByUnit(names, wrap);
}

function renderPerMetric(names, wrap){
  const chartIds=[];
  for(const metricName of names){
    const m = METRICS_DATA[metricName]; if(!m) continue;
    const unit = m.unit || "UNKNOWN";
    const xTitle = truncateLabel(m.label || m.metric);

    const card=document.createElement('div'); card.className='chart-card';
    const title=document.createElement('div'); title.className='chart-title';
    title.innerHTML = metricName + ' <span class="pill">' + unit + '</span>';
    const div=document.createElement('div');
    const chartId='chart-'+metricName.replace(/[^a-zA-Z0-9_-]/g,'_')+'-'+Math.random().toString(36).slice(2,8);
    div.id=chartId; card.appendChild(title); card.appendChild(div); wrap.appendChild(card);

    const traces=[{ type:'scatter', mode:'lines+markers', x:m.x, y:m.y, name:metricName,
      hovertemplate:'Metric: '+(m.label||m.metric)+'<br>Time: %{x}<br>Value: %{y}<extra></extra>' }];

    const containerWidth = div.clientWidth || window.innerWidth - 32;
    const layout={ title:'', xaxis:{ title:xTitle }, yaxis:{ title:'' }, hovermode:'x unified',
      showlegend:false, margin:{ t:40, r:30, b:60, l:60 }, height:${chart_height}, autosize:true, width:containerWidth };

    Plotly.newPlot(chartId, traces, layout, {responsive:true});
    chartIds.push(chartId);
    window.addEventListener('resize', ()=>{ const w=div.clientWidth||window.innerWidth-32; Plotly.relayout(chartId,{width:w,height:${chart_height}}); });
  }
  if(chartIds.length>1) setupRangeSync(chartIds);
}

function renderGroupedByUnit(names, wrap){
  const byU=groupByUnit(names);
  const chartIds=[];
  for(const unit of Object.keys(byU)){
    const metrics=byU[unit]; if(!metrics.length) continue;

    const card=document.createElement('div'); card.className='chart-card';
    const title=document.createElement('div'); title.className='chart-title';
    title.innerHTML='Selected Metrics <span class="pill">'+unit+'</span>';
    const div=document.createElement('div');
    const chartId='chart-unit-'+unit.replace(/[^a-zA-Z0-9_-]/g,'_')+'-'+Math.random().toString(36).slice(2,8);
    div.id=chartId; card.appendChild(title); card.appendChild(div); wrap.appendChild(card);

    const traces = metrics.map(m=>({ type:'scatter', mode:'lines+markers', x:m.x, y:m.y, name:m.metric,
      hovertemplate:'Metric: '+(m.label||m.metric)+'<br>Time: %{x}<br>Value: %{y}<extra></extra>' }));

    const containerWidth = div.clientWidth || window.innerWidth - 32;
    const layout={ title:'', xaxis:{ title:'' }, yaxis:{ title:'' }, hovermode:'x unified', showlegend:true,
      legend:{ orientation:'h', x:0, xanchor:'left', y:-0.25, yanchor:'top', font:{ size:11 } },
      margin:{ t:40, r:30, b:150, l:60 }, height:${chart_height}, autosize:true, width:containerWidth };

    Plotly.newPlot(chartId, traces, layout, {responsive:true});
    chartIds.push(chartId);
    window.addEventListener('resize', ()=>{ const w=div.clientWidth||window.innerWidth-32; Plotly.relayout(chartId,{width:w,height:${chart_height}}); });
  }
  if(chartIds.length>1) setupRangeSync(chartIds);
}

function setupRangeSync(chartIds){
  let suppress=false;
  function parse(ev){
    let r0=null,r1=null,autorange=null,changed=false;
    if(ev && Object.prototype.hasOwnProperty.call(ev,'xaxis.autorange')){ autorange=!!ev['xaxis.autorange']; changed=true; return {r0,r1,autorange,changed}; }
    if(Array.isArray(ev?.['xaxis.range'])){ r0=ev['xaxis.range'][0]; r1=ev['xaxis.range'][1]; changed=true; }
    else if(Object.prototype.hasOwnProperty.call(ev||{},'xaxis.range[0]') && Object.prototype.hasOwnProperty.call(ev||{},'xaxis.range[1]')){ r0=ev['xaxis.range[0]']; r1=ev['xaxis.range[1]']; changed=true; }
    return {r0,r1,autorange,changed};
  }
  function apply(src,r0,r1,auto){
    suppress=true;
    for(const id of chartIds){ if(id===src) continue;
      if(auto) Plotly.relayout(id,{'xaxis.autorange':true});
      else if(r0!=null && r1!=null) Plotly.relayout(id,{'xaxis.range':[r0,r1],'xaxis.autorange':false});
    }
    setTimeout(()=>{suppress=false;},0);
  }
  for(const id of chartIds){
    const div=document.getElementById(id);
    div.on('plotly_relayout',(ev)=>{ if(suppress) return; const {r0,r1,autorange,changed}=parse(ev); if(!changed) return; apply(id,r0,r1,autorange); });
  }
}

// Reset zoom (X+Y) for all interactive charts
function resetZoomAll() {
  document.querySelectorAll('#interactive-panels .chart-card > div[id^="chart"]').forEach(div => {
    Plotly.relayout(div.id, { 'xaxis.autorange': true, 'yaxis.autorange': true });
  });
}

(function init(){
  const tabs=document.querySelectorAll('.tab-btn'); const panels=document.querySelectorAll('.panel');
  function activate(id){ tabs.forEach(t=>t.classList.toggle('active',t.dataset.target===id)); panels.forEach(p=>p.classList.toggle('active',p.id===id)); }
  tabs.forEach(t=>t.addEventListener('click',()=>activate(t.dataset.target)));
  if(tabs.length) activate(tabs[0].dataset.target);

  MS.init();

  document.getElementById('btn-plot')?.addEventListener('click', renderInteractive);
  document.getElementById('btn-clear')?.addEventListener('click', ()=>{ document.getElementById('interactive-panels').innerHTML=''; showWarn(''); });
  document.getElementById('btn-reset-range')?.addEventListener('click', resetZoomAll);

  const chk = document.getElementById('chk-individual');
  const chip = document.getElementById('chip-individual');
  function syncChip(){
    const on = !!chk.checked; chip.classList.toggle('active', on); chip.setAttribute('aria-pressed', on ? 'true' : 'false');
  }
  chip.addEventListener('click', ()=>{ chk.checked = !chk.checked; syncChip(); if ((MS.getSelected?.()||[]).length > 0) renderInteractive(); });
  chk.addEventListener('change', ()=>{ syncChip(); if ((MS.getSelected?.()||[]).length > 0) renderInteractive(); });
  syncChip();
})();
</script>
</body>
</html>
"""

def render_html(template: str, mapping: dict) -> str:
    out = template
    for k, v in mapping.items():
        out = out.replace("${" + k + "}", str(v))
    return out

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
        description="Convert metrics JSON → interactive HTML (Summary + Interactive Select).",
        formatter_class=argparse.RawTextHelpFormatter, add_help=True,
    )
    p.add_argument("-i", "--input", nargs='+',
                   help="Input file/directory path(s). Can be a list of .json files or a directory containing them.")
    p.add_argument("-o", "--output",
                   help="Output path. If it is a directory (or ends with '/' or '\\\\'), files will be written inside it as <input-stem>.html.")
    p.add_argument("--title", help='Page title (default: "Metrics Report").')
    p.add_argument("--inline-js", action="store_true", help="Embed Plotly JS inline (offline HTML).")
    p.add_argument("--ist", action="store_true", help="Use Asia/Kolkata timestamps.")
    # hidden opts
    p.add_argument("--chart-height", type=int, default=520, help=argparse.SUPPRESS)
    p.add_argument("--interactive-columns", type=int, default=1, help=argparse.SUPPRESS)
    p.add_argument("--narrow", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--timezone", "--tz", dest="timezone", default=None, help=argparse.SUPPRESS)
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    args = p.parse_args()

    if not args.input:
        args.input = [prompt_str("Enter input JSON file(s) or directory path(s)")]
        if not args.input[0]:
            p.error("Input path is required.")

    if args.output is None:
        args.output = ""  # Will be determined dynamically per file
    if not args.title:
        args.title = prompt_str("Title (optional)", "Metrics Report")

    # only prompt if flags not present (keeps CLI non-interactive-friendly)
    if "--ist" not in sys.argv:
        args.ist = prompt_yes_no("Render times in IST (Asia/Kolkata)?", default_yes=True)
    if "--inline-js" not in sys.argv:
        args.inline_js = prompt_yes_no("Embed Plotly JS in the HTML (works fully offline)?", default_yes=True)

    args.timezone = "Asia/Kolkata" if args.ist else "UTC"
    if args.narrow:
        args.interactive_columns = 2
    return args

def find_json_files(paths: List[str]) -> List[Path]:
    json_files: List[Path] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if path.is_dir():
            logging.info(f"Searching for JSON files in directory: {path}")
            json_files.extend([p for p in path.rglob('*.json')])
        elif path.is_file():
            if path.suffix.lower() == ".json":
                json_files.append(path)
            else:
                logging.warning(f"Skipping file with non-JSON extension: {path}")
        else:
            logging.error(f"Path does not exist: {path}")
    # de-dup
    uniq = sorted({p.resolve() for p in json_files})
    return [Path(p) for p in uniq]

def _looks_like_dir_string(raw_out: str) -> bool:
    # treat "--output out/" as a directory on any OS even if it doesn't exist yet
    return raw_out.endswith("/") or raw_out.endswith("\\") or raw_out.strip() in (".", "./", ".\\", "")

def resolve_output_path(input_path: Path, raw_out: Optional[str], multi_inputs: bool) -> Path:
    """
    - If raw_out is None/empty: write next to input as <stem>.html
    - If raw_out is an existing directory OR looks like a directory string: write into it as <stem>.html
    - If raw_out is a file path:
        * single input: write exactly there (ensure .html)
        * multiple inputs: write into that file's parent directory as <stem>.html (warn once)
    """
    if not raw_out:
        return input_path.with_suffix(".html").resolve()

    out_path = Path(raw_out).expanduser()
    if out_path.exists() and out_path.is_dir():
        return (out_path / f"{input_path.stem}.html").resolve()

    if _looks_like_dir_string(raw_out):
        return (out_path / f"{input_path.stem}.html").resolve()

    # treat as file
    suf = out_path.suffix.lower()
    if suf not in (".html", ".htm"):
        out_path = out_path.with_suffix(".html")
    if multi_inputs:
        parent = out_path.parent if out_path.parent != Path("") else Path.cwd()
        logging.warning(f"--output looks like a file but multiple inputs provided; writing per-file HTMLs into: {parent}")
        parent.mkdir(parents=True, exist_ok=True)
        return (parent / f"{input_path.stem}.html").resolve()
    else:
        parent = out_path.parent if out_path.parent != Path("") else Path.cwd()
        parent.mkdir(parents=True, exist_ok=True)
        return out_path.resolve()

def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read or decode JSON from {path}: {e}")
        return None

def make_dataframe(series_entry):
    header = series_entry.get("header", {}) or {}
    name = header.get("name", "unknown")
    units = header.get("units", "UNKNOWN")
    desc  = header.get("metric_description", "") or name
    data  = series_entry.get("data", []) or []

    df = pd.DataFrame(data)
    if df.empty:
        logging.warning(f"DataFrame for metric '{name}' is empty.")
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
    if pd.isna(x): return ""
    try:
        x = float(x)
    except Exception:
        return str(x)
    neg = x < 0
    ax = abs(x)
    for unit, th in [("T",1e12),("B",1e9),("M",1e6),("K",1e3)]:
        if ax >= th:
            val = ax / th
            s = f"{val:,.2f}".rstrip("0").rstrip(".") + unit
            return ("-" + s) if neg else s
    if x != int(x):
        s = f"{x:,.6f}".rstrip("0").rstrip(".")
    else:
        s = f"{int(x):,d}"
    return ("-" + s) if neg else s

def _fmt_ts(ts_str: str, tz_name: str) -> str:
    if not ts_str: return ""
    try:
        t = pd.to_datetime(ts_str, utc=True, errors="coerce")
        if pd.isna(t): return str(ts_str)
        t = t.tz_convert(tz_name)
        return t.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        logging.warning(f"Failed to format timestamp '{ts_str}': {e}")
        return str(ts_str)

# -------- Robust entity metadata extraction & display builder --------
def extract_entity_meta(data, series):
    """
    Pull entity info from:
      1) top-level object (data)
      2) top-level header (data['header'])
      3) series headers (but NEVER use 'name' from series headers)
    Avoid picking any value that equals a known metric id.
    """
    root = data if isinstance(data, dict) else {}
    top = data.get("header") or {}
    series_headers = []
    if isinstance(series, list):
        for s in series:
            h = (s or {}).get("header") or {}
            if isinstance(h, dict) and h:
                series_headers.append(h)

    # Metric ids to avoid misusing as entity_name
    metric_names = {
        (h.get("name") or "").strip()
        for h in series_headers
        if isinstance(h.get("name"), str)
    }
    metric_names.discard("")

    def first_nonempty(dicts, keys, *, disallow_values=()):
        for d in dicts:
            for k in keys:
                if k in d:
                    v = d[k]
                    if v not in (None, "", "N/A"):
                        sv = v.strip() if isinstance(v, str) else v
                        if isinstance(sv, str) and sv in disallow_values:
                            continue
                        return v
        return ""

    # UUID & entity type: allow across all tiers
    entity_uuid = first_nonempty(
        [root, top] + series_headers,
        ["entity_uuid", "entityUuid", "uuid", "vs_uuid", "pool_uuid", "se_uuid"]
    )
    metric_entity = first_nonempty(
        [root, top] + series_headers,
        ["metric_entity", "metricEntity", "entity_type", "entityType", "type"]
    )

    # Name:
    # - Root: allow 'name' (many exports put entity name at root)
    # - Top header: allow entity-name aliases but NOT generic 'name'
    # - Series headers: NEVER use 'name' (metric id); only explicit entity-name aliases if present
    entity_name = first_nonempty(
        [root],
        ["entity_name", "entityName", "display_name", "name", "vs_name", "pool_name", "se_name"],
        disallow_values=metric_names
    )
    if not entity_name:
        entity_name = first_nonempty(
            [top],
            ["entity_name", "entityName", "display_name", "vs_name", "pool_name", "se_name"],
            disallow_values=metric_names
        )
    if not entity_name:
        entity_name = first_nonempty(
            series_headers,
            ["entity_name", "entityName", "display_name", "vs_name", "pool_name", "se_name"],
            disallow_values=metric_names
        )

    return {"entity_uuid": entity_uuid, "metric_entity": metric_entity, "entity_name": entity_name}

def build_entity_display(meta: dict) -> str:
    name = meta.get("entity_name") or ""
    uuid = meta.get("entity_uuid") or ""
    etyp = meta.get("metric_entity") or ""
    parts = []
    if name:
        parts.append(str(name))
    if uuid:
        parts.append(f"({uuid})")
    if etyp:
        sep = " – " if (name or uuid) else ""
        parts.append(sep + etyp if sep else etyp)
    return " ".join(parts) if parts else "N/A"
# --------------------------------------------------------------------

def process_file(file_path: Path, args):
    logging.info(f"Processing file: {file_path}")
    data = load_json(file_path)
    if data is None:
        return

    series = data.get("series", [])
    if not isinstance(series, list):
        logging.warning(f"Series data in {file_path} is not a list. Skipping.")
        return

    # derive entity details (root → header → series headers)
    meta = extract_entity_meta(data, series)
    entity_display = build_entity_display(meta)

    df_list = [make_dataframe(s) for s in series]
    all_df = pd.concat(df_list, ignore_index=True) if df_list else pd.DataFrame()

    if all_df.empty:
        logging.error(f"No data found in {file_path}. Skipping report generation.")
        return

    all_df.dropna(subset=['time', 'value'], inplace=True)
    all_df.sort_values('time', inplace=True)

    # Plotly data structure for client-side plotting
    metrics_json = {}
    for metric_id, group in all_df.groupby('metric'):
        group = group.sort_values('time')
        time_converted = group['time'].dt.tz_convert(args.timezone).dt.strftime('%Y-%m-%d %H:%M:%S').tolist()
        metrics_json[metric_id] = {
            "metric": metric_id,
            "unit": group['units'].iloc[0] if not group.empty else "",
            "label": group['description'].iloc[0] if not group.empty else metric_id,
            "x": time_converted,
            "y": group['value'].tolist()
        }

    # Summary table
    stats_df = collect_stats(series)
    if not stats_df.empty:
        stats_df['min_ts'] = stats_df['min_ts'].apply(lambda x: _fmt_ts(x, args.timezone))
        stats_df['max_ts'] = stats_df['max_ts'].apply(lambda x: _fmt_ts(x, args.timezone))
        stats_df_html = stats_df.to_html(
            index=False, classes='metrics-table', na_rep="",
            float_format=lambda x: f"{x:,.2f}",
            formatters={
                'min': _human_number, 'max': _human_number,
                'mean': _human_number, 'sum': _human_number,
                'num_samples': '{:,}'.format
            }
        )
    else:
        stats_df_html = "<table><tr><td>No summary statistics available.</td></tr></table>"

    # Plotly JS
    if args.inline_js and _get_plotlyjs:
        logging.info("Embedding Plotly JS into HTML for offline use.")
        plotly_js = "<script>" + _get_plotlyjs() + "</script>"
    else:
        plotly_js = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'

    # Time window and meta-data
    start_time = all_df['time'].min().tz_convert(args.timezone).strftime('%Y-%m-%d %H:%M:%S')
    stop_time  = all_df['time'].max().tz_convert(args.timezone).strftime('%Y-%m-%d %H:%M:%S')

    # Median step (ignore zero deltas)
    if len(all_df) > 1:
        diffs = all_df['time'].diff().dropna()
        valid_diffs = diffs[diffs.dt.total_seconds() > 0]
        step_sec = valid_diffs.median().total_seconds() if not valid_diffs.empty else "N/A"
    else:
        step_sec = "N/A"

    replacements = {
        "title": args.title,
        "entity_display": entity_display,
        "start": start_time,
        "stop": stop_time,
        "step": f"{step_sec:.0f}" if isinstance(step_sec, (float, int)) else step_sec,
        "tz_label": args.timezone,
        "summary_table": stats_df_html,
        "metrics_json": json.dumps(metrics_json, indent=2),
        "plotly_js": plotly_js,
        "chart_height": args.chart_height,
        "interactive_columns": str(args.interactive_columns if not args.narrow else 2),
    }

    html_output = render_html(HTML_TEMPLATE, replacements)

    out_path = resolve_output_path(file_path, args.output, multi_inputs=(len(input_paths_global) > 1))
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            f.write(html_output)
        logging.info(f"Successfully wrote HTML report to {out_path}")
    except IOError as e:
        logging.error(f"Failed to write to file {out_path}: {e}")

def main():
    global input_paths_global
    args = parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='[%(levelname)s] %(message)s')

    input_paths_global = find_json_files(args.input)
    if not input_paths_global:
        logging.error("No valid JSON files found to process.")
        sys.exit(1)

    logging.info(f"Found {len(input_paths_global)} JSON file(s) to process.")

    for p in input_paths_global:
        process_file(p, args)

if __name__ == "__main__":
    main()
