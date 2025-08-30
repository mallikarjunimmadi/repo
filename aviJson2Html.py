#!/usr/bin/env python3
# json2html.py — JSON → interactive HTML graphs (Plotly)
#
# UI refresh:
# - Plot / Clear Charts / Reset Zoom restyled as pill chips (like tabs) with colors.
# - "Individual graphs" is now a pill-style toggle chip (keeps hidden checkbox for a11y).
# - All previous features retained: compact multi-select with Show Selected toggle,
#   grouped/individual charts, zoom sync, prompts, IST default YES, inline-JS default YES,
#   human-readable summary, input/output niceties.
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
    --interactive-cols: 1;
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

  /* Classic small buttons (kept for dropdown internal actions) */
  .btn { appearance:none; border:1px solid var(--border); background:#fff; padding:6px 10px; border-radius:8px; cursor:pointer; transition:all .15s ease; font-size:12px; }
  .btn:hover { background:#f3f4f6; }
  .btn-primary { background: var(--primary); border-color: var(--primary); color:#fff; }
  .btn-primary:hover { background: var(--primary-600); border-color: var(--primary-600); }

  /* New pill-style action buttons */
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
  .chip-toggle.active { background:#ecfdf5; border-color:#a7f3d0; color:#065f46; } /* green-ish when ON */
  .chip-toggle:hover { filter:brightness(0.98); }
  .sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }

  /* MultiSelect (unchanged) */
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

  .ms-footer { display:flex; justify-content:space-between; align-items:center; padding:8px; border-top:1px solid var(--border); font-size:12px; color:var(--muted); }
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
    <div><b>Entity:</b> ${entity_uuid} (${metric_entity})</div>
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
      <!-- Combobox MultiSelect -->
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
          <div class="ms-body" id="ms-body"><!-- groups/items injected --></div>
          <div class="ms-footer">
            <div><span class="ms-count" id="ms-count">0</span> selected</div>
            <div class="note">Legend shows metric IDs</div>
          </div>
        </div>
      </div>

      <!-- Action chip bar -->
      <div class="chip-bar">
        <button id="btn-plot" class="chip-btn chip-primary" type="button">Plot</button>
        <button id="btn-clear" class="chip-btn chip-warn" type="button">Clear Charts</button>
        <button id="btn-reset-range" class="chip-btn chip-muted" type="button">Reset Zoom</button>

        <!-- Toggle chip for Individual graphs -->
        <input type="checkbox" id="chk-individual" class="sr-only" aria-hidden="true"/>
        <button id="chip-individual" class="chip-toggle" type="button" aria-pressed="false" title="Toggle: Individual graphs">Individual graphs</button>
      </div>

      <div id="warn" class="warn"></div>
    </div>

    <div class="charts-wrap" id="interactive-panels"></div>
  </div>

<script>
// ---- Data ----
const METRICS_DATA = ${metrics_json};
const METRIC_NAMES = Object.keys(METRICS_DATA).sort((a,b)=> a.localeCompare(b));

// ---- Combobox MultiSelect (compact + Show Selected toggle) ----
const MS = (() => {
  const state = {
    open: false,
    groups: {},          // unit -> [metric]
    selected: new Set(), // metric ids
    showOnlySelected: false,
    els: {},
  };

  function qs(id){ return document.getElementById(id); }
  function esc(s){ return (s||"").replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }

  function buildGroups() {
    state.groups = {};
    for (const name of METRIC_NAMES) {
      const m = METRICS_DATA[name];
      const unit = m.unit || "UNKNOWN";
      (state.groups[unit] ||= []).push(name);
    }
    for (const u of Object.keys(state.groups)) state.groups[u].sort((a,b)=>a.localeCompare(b));
  }

  function renderList(filter="") {
    const body = state.els.body;
    body.innerHTML = "";
    const f = filter.trim().toLowerCase();

    for (const unit of Object.keys(state.groups).sort((a,b)=>a.localeCompare(b))) {
      let base = state.groups[unit];
      if (state.showOnlySelected) base = base.filter(n => state.selected.has(n));

      const names = base.filter(n=>{
        if (!f) return true;
        const m = METRICS_DATA[n];
        const hay = (n + " " + (m.label||"") + " " + unit).toLowerCase();
        return hay.includes(f);
      });

      if (!names.length) continue;

      const g = document.createElement('div'); g.className = 'ms-group';
      const gt = document.createElement('div'); gt.className = 'ms-group-title'; gt.textContent = unit;
      g.appendChild(gt);

      for (const name of names) {
        const m = METRICS_DATA[name];

        const row = document.createElement('label'); row.className = 'ms-item';
        const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = state.selected.has(name); cb.setAttribute('data-name', name);
        const textWrap = document.createElement('span'); textWrap.className = 'ms-text';
        textWrap.innerHTML = "<div><b>"+esc(name)+"</b></div><div class='sub'>"+esc(m.label||m.metric)+"</div>";
        row.appendChild(cb); row.appendChild(textWrap);

        cb.addEventListener('change', (e)=>{
          e.stopPropagation();
          toggle(name, cb.checked);
          if (state.showOnlySelected) renderList(state.els.search.value);
        });

        g.appendChild(row);
      }
      body.appendChild(g);
    }
    adjustPanelPositionAndSize();
  }

  function renderTagsAndCounter() {
    const tags = state.els.tags;
    const placeholder = state.els.placeholder;
    const counter = state.els.counter;

    tags.innerHTML = "";
    const arr = Array.from(state.selected).sort((a,b)=> a.localeCompare(b));

    if (!state.selected.size) {
      tags.style.display = "none";
      counter.style.display = "none";
      placeholder.style.display = "";
      return;
    }
    placeholder.style.display = "none";
    tags.style.display = "flex";

    const SHOW = 3;
    const showArr = arr.slice(0, SHOW);
    for (const name of showArr) {
      const t = document.createElement('span'); t.className = 'ms-tag';
      t.innerHTML = "<span>"+esc(name)+"</span>";
      const x = document.createElement('button'); x.type="button"; x.innerHTML = "&times;";
      x.addEventListener('click', (e)=>{
        e.stopPropagation();
        state.selected.delete(name);
        syncChecks();
        renderTagsAndCounter();
        updateCount();
        if (state.showOnlySelected) renderList(state.els.search.value);
      });
      t.appendChild(x);
      tags.appendChild(t);
    }

    counter.textContent = `${state.selected.size} selected`;
    counter.style.display = "";
  }

  function updateCount(){ state.els.count.textContent = state.selected.size; }

  function syncChecks() {
    const boxes = state.els.body.querySelectorAll('input[type="checkbox"][data-name]');
    boxes.forEach(cb => { cb.checked = state.selected.has(cb.getAttribute('data-name')); });
  }

  function toggle(name, val) {
    if (val) state.selected.add(name); else state.selected.delete(name);
    renderTagsAndCounter(); updateCount(); updateShowButtonState();
  }

  function selectAll() {
    for (const n of METRIC_NAMES) state.selected.add(n);
    syncChecks(); renderTagsAndCounter(); updateCount(); updateShowButtonState();
    if (state.showOnlySelected) renderList(state.els.search.value);
  }
  function clearAll() {
    state.selected.clear(); syncChecks(); renderTagsAndCounter(); updateCount(); updateShowButtonState();
    if (state.showOnlySelected) renderList(state.els.search.value);
  }

  function open() {
    if (state.open) return;
    state.open = true;
    state.els.root.classList.add('open');
    state.els.toggle.setAttribute('aria-expanded','true');
    renderList(state.els.search.value);
    syncChecks();
    setTimeout(()=> state.els.search.focus(), 0);
  }
  function close() {
    if (!state.open) return;
    state.open = false;
    state.els.root.classList.remove('open');
    state.els.toggle.setAttribute('aria-expanded','false');
  }
  function toggleOpen(){ state.open ? close() : open(); }

  function adjustPanelPositionAndSize() {
    const panel = state.els.panel;
    if (!panel) return;
    panel.classList.remove('up','down');

    const rootRect = state.els.root.getBoundingClientRect();
    const viewportH = window.innerHeight || document.documentElement.clientHeight;

    const spaceBelow = viewportH - rootRect.bottom - 12;
    const spaceAbove = rootRect.top - 12;

    const HEADER_FOOTER = 92;

    if (spaceBelow >= 220 || spaceBelow >= spaceAbove) {
      panel.classList.add('down');
      const maxH = Math.max(180, Math.min(420, spaceBelow));
      panel.style.maxHeight = (maxH) + "px";
      const bodyMax = Math.max(120, maxH - HEADER_FOOTER);
      state.els.body.style.maxHeight = bodyMax + "px";
    } else {
      panel.classList.add('up');
      const maxH = Math.max(180, Math.min(420, spaceAbove));
      panel.style.maxHeight = (maxH) + "px";
      const bodyMax = Math.max(120, maxH - HEADER_FOOTER);
      state.els.body.style.maxHeight = bodyMax + "px";
    }
  }

  function updateShowButtonState(){
    const btn = qs('ms-show');
    if (!btn) return;
    btn.disabled = state.showOnlySelected ? false : (state.selected.size === 0);
    btn.textContent = state.showOnlySelected ? "Show All" : "Show Selected";
  }

  function setupDOM() {
    state.els.root = qs('ms');
    state.els.toggle = qs('ms-toggle');
    state.els.panel = qs('ms-panel');
    state.els.placeholder = qs('ms-placeholder');
    state.els.tags = qs('ms-tags');
    state.els.counter = qs('ms-counter');
    state.els.body = qs('ms-body');
    state.els.count = qs('ms-count');
    state.els.search = qs('ms-search');

    state.els.toggle.addEventListener('click', (e)=> { e.stopPropagation(); toggleOpen(); });
    document.addEventListener('click', (e)=>{
      if (!state.els.root.contains(e.target)) close();
    });

    qs('ms-select-all').addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); selectAll(); });
    qs('ms-clear').addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); clearAll(); });

    const btnShow = qs('ms-show');
    btnShow.addEventListener('click', (e)=>{
      e.preventDefault(); e.stopPropagation();
      if (!state.showOnlySelected) {
        if (state.selected.size === 0) return;
        state.showOnlySelected = true;
      } else {
        state.showOnlySelected = false;
      }
      renderList(state.els.search.value);
      updateShowButtonState();
    });

    state.els.search.addEventListener('input', ()=> renderList(state.els.search.value));
    window.addEventListener('resize', ()=> { if (state.open) adjustPanelPositionAndSize(); });
    window.addEventListener('scroll', ()=> { if (state.open) adjustPanelPositionAndSize(); }, true);
  }

  function init() {
    setupDOM();
    buildGroups();
    renderTagsAndCounter(); updateCount(); updateShowButtonState();
  }

  function getSelected(){ return Array.from(state.selected); }

  return { init, getSelected, selectAll, clear: clearAll, open, close };
})();

// ---- Plot helpers ----
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

// ---- Boot ----
(function init(){
  // Tabs
  const tabs=document.querySelectorAll('.tab-btn'); const panels=document.querySelectorAll('.panel');
  function activate(id){ tabs.forEach(t=>t.classList.toggle('active',t.dataset.target===id)); panels.forEach(p=>p.classList.toggle('active',p.id===id)); }
  tabs.forEach(t=>t.addEventListener('click',()=>activate(t.dataset.target)));
  if(tabs.length) activate(tabs[0].dataset.target);

  // MultiSelect
  MS.init();

  // Action chips
  document.getElementById('btn-plot')?.addEventListener('click', renderInteractive);
  document.getElementById('btn-clear')?.addEventListener('click', ()=>{ document.getElementById('interactive-panels').innerHTML=''; showWarn(''); });
  document.getElementById('btn-reset-range')?.addEventListener('click', ()=>{
    document.querySelectorAll('#interactive-panels .chart-card > div[id^="chart"]').forEach(div=>{
      Plotly.relayout(div.id, {'xaxis.autorange': true});
    });
  });

  // Toggle chip for "Individual graphs"
  const chk = document.getElementById('chk-individual');
  const chip = document.getElementById('chip-individual');
  function syncChip(){
    const on = !!chk.checked;
    chip.classList.toggle('active', on);
    chip.setAttribute('aria-pressed', on ? 'true' : 'false');
  }
  chip.addEventListener('click', ()=>{
    chk.checked = !chk.checked;
    syncChip();
    // auto-render if there are selections
    const selectedCount = (typeof MS.getSelected === 'function') ? MS.getSelected().length : 0;
    if (selectedCount > 0) renderInteractive();
  });
  // for completeness if someone toggles via keyboard focus to hidden checkbox
  chk.addEventListener('change', ()=>{ syncChip(); const n = MS.getSelected().length; if (n>0) renderInteractive(); });
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
      description="Convert metrics JSON → interactive HTML (Summary + Interactive Select). Wide plots by default; zoom/pan sync.",
      formatter_class=argparse.RawTextHelpFormatter, add_help=True,
  )
  p.add_argument("-i","--input", help="Input JSON file path ('.json' optional).")
  p.add_argument("-o","--output", help="Output HTML file path (optional). If blank, uses <input_stem>.html")
  p.add_argument("--title", help='Page title (default: "Metrics Report").')
  p.add_argument("--inline-js", action="store_true", help="Embed Plotly JS inline (offline HTML).")
  p.add_argument("--ist", action="store_true", help="Use Asia/Kolkata timestamps.")
  # hidden opts
  p.add_argument("--chart-height", type=int, default=520, help=argparse.SUPPRESS)
  p.add_argument("--interactive-columns", type=int, default=1, help=argparse.SUPPRESS)
  p.add_argument("--narrow", action="store_true", help=argparse.SUPPRESS)
  p.add_argument("--timezone","--tz", dest="timezone", default=None, help=argparse.SUPPRESS)
  p.add_argument("-v","--verbose", action="store_true", help="Verbose logging.")
  args = p.parse_args()

  if not args.input:
      args.input = prompt_str("Enter input JSON file path")
  if args.output is None:
      args.output = prompt_str("Output HTML file name/path (optional)", "")
  if not args.title:
      args.title = prompt_str("Title (optional)", "Metrics Report")

  if "--ist" not in sys.argv:
      args.ist = prompt_yes_no("Render times in IST (Asia/Kolkata)?", default_yes=True)
  if "--inline-js" not in sys.argv:
      args.inline_js = prompt_yes_no("Embed Plotly JS in the HTML (works fully offline)?", default_yes=True)

  args.timezone = "Asia/Kolkata" if args.ist else "UTC"
  return args

def resolve_input_path(raw: str) -> Path:
  p = Path(raw).expanduser()
  if p.exists(): return p.resolve()
  if p.suffix.lower() != ".json":
      p_json = p.with_suffix(".json")
      if p_json.exists(): return p_json.resolve()
  return p.resolve()

def _ensure_html_suffix(p: Path) -> Path:
  suf = p.suffix.lower()
  if suf in (".html",".htm"): return p
  return p.with_suffix(".html")

def resolve_output_path(input_path: Path, raw_out: str | None) -> Path:
  if not raw_out:
      out = input_path.with_suffix(".html")
  else:
      p = Path(raw_out).expanduser()
      if p.parent == Path(""): p = Path.cwd() / p.name
      p = _ensure_html_suffix(p)
      out = p
  return out.resolve()

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
  if pd.isna(x): return ""
  try: x = float(x)
  except Exception: return str(x)
  neg = x < 0; x = abs(x)
  for unit,th in [("T",1e12),("B",1e9),("M",1e6),("K",1e3)]:
      if x >= th:
          val = x / th
          s = f"{val:,.2f}".rstrip("0").rstrip(".") + unit
          return "-" + s if neg else s
  if x != int(x): s = f"{x:,.6f}".rstrip("0").rstrip(".")
  else: s = f"{int(x):,d}"
  return "-" + s if neg else s

def _fmt_ts(ts_str: str, tz_name: str) -> str:
  if not ts_str: return ""
  try:
      t = pd.to_datetime(ts_str, utc=True, errors="coerce")
      if pd.isna(t): return str(ts_str)
      t = t.tz_convert(tz_name)
      return t.strftime("%Y-%m-%d %H:%M:%S %Z")
  except Exception:
      return str(ts_str)

def dataframe_to_html_table(df: pd.DataFrame, tz_name: str) -> str:
  if df.empty:
      return "<p class='note'>No statistics available.</p>"
  df2 = df.copy()
  for c in ["mean","min","max","sum","trend","num_samples"]:
      if c in df2.columns: df2[c] = df2[c].apply(_human_number)
  for c in ["min_ts","max_ts"]:
      if c in df2.columns: df2[c] = df2[c].apply(lambda s: _fmt_ts(s, tz_name))
  cols = ["metric","units","description","mean","min","min_ts","max","max_ts","sum","trend","num_samples"]
  cols = [c for c in cols if c in df2.columns]
  return df2[cols].to_html(index=False, classes="stats", border=0, escape=False)

def to_label(metric: str, description: str):
  return description or metric

def build_metrics_json_for_js(df_all: pd.DataFrame, tz_name: str) -> str:
  store = {}
  if df_all.empty: return json.dumps(store)
  for metric, dfx in df_all.groupby("metric", sort=True):
      dfx = dfx.sort_values("time")
      times=[]
      for t in dfx["time"]:
        if pd.isna(t): times.append(None)
        else:
          tt = pd.Timestamp(t).tz_convert(tz_name)
          times.append(tt.isoformat())
      store[metric] = {
          "metric": metric,
          "unit": dfx["units"].iloc[0],
          "label": to_label(metric, dfx["description"].iloc[0] if not dfx.empty else metric),
          "x": times,
          "y": [None if pd.isna(v) else float(v) for v in dfx["value"]],
      }
  return json.dumps(store, ensure_ascii=False)

def main():
  args = parse_args()
  logging.basicConfig(level=(logging.DEBUG if args.verbose else logging.INFO), format="[%(levelname)s] %(message)s")

  in_raw = args.input
  in_path = resolve_input_path(in_raw)
  if not in_path.exists():
      logging.error("Input file not found: %s\nHint: If your file is named '%s.json', you can pass '%s' (without .json) or the full name.",
                    in_raw, Path(in_raw).name, in_raw)
      raise SystemExit(2)

  out_path = resolve_output_path(in_path, (args.output or "").strip())

  tz_name = "Asia/Kolkata" if args.ist else "UTC"
  tz_label = "IST" if tz_name == "Asia/Kolkata" else tz_name

  logging.info("Reading: %s", in_path)
  data = load_json(in_path)

  start_raw = data.get("start", ""); stop_raw = data.get("stop", "")
  start_disp = _fmt_ts(start_raw, tz_name) if start_raw else ""
  stop_disp  = _fmt_ts(stop_raw, tz_name) if stop_raw else ""
  step  = data.get("step", "")
  entity_uuid = data.get("entity_uuid", ""); metric_entity = data.get("metric_entity", "")
  series_list = data.get("series", []) or []

  frames = [make_dataframe(s) for s in series_list]
  df_all = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=["time","value","metric","units","description"])

  stats_df = collect_stats(series_list)
  stats_html = dataframe_to_html_table(stats_df, tz_name)

  if args.inline_js:
      try:
          from plotly.offline import get_plotlyjs
          plotly_js = f"<script>{get_plotlyjs()}</script>"
      except Exception:
          logging.warning("Failed to inline Plotly JS; falling back to CDN.")
          plotly_js = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'
  else:
      plotly_js = '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>'

  metrics_json = build_metrics_json_for_js(df_all, tz_name)

  html = render_html(HTML_TEMPLATE, {
      "title": args.title or "Metrics Report",
      "plotly_js": plotly_js,
      "entity_uuid": entity_uuid,
      "metric_entity": metric_entity,
      "start": start_disp, "stop": stop_disp, "step": (step if step is not None else ""),
      "summary_table": stats_html, "metrics_json": metrics_json, "tz_label": tz_label,
      "chart_height": args.chart_height,
  })

  logging.info("Writing HTML: %s", out_path)
  out_path.parent.mkdir(parents=True, exist_ok=True)
  out_path.write_text(html, encoding="utf-8")
  logging.info("Done. Open %s in your browser.", out_path)

if __name__ == "__main__":
  main()
