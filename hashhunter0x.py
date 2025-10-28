#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HashHunter0x - fast MD5 lookups against massive IOC hash sets

CLI (5 key commands)
====================
  update  -> downloads and ingests IOC (MB and/or VS)
  build   -> builds sorted binaries, prefix indexes, and bloom filters
  scan    -> compares your hashes against the sources
  check   -> single hash lookup
  status  -> dataset/index status summary

Recommended workflow
--------------------
1. Prepare data
   - `hashhunter update --all` syncs MalwareBazaar and VirusShare.
   - Alternative: `hashhunter update --mb` or `hashhunter update --vs` for a specific source.
2. Build indexes
   - `hashhunter build --all` generates the bin, idx, and bloom files.
   - Alternative: use `--mb`, `--vs`, or `--custom` for selected sources.
3. Run analysis
   - `hashhunter scan hashes.txt`
   - Options: add `--html report.html`, `--json output.jsonl`.
4. Ad-hoc lookups
   - `hashhunter check <md5>` validates a single hash across the chosen sources.
5. Review status
   - `hashhunter status` shows a summary of datasets and indexes available.

Notes
-----
- By default it works in the current directory (IOC/, data/, output/).
- No external dependencies: only the Python standard library. Uses mmap, external sorting, and a persistent bloom filter.
"""

from __future__ import annotations

import argparse
import binascii
import csv
import datetime as dt
import gzip
import io
import json
import math
import mmap
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse
import zipfile
import http.cookiejar
from typing import Iterable, Iterator, List, Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================
# Constants & utilities
# ==========================
APP = "HashHunter0x"
VERSION = "0.1.0"

MB_URL = "https://bazaar.abuse.ch/export/txt/md5/full/"
MB_FILENAME = "mb_md5_full.txt"
VS_HASHES_URL = "https://virusshare.com/hashes"
VS_LINK_RE = re.compile(
    r'href=["\'](?P<href>[^"\']*VirusShare_[0-9]{5}\.(?:md5(?:\.txt)?|txt|zip))["\']',
    re.IGNORECASE,
)
CUSTOM_DIRNAME = "custom"

SOURCE_ORDER = ["mb", "vs", "custom"]
SOURCE_LABELS = {
    "mb": "MalwareBazaar",
    "vs": "VirusShare",
    "custom": "Custom",
}

UPLOAD_BANNER = r"""
  _               _     _                 _             ___       
 | |             | |   | |               | |           / _ \      
 | |__   __ _ ___| |__ | |__  _   _ _ __ | |_ ___ _ __| | | |_  __
 | '_ \ / _` / __| '_ \| '_ \| | | | '_ \| __/ _ \ '__| | | \ \/ /
 | | | | (_| \__ \ | | | | | | |_| | | | | ||  __/ |  | |_| |>  < 
 |_| |_|\__,_|___/_| |_|_| |_|\__,_|_| |_|\__\___|_|   \___//_/\_\
                                                                  
                                                                    
                 HashHunter0x :: by corvus0X
"""

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>HashHunter0x - Scan Report</title>
  <style>
    :root{
      --bg:#0e1013; --panel:#161a22; --panel-2:#1f2530; --panel-3:#0b0d11;
      --fg:#e8f1ff; --muted:#9da5b4; --brand:#66d9ef; --ok:#a6e22e; --err:#f92672; --warn:#f4bf75;
      --border: #232a34; --accent:#8be9fd; --shadow:0 8px 24px rgba(0,0,0,.25);
      --pill-bg:#0f141c; --pill-border:#2a3342;
      --link:#9ae7ff; --link-h:#a6e22e;
    }
    [data-theme="light"]{
      --bg:#f7f9fc; --panel:#ffffff; --panel-2:#f0f4fb; --panel-3:#e9eef7;
      --fg:#111827; --muted:#4b5563; --brand:#2563eb; --ok:#16a34a; --err:#dc2626; --warn:#eab308;
      --border:#e5e7eb; --accent:#60a5fa; --shadow:0 8px 24px rgba(0,0,0,.12);
      --pill-bg:#f3f4f6; --pill-border:#e5e7eb;
      --link:#2563eb; --link-h:#0ea5e9;
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{margin:0;font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--fg)}
    a{color:var(--link);text-decoration:none}
    a:hover{color:var(--link-h)}

    .container{max-width:1200px;margin:0 auto;padding:24px}
    header{position:sticky;top:0;z-index:10;background:linear-gradient(180deg,var(--bg) 70%,transparent);backdrop-filter:saturate(1.2) blur(2px);}
    .toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:flex-start;padding:12px 0;border-bottom:1px solid var(--border)}
    h1{
      color:#444;
      text-align:center;
      margin:20px 0 10px;
      font-size:2.4rem;
      font-weight:900;
      letter-spacing:.025em;
    }
    h1::after{
      content:"";
      display:block;
      width:64px;
      margin:12px auto 0;
      border-bottom:3px solid #444;
    }
    .meta{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:.92rem;min-height:0}

    .controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
    .controls input[type="text"]{
      background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:10px;
      padding:12px 14px;font-size:1rem;
      width:clamp(320px,48vw,640px); /* larger input */
    }
    .btn, select{
      background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:10px;padding:8px 12px;font-size:.9rem
    }
    .btn{cursor:pointer}
    .btn.ghost{background:var(--panel-3)}
    .btn.theme-toggle{display:inline-flex;align-items:center;gap:6px}
    .btn.vt{padding:5px 10px;font-size:.8rem;border-radius:8px;letter-spacing:.02em;text-transform:uppercase;font-weight:600}
    .switch{display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid var(--border);border-radius:10px;background:var(--panel)}
    .switch input{accent-color:var(--brand)}

    .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}
    @media(max-width:900px){.kpis{grid-template-columns:repeat(2,1fr)}}
    @media(max-width:560px){.kpis{grid-template-columns:1fr}}
    .kpi{background:var(--panel-2);border:1px solid var(--border);border-radius:14px;padding:14px;box-shadow:var(--shadow)}
    .kpi .label{color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-size:.8rem}
    .kpi .value{font-size:1.6rem;font-weight:800;margin-top:6px}
    .kpi .ok{color:var(--ok)} .kpi .err{color:var(--err)} .kpi .warn{color:var(--warn)}

    .panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow)}
    .panel .panel-h{display:flex;gap:8px;align-items:center;justify-content:space-between;padding:12px;border-bottom:1px solid var(--border)}
    .panel .panel-b{padding:12px}

    table{width:100%;border-collapse:separate;border-spacing:0}
    thead th{position:sticky;top:64px;background:var(--panel);border-bottom:1px solid var(--border);text-align:left;padding:10px 12px;font-size:.9rem;color:var(--muted);cursor:pointer}
    tbody td{border-bottom:1px solid var(--border);padding:10px 12px;font-size:.95rem}
    tbody td.alias{max-width:280px;white-space:normal;word-break:break-word;overflow-wrap:anywhere}
    tbody tr:hover{background:rgba(255,255,255,.025)}
    code{background:var(--pill-bg);border:1px solid var(--pill-border);padding:3px 6px;border-radius:8px}

    .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid var(--pill-border);background:var(--pill-bg);font-weight:600;font-size:.78rem}
    .pill.hit{background:rgba(249,38,114,.18);border-color:rgba(249,38,114,.5);color:var(--err);text-transform:uppercase;letter-spacing:.04em}
    .pill.miss{color:var(--muted)}

    .hidden{display:none!important}

    /* Print */
    @media print{
      header{position:static}
      .controls,.toolbar .btn,.toolbar .switch{display:none!important}
      thead th{top:auto}
      .container{padding:0}
      body{background:white;color:black}
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>HashHunter0x - Scan Report</h1>
      <div class="toolbar">
        <div class="controls">
          <input id="q" type="text" placeholder="Search hash or alias..." />
          <label class="switch" title="Only positives">
            <input id="onlyPos" type="checkbox" />
            <span>Only positives</span>
          </label>
          <label class="switch" title="MalwareBazaar source">
            <input id="fMB" type="checkbox" checked />
            <span>MB</span>
          </label>
          <label class="switch" title="VirusShare source">
            <input id="fVS" type="checkbox" checked />
            <span>VS</span>
          </label>
          <label class="switch" title="Custom source">
            <input id="fCU" type="checkbox" checked />
            <span>Custom</span>
          </label>
          <select id="pageSize">
            <option value="all">All</option>
            <option value="100" selected>100</option>
            <option value="500">500</option>
            <option value="1000">1000</option>
          </select>
          <button class="btn ghost" id="copyPos" type="button">Copy positives</button>
          <button class="btn ghost theme-toggle" id="themeToggle" type="button" title="Toggle theme">Toggle theme</button>
        </div>
      </div>
      <div class="meta" id="meta"></div>
    </header>

    <section class="kpis">
      <div class="kpi">
        <div class="label">Hashes in dataset</div>
        <div class="value" id="kDataset">-</div>
      </div>
      <div class="kpi">
        <div class="label">Analyzed hashes</div>
        <div class="value" id="kScanned">-</div>
      </div>
      <div class="kpi">
        <div class="label">Positive hashes</div>
        <div class="value" id="kPositive">-</div>
      </div>
      <div class="kpi">
        <div class="label">Processed files</div>
        <div class="value" id="kFiles">-</div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-h">
        <strong>Results</strong>
        <span class="muted" id="summary"></span>
      </div>
      <div class="panel-b">
        <div class="table-wrapper">
          <table id="tbl">
            <thead>
              <tr>
                <th data-key="#">#</th>
                <th data-key="hash">Hash</th>
                <th data-key="alias">Alias</th>
                <th data-key="mb">MalwareBazaar</th>
                <th data-key="vs">VirusShare</th>
                <th data-key="custom">Custom</th>
                <th data-key="vt">VirusTotal</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
      </div>
    </section>
  </div>

  <!-- Payload JSON (injected by the generator) -->
  <script id="hhx_payload" type="application/json">
__PAYLOAD__
  </script>

  <script>
    (function(){
      const $ = (sel)=>document.querySelector(sel);
      const $$ = (sel)=>document.querySelectorAll(sel);
      const st = {
        data: {meta:{}, rows:[]},
        pageSize: 100, // show 100 rows by default
        sortKey: 'priority',
        sortDir: 'desc',
        filters: { q:'', onlyPos:false, mb:true, vs:true, custom:true },
        theme: 'dark'
      };
      const pageSizeSelect = $('#pageSize');

      function applyTheme(t){
        st.theme = (t === 'light') ? 'light' : 'dark';
        if(st.theme === 'light'){
          document.documentElement.setAttribute('data-theme','light');
        }else{
          document.documentElement.removeAttribute('data-theme');
        }
      }

      // Theme toggle
      const themeToggle = document.getElementById('themeToggle');
      const storedTheme = localStorage.getItem('hhx_theme');
      if(storedTheme){ applyTheme(storedTheme); }

      const updateThemeToggle = ()=>{
        if(!themeToggle) return;
        themeToggle.textContent = st.theme === 'dark' ? 'Light theme' : 'Dark theme';
      };

      updateThemeToggle();

      if(themeToggle){
        themeToggle.addEventListener('click', ()=>{
          const next = st.theme === 'dark' ? 'light' : 'dark';
          applyTheme(next);
          localStorage.setItem('hhx_theme', next);
          updateThemeToggle();
        });
      }

      // Hotkeys
      document.addEventListener('keydown', (e)=>{
        if(e.key==='/' && !e.ctrlKey){ $('#q').focus(); e.preventDefault(); }
        if(e.ctrlKey && e.key==='/'){ $('#q').focus(); e.preventDefault(); }
      });

      // Load payload
      try{
        const payload = JSON.parse($('#hhx_payload').textContent||'{}');
        st.data = payload;
      }catch(e){ console.error('Invalid payload', e); }

      // Controls
      $('#q').addEventListener('input', e=>{ st.filters.q = e.target.value.toLowerCase(); render(); });
      $('#onlyPos').addEventListener('change', e=>{ st.filters.onlyPos = e.target.checked; render(); });
      $('#fMB').addEventListener('change', e=>{ st.filters.mb = e.target.checked; render(); });
      $('#fVS').addEventListener('change', e=>{ st.filters.vs = e.target.checked; render(); });
      $('#fCU').addEventListener('change', e=>{ st.filters.custom = e.target.checked; render(); });
      const syncPageSizeControl = ()=>{
        if(!pageSizeSelect) return;
        pageSizeSelect.value = st.pageSize === Number.MAX_SAFE_INTEGER ? 'all' : String(st.pageSize);
      };
      if(pageSizeSelect){
        syncPageSizeControl();
        pageSizeSelect.addEventListener('change', e=>{
          const v = e.target.value;
          st.pageSize = (v === 'all') ? Number.MAX_SAFE_INTEGER : (parseInt(v,10)||Number.MAX_SAFE_INTEGER);
          syncPageSizeControl();
          render();
        });
      }
      $('#copyPos').addEventListener('click', copyPositives);

      // Sort
      $$('#tbl thead th').forEach(th=>{
        th.addEventListener('click',()=>{
          const key=th.dataset.key; if(!key) return;
          if(st.sortKey===key){ st.sortDir = st.sortDir==='asc'?'desc':'asc'; } else { st.sortKey=key; st.sortDir='asc'; }
          render();
        });
      });

      function vtLink(h){ return `https://www.virustotal.com/gui/search/${h}` }

      function setMeta(filteredRows){
        const m = st.data.meta||{};
        // Hidden meta line (no text):
        $('#meta').textContent = '';
        $('#kDataset').textContent = (m.dataset_total ?? '-') .toLocaleString?.() || m.dataset_total || '-';
        $('#kScanned').textContent = (m.scanned ?? st.data.rows.length).toLocaleString();
        $('#kPositive').textContent = countPositives(filteredRows).toLocaleString();
        $('#kFiles').textContent = (m.files_processed ?? 0).toLocaleString();
      }

      function filterRows(){
        const q = st.filters.q; const only = st.filters.onlyPos; const f = st.filters;
        return (st.data.rows||[]).filter(r=>{
          const hit = (f.mb && r.mb) || (f.vs && r.vs) || (f.custom && r.custom);
          if(only && !hit) return false;
          if(q){
            const hay = (r.hash||'') + ' ' + (r.alias||'');
            if(hay.toLowerCase().indexOf(q)===-1) return false;
          }
          return true;
        });
      }

      function countPositives(rows){
        let c=0; for(const r of rows){ if(r.mb||r.vs||r.custom) c++; } return c;
      }

      function sortRows(rows){
        const key = st.sortKey; const dir = st.sortDir==='asc'?1:-1;
        return rows.slice().sort((a,b)=>{
          const va = key==='#'?0: (a[key]??'');
          const vb = key==='#'?0: (b[key]??'');
          if(typeof va === 'boolean' && typeof vb === 'boolean') return (va===vb?0:(va?1:-1))*dir;
          return String(va).localeCompare(String(vb))*dir;
        });
      }

      function renderTable(filteredRows){
        const body = $('#rows');
        body.innerHTML='';
        const sorted = sortRows(filteredRows);
        const visible = st.pageSize === Number.MAX_SAFE_INTEGER ? sorted : sorted.slice(0, st.pageSize);
        for(let i=0;i<visible.length;i++){
          const r = visible[i];
          const positive = (typeof r.hit === 'boolean') ? r.hit : !!(r.mb || r.vs || r.custom);
          const tr = document.createElement('tr');
          const idx = document.createElement('td'); idx.textContent = (i+1).toString(); tr.appendChild(idx);

          const tdHash = document.createElement('td'); tdHash.innerHTML = `<code>${r.hash}</code>`; tr.appendChild(tdHash);
          const tdAlias = document.createElement('td'); tdAlias.className = 'alias'; tdAlias.textContent = r.alias||'-'; tr.appendChild(tdAlias);
          const c = (v)=>`<span class="pill ${v?'hit':'miss'}">${v?'Yes':'No'}</span>`;
          const tdMB = document.createElement('td'); tdMB.innerHTML = c(!!r.mb); tr.appendChild(tdMB);
          const tdVS = document.createElement('td'); tdVS.innerHTML = c(!!r.vs); tr.appendChild(tdVS);
          const tdCU = document.createElement('td'); tdCU.innerHTML = c(!!r.custom); tr.appendChild(tdCU);
          const tdVT = document.createElement('td'); tdVT.innerHTML = `<a class="btn ghost vt" target="_blank" rel="noopener" href="${vtLink(r.hash)}">Open</a>`; tr.appendChild(tdVT);

          body.appendChild(tr);
        }
      }

      function copyPositives(){
        const rows = filterRows().filter(r=>r.mb||r.vs||r.custom);
        const txt = rows.map(r=>r.hash).join('\\n');
        navigator.clipboard.writeText(txt).then(()=>{ toast('Copied list of positives'); });
      }

      function toast(msg){
        const n = document.createElement('div'); n.textContent=msg; n.style.cssText='position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:var(--panel-2);color:var(--fg);padding:10px 14px;border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow);z-index:9999';
        document.body.appendChild(n); setTimeout(()=>n.remove(), 1800);
      }

      function render(){
        const filteredRows = filterRows();
        setMeta(filteredRows);
        renderTable(filteredRows);
      }

      render();
    })();
  </script>
</body>
</html>
"""

def render_html_report(path: Path, meta: Dict[str, Any], rows: List[Dict[str, Any]]) -> None:
    payload = {"meta": meta, "rows": rows}
    payload_json = json.dumps(payload, ensure_ascii=False, indent=2)
    content = HTML_REPORT_TEMPLATE.replace("__PAYLOAD__", payload_json)
    path.write_text(content, encoding="utf-8")


def count_dataset_files(paths: Paths, sources: List[str]) -> int:
    mapping = {
        "mb": paths.ioc_mb,
        "vs": paths.ioc_vs,
        "custom": paths.ioc_custom,
    }
    total = 0
    for src in sources:
        base = mapping.get(src)
        if not base or not base.exists():
            continue
        for entry in base.rglob("*"):
            if entry.is_file():
                total += 1
    return total

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
RECORD_SIZE = 16  # 16 bytes per MD5
PREFIX_BYTES = 2  # index by 2 bytes = 65,536 buckets
INDEX_ENTRIES = (1 << (PREFIX_BYTES * 8))  # 65,536

# Bloom header: magic, m_bits, k, n, reserved
BLOOM_HDR_STRUCT = struct.Struct(">8sQIQ16s")
BLOOM_MAGIC = b"HHBLOOM\x01"

DEFAULT_FP_RATE = 1e-3
DEFAULT_THREADS = 6
DEFAULT_CHUNK_RECS = 8_000_000  # 8M records per chunk (external sort)
VS_DOWNLOAD_THREADS = 4  # parallel downloads for VirusShare

ANSI_RESET = "\033[0m"
LOG_COLORS = {
    "INFO": "\033[36m",
    "RUN": "\033[35m",
    "WARN": "\033[33m",
    "ERROR": "\033[31m",
    "SUCCESS": "\033[32m",
    "COUNTS": "\033[94m",
    "RESULTS": "\033[92m",
    "ALERT": "\033[91m",
}
USE_COLORS = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
if USE_COLORS and os.name == "nt":
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE = -11
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        USE_COLORS = False

# ==========================
# Basic helpers
# ==========================

def log(msg: str, level: str = "INFO", quiet: bool = False):
    if quiet:
        return
    text = msg
    lvl = level.upper()
    if level.upper() == "INFO" and msg.startswith("["):
        match = re.match(r"^\[([^\]]+)\]\s*(.*)$", msg)
        if match:
            lvl = match.group(1).strip().upper()
            text = match.group(2)
    line = f"[{lvl}] {text}" if text else f"[{lvl}]"
    if USE_COLORS:
        color = LOG_COLORS.get(lvl)
        if color:
            if lvl == "SUCCESS":
                print(f"{color}{line}{ANSI_RESET}")
            else:
                prefix_colored = f"{color}[{lvl}]{ANSI_RESET}"
                if text:
                    print(f"{prefix_colored} {text}")
                else:
                    print(prefix_colored)
            return
    print(line)

def ensure_dirs(*paths: Path):
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)


def is_valid_md5(s: str) -> bool:
    return bool(MD5_RE.match(s))


def md5hex_to_bytes(s: str) -> bytes:
    # Assumes prior validation
    return binascii.unhexlify(s.strip().lower().encode("ascii"))


def bytes_to_md5hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sizeof_fmt(num: int, suffix="B") -> str:
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Y{suffix}"

# ==========================
# Default paths
# ==========================
class Paths:
    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.ioc = workdir / "IOC"
        self.ioc_mb = self.ioc / "MalwareBazaar"
        self.ioc_vs = self.ioc / "VirusShare"
        self.ioc_custom = self.ioc / CUSTOM_DIRNAME
        self.data = workdir / "data"
        self.output = workdir / "output"
        self.cache = workdir / "cache"
        ensure_dirs(
            self.ioc_mb,
            self.ioc_vs,
            self.ioc_custom,
            self.data,
            self.output,
            self.cache,
        )

    # Bin/idx/bf filenames per source
    def bin_path(self, source: str) -> Path:
        return self.data / f"hashset.{source}.bin"

    def idx_path(self, source: str) -> Path:
        return self.data / f"hashset.{source}.idx"

    def bf_path(self, source: str) -> Path:
        return self.data / f"hashset.{source}.bf"

    def manifest_path(self) -> Path:
        return self.data / "manifest.json"

# ==========================
# UPDATE: download/ingest IOC
# ==========================

def http_get(url: str, dest: Path, timeout: int = 30) -> Tuple[int, Optional[str], Optional[str]]:
    """Simple download helper backed by urllib; returns (bytes_written, etag, last_modified)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": f"{APP}/{VERSION} (python-stdlib-urllib)"
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            etag = resp.headers.get("ETag")
            lastmod = resp.headers.get("Last-Modified")
            with open(dest, "wb") as f:
                shutil.copyfileobj(resp, f)
            size = dest.stat().st_size
            return size, etag, lastmod
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP error {e.code} for {url}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error {e.reason} for {url}")


def update_malwarebazaar(paths: Paths, quiet: bool = False) -> Tuple[int, int]:
    """Download the full MD5 dump or reuse the local copy if it already exists. Returns (valid, invalid)."""
    dest = paths.ioc_mb / MB_FILENAME
    log("Checking MalwareBazaar full MD5 dump...", quiet=quiet)
    size, etag, lastmod = http_get(MB_URL, dest)
    log(f"Saved: {dest} ({sizeof_fmt(size)})", quiet=quiet)

    if zipfile.is_zipfile(dest):
        with zipfile.ZipFile(dest) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".txt")]
            if not names:
                raise RuntimeError("MalwareBazaar ZIP missing inner .txt file")
            data = zf.read(names[0])
        dest.write_bytes(data)
        size = len(data)
        log(f"Extracted ZIP payload: {dest} ({sizeof_fmt(size)})", quiet=quiet)

    valid, invalid = validate_md5_file(dest, quiet=quiet)
    log(f"Lines: {valid+invalid:,} | Valid MD5: {valid:,} | Invalid: {invalid:,}", quiet=quiet)
    return valid, invalid


def list_vs_files(paths: Paths) -> List[Path]:
    files: List[Path] = []
    for p in sorted(paths.ioc_vs.rglob("*")):
        if p.is_file() and (p.suffix.lower() in {".txt", ".zip", ".md5"}):
            files.append(p)
    return files


def list_custom_files(paths: Paths) -> List[Path]:
    files: List[Path] = []
    for p in sorted(paths.ioc_custom.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".txt", ".md5"}:
            files.append(p)
    return files


def download_virusshare_remote(paths: Paths, cookie_file: Optional[Path], quiet: bool=False) -> List[Path]:
    """Download MD5 listings from virusshare.com. Cookies are optional."""
    jar: Optional[http.cookiejar.MozillaCookieJar] = None
    if cookie_file is not None:
        if not cookie_file.exists():
            log(f"VirusShare: cookie file no encontrado: {cookie_file}", level="ERROR", quiet=quiet)
            return []
        jar = http.cookiejar.MozillaCookieJar()
        try:
            jar.load(str(cookie_file), ignore_discard=True, ignore_expires=True)
        except Exception as e:
            log(f"VirusShare: no se pudieron cargar las cookies ({e})", level="ERROR", quiet=quiet)
            return []

    handlers = []
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", f"{APP}/{VERSION} (python-stdlib-urllib)")]

    try:
        with opener.open(VS_HASHES_URL, timeout=45) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        level = "ERROR" if e.code not in (401, 403) else "WARN"
        msg = (
            "VirusShare: access denied (login required?). Use --cookie-file with your cookies."
            if e.code in (401, 403) else f"VirusShare: HTTP error {e.code} while accessing {VS_HASHES_URL}"
        )
        log(msg, level=level, quiet=quiet)
        return []
    except urllib.error.URLError as e:
        log(f"VirusShare: network error {e.reason}", level="ERROR", quiet=quiet)
        return []

    if jar is not None:
        # Use the current cookie values (including fresh Set-Cookie) for later concurrent downloads.
        cookie_header = "; ".join(f"{c.name}={c.value}" for c in jar if c.name and c.value) or None
    else:
        cookie_header = None

    links = sorted({m.group("href") for m in VS_LINK_RE.finditer(html)})
    if not links:
        log("VirusShare: no hash files were found on the listings page.", level="WARN", quiet=quiet)
        return []

    targets = []
    for href in links:
        url = urljoin(VS_HASHES_URL, href)
        local_name = Path(urlparse(url).path).name
        dest = paths.ioc_vs / local_name
        if dest.exists():
            continue
        targets.append((local_name, url, dest))

    if not targets:
        log("VirusShare: no new files were downloaded (all already present).", quiet=quiet)
        return []

    headers = {"User-Agent": f"{APP}/{VERSION} (python-stdlib-urllib)", "Referer": VS_HASHES_URL}
    if cookie_header:
        headers["Cookie"] = cookie_header

    downloaded: List[Path] = []

    def worker(entry):
        local_name, url, dest = entry
        tmp = dest.with_suffix(dest.suffix + ".part")
        log(f"VirusShare: downloading {local_name}", quiet=quiet)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
                shutil.copyfileobj(resp, out)
            tmp.replace(dest)
            return dest
        except urllib.error.HTTPError as e:
            log(f"VirusShare: HTTP error {e.code} while downloading {local_name}", level="ERROR", quiet=quiet)
        except urllib.error.URLError as e:
            log(f"VirusShare: network error {e.reason} while downloading {local_name}", level="ERROR", quiet=quiet)
        except Exception as e:
            log(f"VirusShare: error while saving {local_name}: {e}", level="ERROR", quiet=quiet)
        finally:
            tmp.unlink(missing_ok=True)
        return None

    max_workers = min(VS_DOWNLOAD_THREADS, len(targets))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(worker, entry): entry for entry in targets}
        for fut in as_completed(futures):
            dest = fut.result()
            if dest is not None:
                downloaded.append(dest)

    if downloaded:
        log(f"VirusShare: downloaded {len(downloaded)} new file(s).", quiet=quiet)
    else:
        log("VirusShare: no new files downloaded (already present or failures).", quiet=quiet)
    return downloaded


def update_virusshare(paths: Paths, local_only: bool, cookie_file: Optional[Path], quiet: bool=False) -> Tuple[int, int]:
    """Optionally download and ingest VirusShare MD5 lists."""
    if not local_only:
        download_virusshare_remote(paths, cookie_file, quiet=quiet)
    files = list_vs_files(paths)
    if not files:
        log("VirusShare: no local files found in IOC/VirusShare/", level="WARN", quiet=quiet)
        return 0, 0

    total_valid = 0
    total_invalid = 0
    for f in files:
        if f.suffix.lower() == ".zip":
            with zipfile.ZipFile(f, 'r') as z:
                for name in z.namelist():
                    if name.lower().endswith('.txt'):
                        with z.open(name) as zf:
                            v, inv = validate_md5_stream(io.TextIOWrapper(zf, encoding='utf-8', errors='ignore'), quiet=True)
                            total_valid += v
                            total_invalid += inv
        else:
            v, inv = validate_md5_file(f, quiet=True)
            total_valid += v
            total_invalid += inv

    log(f"Found: {len(files)} file(s) in IOC/VirusShare/", quiet=quiet)
    log(f"Total lines: {total_valid+total_invalid:,} | Valid MD5: {total_valid:,} | Invalid: {total_invalid:,}", quiet=quiet)
    return total_valid, total_invalid


def update_custom(paths: Paths, quiet: bool=False) -> Tuple[int, int]:
    """Validate local files placed in IOC/custom."""
    ensure_dirs(paths.ioc_custom)
    files = list_custom_files(paths)
    if not files:
        log("Custom: no files found in IOC/custom", level="WARN", quiet=quiet)
        return 0, 0

    total_valid = 0
    total_invalid = 0
    for f in files:
        v, inv = validate_md5_file(f, quiet=True)
        total_valid += v
        total_invalid += inv
        log(f"[CUSTOM] {f.name}: valid={v:,} invalid={inv:,}", quiet=quiet)

    log(f"[CUSTOM] Total valid={total_valid:,} invalid={total_invalid:,}", quiet=quiet)
    return total_valid, total_invalid


def validate_md5_file(path: Path, quiet: bool=False) -> Tuple[int,int]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return validate_md5_stream(f, quiet=quiet)


def validate_md5_stream(stream: io.TextIOBase, quiet: bool=False) -> Tuple[int,int]:
    valid = invalid = 0
    for line in stream:
        s = line.strip()
        if not s:
            continue
        if is_valid_md5(s):
            valid += 1
        else:
            invalid += 1
    return valid, invalid

# ==========================
# BUILD: sort, index, bloom
# ==========================

class PartWriter:
    """Write sorted chunks of MD5 records (16B each) into temporary .part files."""
    def __init__(self, tmpdir: Path, source: str):
        self.tmpdir = tmpdir
        self.source = source
        self.parts: List[Path] = []
        self._buf: List[bytes] = []

    def add(self, rec: bytes):
        self._buf.append(rec)

    def flush_part(self):
        if not self._buf:
            return
        self._buf.sort()
        part_path = self.tmpdir / f"{self.source}.{len(self.parts):05d}.part"
        with open(part_path, 'wb') as w:
            w.writelines(self._buf)
        self.parts.append(part_path)
        self._buf.clear()

    def finalize(self):
        self.flush_part()
        return self.parts


def iter_md5_records_from_source(paths: Paths, source: str) -> Iterator[bytes]:
    """Iterate valid MD5 values as raw 16-byte records sourced from IOC folders."""
    if source == 'mb':
        src = paths.ioc_mb / MB_FILENAME
        if not src.exists():
            return
        with open(src, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                s = line.strip()
                if s and is_valid_md5(s):
                    yield md5hex_to_bytes(s)
    elif source == 'vs':
        for p in list_vs_files(paths):
            if p.suffix.lower() == '.zip':
                with zipfile.ZipFile(p, 'r') as z:
                    for name in z.namelist():
                        if name.lower().endswith('.txt'):
                            with z.open(name) as zf:
                                for line in io.TextIOWrapper(zf, encoding='utf-8', errors='ignore'):
                                    s = line.strip()
                                    if s and is_valid_md5(s):
                                        yield md5hex_to_bytes(s)
            else:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        s = line.strip()
                        if s and is_valid_md5(s):
                            yield md5hex_to_bytes(s)
    elif source == 'custom':
        for p in list_custom_files(paths):
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    s = line.strip()
                    if s and is_valid_md5(s):
                        yield md5hex_to_bytes(s)


def external_sort_and_merge(paths: Paths, source: str, chunk_recs: int, quiet: bool=False) -> Tuple[Path, int]:
    """Externally sort all MD5 entries for a source and produce a deduplicated .bin file.
    Returns (bin_path, total_records)."""
    tmpdir = Path(tempfile.mkdtemp(prefix=f"hhx_{source}_", dir=str(paths.cache)))
    partw = PartWriter(tmpdir, source)

    count = 0
    buf_count = 0
    last_report = time.time()
    for rec in iter_md5_records_from_source(paths, source):
        partw.add(rec)
        count += 1
        buf_count += 1
        # Flush chunk
        if buf_count >= chunk_recs:
            partw.flush_part()
            buf_count = 0
            if time.time() - last_report > 1.5:
                log(f"[{source.upper()}] External sort... parts={len(partw.parts)} records={count:,}", quiet=quiet)
                last_report = time.time()

    parts = partw.finalize()
    log(f"[{source.upper()}] Total records read: {count:,} | parts={len(parts)}", quiet=quiet)

    # Merge k-way
    bin_path = paths.bin_path(source)
    with open(bin_path, 'wb') as out:
        # Open each part as a 16-byte stream
        streams: List[io.BufferedReader] = [open(p, 'rb') for p in parts]
        try:
            heads: List[Optional[bytes]] = [s.read(RECORD_SIZE) for s in streams]
            last_written: Optional[bytes] = None
            while True:
                # Choose the minimum among head records
                min_idx = -1
                min_val = None
                for i, h in enumerate(heads):
                    if h is None or len(h) == 0:
                        continue
                    if min_val is None or h < min_val:
                        min_val = h
                        min_idx = i
                if min_idx == -1:
                    break  # finished
                # Write if not duplicated
                if last_written != min_val:
                    out.write(min_val)
                    last_written = min_val
                # Advance the stream at min_idx
                heads[min_idx] = streams[min_idx].read(RECORD_SIZE)
        finally:
            for s in streams:
                s.close()
        # Cleanup for part files
        for p in parts:
            try:
                p.unlink()
            except Exception:
                pass
        try:
            tmpdir.rmdir()
        except Exception:
            pass

    total_records = bin_path.stat().st_size // RECORD_SIZE
    return bin_path, total_records


def build_prefix_index(bin_path: Path, idx_path: Path, quiet: bool=False) -> None:
    """Build a 2-byte prefix index using counts plus prefix sums."""
    size = bin_path.stat().st_size
    n = size // RECORD_SIZE
    counts = [0] * INDEX_ENTRIES
    with open(bin_path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for i in range(n):
                pos = i * RECORD_SIZE
                prefix = int.from_bytes(mm[pos:pos+PREFIX_BYTES], 'big')
                counts[prefix] += 1
        finally:
            mm.close()
    # prefix sums -> starts
    starts = [0] * (INDEX_ENTRIES + 1)
    total = 0
    for i in range(INDEX_ENTRIES):
        starts[i] = total
        total += counts[i]
    starts[INDEX_ENTRIES] = total

    with open(idx_path, 'wb') as w:
        w.write(struct.pack(f">{INDEX_ENTRIES+1}Q", *starts))


def bloom_params(n: int, fp_rate: float) -> Tuple[int, int]:
    """Compute (m_bits, k) parameters for the bloom filter."""
    if n <= 0:
        return 8, 1
    m = math.ceil(-n * math.log(fp_rate) / (math.log(2) ** 2))
    k = max(1, round((m / n) * math.log(2)))
    return m, k


def bloom_build_from_bin(bin_path: Path, bf_path: Path, n: int, fp_rate: float, quiet: bool=False) -> Tuple[int,int]:
    m_bits, k = bloom_params(n, fp_rate)
    m_bytes = (m_bits + 7) // 8
    log(f"Bloom params: n={n:,} m_bits={m_bits:,} (~{sizeof_fmt(m_bytes)}) k={k}", quiet=quiet)

    bitarr = bytearray(m_bytes)

    # hashing: double hashing via BLAKE2b with personalization
    def _hashes(rec: bytes) -> Tuple[int, int]:
        import hashlib
        h1 = hashlib.blake2b(rec, digest_size=16, person=b'HH0xA').digest()
        h2 = hashlib.blake2b(rec, digest_size=16, person=b'HH0xB').digest()
        return int.from_bytes(h1, 'big'), int.from_bytes(h2, 'big')

    with open(bin_path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for i in range(n):
                pos = i * RECORD_SIZE
                rec = mm[pos:pos+RECORD_SIZE]
                h1, h2 = _hashes(rec)
                for j in range(k):
                    bit = (h1 + j * h2) % m_bits
                    byte_i = bit >> 3
                    bit_i = bit & 7
                    bitarr[byte_i] |= (1 << (7 - bit_i))
                if (i & 0xFFFFF) == 0xFFFFF:  # cada ~1M
                    log(f"[BLOOM] progress {i+1:,}/{n:,}", quiet=quiet)
        finally:
            mm.close()

    # escribir bloom con header
    with open(bf_path, 'wb') as w:
        hdr = BLOOM_HDR_STRUCT.pack(BLOOM_MAGIC, m_bits, k, n, b"\x00"*16)
        w.write(hdr)
        w.write(bitarr)
    return m_bits, k


class Bloom:
    def __init__(self, path: Path):
        self.path = path
        self.f = open(path, 'rb')
        hdr = self.f.read(BLOOM_HDR_STRUCT.size)
        magic, self.m_bits, self.k, self.n, _ = BLOOM_HDR_STRUCT.unpack(hdr)
        if magic != BLOOM_MAGIC:
            raise RuntimeError("Invalid bloom header")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        self.base = BLOOM_HDR_STRUCT.size

    def close(self):
        try:
            self.mm.close()
            self.f.close()
        except Exception:
            pass

    def might_contain(self, rec: bytes) -> bool:
        h1, h2 = self._hashes(rec)
        for j in range(self.k):
            bit = (h1 + j * h2) % self.m_bits
            byte_i = bit >> 3
            bit_i = bit & 7
            b = self.mm[self.base + byte_i]
            if (b & (1 << (7 - bit_i))) == 0:
                return False
        return True

    @staticmethod
    def _hashes(rec: bytes) -> Tuple[int, int]:
        import hashlib
        h1 = hashlib.blake2b(rec, digest_size=16, person=b'HH0xA').digest()
        h2 = hashlib.blake2b(rec, digest_size=16, person=b'HH0xB').digest()
        return int.from_bytes(h1, 'big'), int.from_bytes(h2, 'big')


class BinIndex:
    def __init__(self, bin_path: Path, idx_path: Path):
        self.bin_path = bin_path
        self.idx_path = idx_path
        self.f_bin = open(bin_path, 'rb')
        self.mm = mmap.mmap(self.f_bin.fileno(), 0, access=mmap.ACCESS_READ)
        self.n = self.mm.size() // RECORD_SIZE
        with open(idx_path, 'rb') as f:
            data = f.read()
            self.starts = list(struct.unpack(f">{INDEX_ENTRIES+1}Q", data))

    def close(self):
        try:
            self.mm.close()
            self.f_bin.close()
        except Exception:
            pass

    def range_for_prefix(self, rec: bytes) -> Tuple[int,int]:
        p = int.from_bytes(rec[:PREFIX_BYTES], 'big')
        return self.starts[p], self.starts[p+1]

    def find_exact(self, rec: bytes, start: int, end: int) -> bool:
        # binary search en [start, end)
        lo, hi = start, end
        while lo < hi:
            mid = (lo + hi) // 2
            pos = mid * RECORD_SIZE
            midrec = self.mm[pos:pos+RECORD_SIZE]
            if midrec < rec:
                lo = mid + 1
            elif midrec > rec:
                hi = mid
            else:
                return True
        return False

# ==========================
# SCAN / CHECK
# ==========================

class SourceHandles:
    def __init__(self, label: str, binidx: BinIndex, bloom: Bloom):
        self.label = label
        self.binidx = binidx
        self.bloom = bloom

    def close(self):
        self.binidx.close()
        self.bloom.close()


def load_sources(paths: Paths, sources: List[str]) -> Dict[str, SourceHandles]:
    res: Dict[str, SourceHandles] = {}
    for s in sources:
        binp = paths.bin_path(s)
        idxp = paths.idx_path(s)
        bfp = paths.bf_path(s)
        if not (binp.exists() and idxp.exists() and bfp.exists()):
            raise RuntimeError(f"Source {s} is not built. Run: hashhunter build --{s}")
        label = SOURCE_LABELS.get(s, s.upper())
        res[s] = SourceHandles(label, BinIndex(binp, idxp), Bloom(bfp))
    return res


def scan_hashes(
    paths: Paths,
    infile: Path,
    sources: List[str],
    out_csv: Optional[Path],
    out_json: Optional[Path],
    out_html: Optional[Path],
    quiet: bool = False,
    input_label: Optional[str] = None,
    is_stdin: bool = False,
) -> Dict[str, int]:
    handles = load_sources(paths, sources)
    dataset_total = sum(h.binidx.n for h in handles.values())
    totals = {"valid": 0, "positive": 0, "mb": 0, "vs": 0, "custom": 0, "mb_vs": 0}

    def process_line(line: str) -> Tuple[str, str, Dict[str, bool]]:
        s = line.strip()
        if not s:
            return "", "", {}
        parts = s.split(None, 1)
        candidate = parts[0]
        if not is_valid_md5(candidate):
            return "", "", {}
        alias = parts[1].strip() if len(parts) > 1 else ""
        rec = md5hex_to_bytes(candidate)
        found = {}
        for src in sources:
            h = handles[src]
            if not h.bloom.might_contain(rec):
                found[src] = False
                continue
            start, end = h.binidx.range_for_prefix(rec)
            exact = start < end and h.binidx.find_exact(rec, start, end)
            found[src] = exact
        return candidate, alias, found

    # IO setup
    csv_writer = None
    json_out = None
    html_rows: List[Dict[str, Any]] = []
    html_meta: Optional[Dict[str, Any]] = None
    if out_csv:
        fcsv = open(out_csv, 'w', newline='', encoding='utf-8')
        csv_writer = csv.writer(fcsv)
        csv_writer.writerow(["hash", "alias", "malwarebazaar", "virusshare", "custom", "sources"])
    if out_json:
        json_out = open(out_json, 'w', encoding='utf-8')
    if out_html:
        sources_labels = [SOURCE_LABELS.get(s, s.upper()) for s in sources]
        input_display = input_label if input_label is not None else ("STDIN" if is_stdin else str(infile))
        dataset_files = count_dataset_files(paths, sources)
        html_meta = {
            "input": input_display,
            "sources": sources_labels,
            "generated": now_utc(),
            "dataset_total": dataset_total,
            "scanned": 0,
            "files_processed": dataset_files,
        }

    t0 = time.time()
    processed = 0

    # iterate input
    stream = sys.stdin if str(infile) == '-' else open(infile, 'r', encoding='utf-8', errors='ignore')
    try:
        for line in stream:
            h, alias, hits = process_line(line)
            if not h:
                continue
            processed += 1
            totals['valid'] += 1

            mb = hits.get('mb', False)
            vs = hits.get('vs', False)
            custom_hit = hits.get('custom', False)
            src_flags = [('mb', mb), ('vs', vs), ('custom', custom_hit)]

            hit_any = False
            if mb:
                totals['mb'] += 1
                hit_any = True
            if vs:
                totals['vs'] += 1
                hit_any = True
            if custom_hit:
                totals['custom'] += 1
                hit_any = True
            if mb and vs:
                totals['mb_vs'] += 1
            if hit_any:
                totals['positive'] += 1

            if csv_writer:
                srcs = ",".join(src.upper() for src, flag in src_flags if flag)
                csv_writer.writerow([
                    h,
                    alias,
                    str(mb).lower(),
                    str(vs).lower(),
                    str(custom_hit).lower(),
                    srcs
                ])
            if json_out:
                obj = {
                    "hash": h,
                    "alias": alias,
                    "malwarebazaar": mb,
                    "virusshare": vs,
                    "custom": custom_hit,
                    "sources": [SOURCE_LABELS[src] for src, flag in src_flags if flag]
                }
                json_out.write(json.dumps(obj) + "\n")
            if html_meta is not None:
                priority = 2 if (mb and vs) else (1 if hit_any else 0)
                html_rows.append(
                    {
                        "hash": h,
                        "alias": alias,
                        "mb": bool(mb),
                        "vs": bool(vs),
                        "custom": bool(custom_hit),
                        "hit": hit_any,
                        "priority": priority,
                    }
                )

            if (processed & 0x3FFFF) == 0x3FFFF:  # roughly every ~262k
                elapsed = time.time() - t0
                rate = processed / max(1e-6, elapsed)
                log(f"[RUN] processed={processed:,} ~{int(rate):,} checks/s", quiet=quiet)
    finally:
        duration = time.time() - t0
        if stream is not sys.stdin:
            stream.close()
        for h in handles.values():
            h.close()
        if out_csv:
            fcsv.close()  # type: ignore[name-defined]
        if out_json:
            json_out.close()  # type: ignore[union-attr]
        if html_meta is not None:
            positive_hits = sum(1 for row in html_rows if row["mb"] or row["vs"] or row["custom"])
            ordered_rows = sorted(html_rows, key=lambda row: (-row.get("priority", 0), row.get("hash", "")))
            html_meta["scanned"] = totals["valid"]
            html_meta["positive"] = positive_hits
            html_meta["duration_seconds"] = duration
            html_meta["duration"] = time.strftime('%H:%M:%S', time.gmtime(duration))
            render_html_report(out_html, html_meta, ordered_rows)

    elapsed = time.time() - t0
    log("[COUNTS]", quiet=quiet)
    log(f"  Dataset hashes: {dataset_total:,}", quiet=quiet)
    log(f"  Valid MD5 read: {totals['valid']:,}", quiet=quiet)
    log(f"  Analyzed hashes: {totals['valid']:,}", quiet=quiet)

    print()
    log("[RESULTS]", quiet=quiet)
    if totals['positive'] > 0:
        log(f"[ALERT] Positives:      {totals['positive']:,}", quiet=quiet)
    else:
        log(f"[RESULTS] Positives:      {totals['positive']:,}", quiet=quiet)
    if 'mb' in sources:
        log(f"  MalwareBazaar: {totals['mb']:,}", quiet=quiet)
    if 'vs' in sources:
        log(f"  VirusShare:    {totals['vs']:,}", quiet=quiet)
    if 'custom' in sources:
        log(f"  Custom:        {totals['custom']:,}", quiet=quiet)
    # MB+VS totals are shown in the HTML footer; skip in console to reduce noise.
    log(f"  Duration: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}", quiet=quiet)

    return totals

# ==========================
# MANIFEST / STATUS
# ==========================

def read_manifest(paths: Paths) -> dict:
    p = paths.manifest_path()
    if p.exists():
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {"version": 1, "sources": {}}


def write_manifest(paths: Paths, sources_info: Dict[str, dict]):
    man = read_manifest(paths)
    man.setdefault("sources", {}).update(sources_info)
    with open(paths.manifest_path(), 'w', encoding='utf-8') as f:
        json.dump(man, f, indent=2)


def cmd_update(args):
    paths = Paths(Path(args.workdir).resolve())
    quiet = args.quiet
    sources = parse_sources_flags(args)

    banner = UPLOAD_BANNER.rstrip()
    if USE_COLORS:
        print(f"{LOG_COLORS.get('COUNTS', '')}{banner}{ANSI_RESET}")
    else:
        print(banner)
    log(f"Workdir: {paths.workdir}")
    log(f"[UPDATE] Sources: {', '.join(s.upper() for s in sources)}")

    info: Dict[str, dict] = {}

    if 'mb' in sources:
        v, inv = update_malwarebazaar(paths, quiet=quiet)
        info['MalwareBazaar'] = {
            "valid": v,
            "invalid": inv,
            "updated_at": now_utc(),
            "ioc_path": str(paths.ioc_mb / MB_FILENAME)
        }

    if 'vs' in sources:
        v, inv = update_virusshare(paths, local_only=args.local_only, cookie_file=Path(args.cookie_file) if args.cookie_file else None, quiet=quiet)
        info['VirusShare'] = {
            "valid": v,
            "invalid": inv,
            "updated_at": now_utc(),
            "ioc_path": str(paths.ioc_vs)
        }

    if 'custom' in sources:
        v, inv = update_custom(paths, quiet=quiet)
        info['Custom'] = {
            "valid": v,
            "invalid": inv,
            "updated_at": now_utc(),
            "ioc_path": str(paths.ioc_custom)
        }

    if info:
        write_manifest(paths, info)
    log("[SUMMARY]", quiet=quiet)
    for k, v in info.items():
        log(f"  {k}: Valid={v['valid']:,} Invalid={v['invalid']:,}", quiet=quiet)
    log("[SUCCESS] update finished")


def cmd_build(args):
    paths = Paths(Path(args.workdir).resolve())
    quiet = args.quiet
    sources = parse_sources_flags(args)

    log(f"Workdir: {paths.workdir}")
    log(f"[BUILD] Sources: {', '.join(s.upper() for s in sources)}")
    log(f"[CFG] Bloom fp-rate: {args.fp_rate} | Threads: {args.threads}")

    info: Dict[str, dict] = {}
    for s in sources:
        # External sort and merge -> .bin
        bin_path, n = external_sort_and_merge(paths, s, chunk_recs=args.chunk_recs, quiet=quiet)
        log(f"[{s.upper()}] Records: {n:,} | Bin: {sizeof_fmt(bin_path.stat().st_size)}")
        # Prefix index
        idx_path = paths.idx_path(s)
        build_prefix_index(bin_path, idx_path, quiet=quiet)
        log(f"[{s.upper()}] Prefix index -> {idx_path} ({sizeof_fmt(idx_path.stat().st_size)})")
        # Bloom filter
        bf_path = paths.bf_path(s)
        m_bits, k = bloom_build_from_bin(bin_path, bf_path, n, fp_rate=args.fp_rate, quiet=quiet)
        log(f"[{s.upper()}] Bloom -> {bf_path} (~{sizeof_fmt((m_bits+7)//8)}) k={k}")

        info_name = SOURCE_LABELS.get(s, s.upper())
        info[info_name] = {
            "records": n,
            "built_at": now_utc(),
            "bin": str(bin_path),
            "idx": str(idx_path),
            "bloom": str(bf_path),
            "fp_rate": args.fp_rate,
        }
    if info:
        write_manifest(paths, info)
        log("[MANIFEST] updated")
    log("[SUCCESS] build completed")


def cmd_scan(args):
    paths = Paths(Path(args.workdir).resolve())
    quiet = args.quiet
    sources = parse_sources_flags(args)
    log(f"Workdir: {paths.workdir}")
    log(f"[SCAN] Input: {args.infile}")
    log(f"[SCAN] Sources: {', '.join(s.upper() for s in sources)} | Loading bloom/indices...")

    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    input_id = "stdin" if args.infile == "-" else Path(args.infile).stem or "input"
    default_stem = f"{input_id}_{timestamp}"

    out_csv = Path(args.csv) if args.csv else paths.output / f"{default_stem}.csv"
    out_json = Path(args.json) if args.json else None
    out_html = Path(args.html) if getattr(args, "html", None) else paths.output / f"{default_stem}.html"

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
    out_html.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    totals = scan_hashes(
        paths,
        Path(args.infile),
        sources,
        out_csv,
        out_json,
        out_html,
        quiet=quiet,
        input_label=args.infile,
        is_stdin=(args.infile == "-"),
    )
    elapsed = time.time() - t0

    log(f"[OUTPUT] CSV -> {out_csv}")
    if out_json:
        log(f"[OUTPUT] JSON -> {out_json}")
    log(f"[OUTPUT] HTML -> {out_html}")

    log("[SUCCESS] Scan completed!")


def cmd_check(args):
    paths = Paths(Path(args.workdir).resolve())
    sources = parse_sources_flags(args)
    h = args.hash.strip().lower()
    if not is_valid_md5(h):
        raise SystemExit("Invalid MD5. Expected 32 hex characters.")

    rec = md5hex_to_bytes(h)
    handles = load_sources(paths, sources)
    try:
        print(f"[CHECK] {h}")
        for s in sources:
            hnd = handles[s]
            label = hnd.label
            if not hnd.bloom.might_contain(rec):
                print(f"  {label}: NOT FOUND")
                continue
            start, end = hnd.binidx.range_for_prefix(rec)
            exact = start < end and hnd.binidx.find_exact(rec, start, end)
            print(f"  {label}: {'FOUND' if exact else 'NOT FOUND'}")
    finally:
        for hnd in handles.values():
            hnd.close()


def cmd_status(args):
    paths = Paths(Path(args.workdir).resolve())
    man = read_manifest(paths)

    print(f"[STATUS] {paths.manifest_path()}")
    hdr = (
        f"{'Source':<13} {'Records':>10}  {'Bin':>8}  {'Idx':>6}  {'Bloom':>6}  {'Built At (UTC)':>22}"
    )
    print(hdr)
    print(" " * len(hdr))

    total = 0
    ordered_keys = [SOURCE_LABELS[s] for s in SOURCE_ORDER]
    for k in ordered_keys:
        v = man.get("sources", {}).get(k)
        if not v:
            continue
        recs = v.get("records", v.get("valid", 0))
        total += int(recs)
        binp = v.get("bin")
        idxp = v.get("idx")
        bfp = v.get("bloom")
        built = v.get("built_at", v.get("updated_at", "-"))

        def size_or_dash(p):
            try:
                return sizeof_fmt(Path(p).stat().st_size)
            except Exception:
                return "-"

        print(f"{k:<13} {int(recs):>10,}  {size_or_dash(binp):>8}  {size_or_dash(idxp):>6}  {size_or_dash(bfp):>6}  {built:>22}")
    print(f"{'Total':<13} {total:>10,}")

# ==========================
# CLI
# ==========================

def parse_sources_flags(args) -> List[str]:
    if getattr(args, "all", False):
        return SOURCE_ORDER.copy()
    sels: List[str] = []
    if getattr(args, "mb", False):
        sels.append("mb")
    if getattr(args, "vs", False):
        sels.append("vs")
    if getattr(args, "custom", False):
        sels.append("custom")
    if not sels:
        sels = SOURCE_ORDER.copy()  # default all
    return sels


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='hashhunter', description=f"{APP} v{VERSION} - fast MD5 lookups")
    p.add_argument('--workdir', default='.', help='Base directory (default: .)')

    sub = p.add_subparsers(dest='cmd', required=True)

    # update
    pu = sub.add_parser('update', help='Download/ingest IOC (MB/VS/custom)')
    gsrc = pu.add_mutually_exclusive_group()
    gsrc.add_argument('--all', action='store_true', help='MB + VS + custom (default)')
    gsrc.add_argument('--mb', action='store_true', help='Only MalwareBazaar')
    gsrc.add_argument('--vs', action='store_true', help='Only VirusShare')
    gsrc.add_argument('--custom', action='store_true', help='Only Custom')
    pu.add_argument('--local-only', action='store_true', help='Skip downloads; use local files in IOC/')
    pu.add_argument('--cookie-file', help='Cookies for VS')
    pu.add_argument('--quiet', action='store_true', help='Minimal output')
    pu.set_defaults(func=cmd_update)

    # build
    pb = sub.add_parser('build', help='Build bin/idx/bloom')
    gsrc = pb.add_mutually_exclusive_group()
    gsrc.add_argument('--all', action='store_true')
    gsrc.add_argument('--mb', action='store_true')
    gsrc.add_argument('--vs', action='store_true')
    gsrc.add_argument('--custom', action='store_true')
    pb.add_argument('--fp-rate', type=float, default=DEFAULT_FP_RATE, help='Bloom FP rate (default 1e-3)')
    pb.add_argument('--threads', type=int, default=DEFAULT_THREADS, help='Reserved: build parallelism')
    pb.add_argument('--chunk-recs', type=int, default=DEFAULT_CHUNK_RECS, help='Records per chunk for external sort (default 8M)')
    pb.add_argument('--quiet', action='store_true')
    pb.set_defaults(func=cmd_build)

    # scan
    ps = sub.add_parser('scan', help='Compare hashes against the sources')
    ps.add_argument('infile', help='Input file or - for STDIN')
    gsrc = ps.add_mutually_exclusive_group()
    gsrc.add_argument('--all', action='store_true')
    gsrc.add_argument('--mb', action='store_true')
    gsrc.add_argument('--vs', action='store_true')
    gsrc.add_argument('--custom', action='store_true')
    ps.add_argument('--csv', help='Write CSV output to PATH')
    ps.add_argument('--html', help='Write HTML report to PATH')
    ps.add_argument('--json', help='Write JSONL output to PATH')
    ps.add_argument('--quiet', action='store_true')
    ps.set_defaults(func=cmd_scan)

    # check
    pc = sub.add_parser('check', help='Single MD5 lookup')
    pc.add_argument('hash', help='MD5 (32 hex)')
    gsrc = pc.add_mutually_exclusive_group()
    gsrc.add_argument('--all', action='store_true')
    gsrc.add_argument('--mb', action='store_true')
    gsrc.add_argument('--vs', action='store_true')
    gsrc.add_argument('--custom', action='store_true')
    pc.set_defaults(func=cmd_check)

    # status
    pst = sub.add_parser('status', help='Datasets/index status')
    pst.set_defaults(func=cmd_status)

    return p


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        log("Aborted by user", level="ERROR")
        return 5
    except Exception as e:
        log(str(e), level="ERROR")
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
