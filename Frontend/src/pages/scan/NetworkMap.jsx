/**
 * src/pages/scan/NetworkMap.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Interactive network topology visualization using vis-network.
 *
 * Features:
 *   - Hierarchical top-down layout (Gateway -> Switch -> Subnets -> Hosts)
 *   - Subnet-based clustering (/24 grouped by default)
 *   - Expand/collapse individual subnets with 50-host limit cap
 *   - Subnet filters (checkboxes in sidebar)
 *   - Search box to filter hosts
 *   - Log-proportional link/edge thickness
 *   - Hover tooltips for host labels (hidden at rest)
 */
import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import { Network, DataSet } from "vis-network/standalone";
import AppLayout from "../../components/layout/AppLayout";
import Modal from "../../components/layout/Modal";
import api from "../../api/axiosInstance";
import "../../styles/NetworkMap.css";

/* ── Node/Link configurations ────────────────────────────────────────────────── */
const GROUP_COLORS = {
  router: { background: "#f87171", border: "#ef4444", font: "#fff" },
  switch: { background: "#60a5fa", border: "#3b82f6", font: "#fff" },
  gateway: { background: "#fca5a5", border: "#f87171", font: "#fff" },
  firewall: { background: "#fb923c", border: "#f97316", font: "#fff" },
  wireless_ap: { background: "#2dd4bf", border: "#14b8a6", font: "#fff" },
  server: { background: "#c084fc", border: "#a855f7", font: "#fff" },
  workstation: { background: "#818cf8", border: "#6366f1", font: "#fff" },
  desktop: { background: "#93c5fd", border: "#3b82f6", font: "#fff" },
  laptop: { background: "#f472b6", border: "#ec4899", font: "#fff" },
  endpoint: { background: "#a78bfa", border: "#8b5cf6", font: "#fff" },
  printer: { background: "#fbbf24", border: "#f59e0b", font: "#fff" },
  camera: { background: "#34d399", border: "#10b981", font: "#fff" },
  iot: { background: "#a3e635", border: "#84cc16", font: "#fff" },
  plc: { background: "#4ade80", border: "#22c55e", font: "#fff" },
  rtu: { background: "#a7f3d0", border: "#34d399", font: "#fff" },
  storage: { background: "#94a3b8", border: "#64748b", font: "#fff" },
  virtual_machine: { background: "#e879f9", border: "#d946ef", font: "#fff" },
  mobile: { background: "#6ee7b7", border: "#10b981", font: "#fff" },
  load_balancer: { background: "#fda4af", border: "#f43f5e", font: "#fff" },
  modem: { background: "#22d3ee", border: "#06b6d4", font: "#fff" },
  unknown: { background: "#cbd5e1", border: "#94a3b8", font: "#fff" },
  subnet: { background: "#22d3ee", border: "#0891b2", font: "#fff" },
};

// Stable SVG template strings for all 21 device categories
const ROUTER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="routerGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f87171" />
      <stop offset="100%" stop-color="#ef4444" />
    </linearGradient>
  </defs>
  <circle cx="32" cy="32" r="26" fill="#1e1b4b" stroke="url(#routerGrad)" stroke-width="2.5" />
  <path d="M32 8v10M32 46v10M8 32h10M46 32h10" stroke="#f87171" stroke-width="2.5" stroke-linecap="round" />
  <circle cx="32" cy="32" r="10" fill="#0f172a" stroke="#f87171" stroke-width="2" />
  <circle cx="32" cy="32" r="4" fill="#ef4444" />
</svg>`;

const SWITCH_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="switchGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#60a5fa" />
      <stop offset="100%" stop-color="#3b82f6" />
    </linearGradient>
  </defs>
  <rect x="6" y="16" width="52" height="32" rx="6" fill="#172554" stroke="url(#switchGrad)" stroke-width="2.5" />
  <rect x="12" y="24" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <rect x="24" y="24" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <rect x="36" y="24" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <rect x="48" y="24" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <rect x="12" y="34" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <rect x="24" y="34" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <rect x="36" y="34" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <rect x="48" y="34" width="8" height="6" rx="1" fill="#0f172a" stroke="#60a5fa" stroke-width="1.5" />
  <circle cx="16" cy="21" r="1.5" fill="#22c55e" />
  <circle cx="28" cy="21" r="1.5" fill="#22c55e" />
  <circle cx="40" cy="21" r="1.5" fill="#ef4444" />
  <circle cx="52" cy="21" r="1.5" fill="#22c55e" />
</svg>`;

const GATEWAY_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="gwGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#fca5a5" />
      <stop offset="100%" stop-color="#f87171" />
    </linearGradient>
  </defs>
  <rect x="8" y="12" width="48" height="40" rx="8" fill="#1e1b4b" stroke="url(#gwGrad)" stroke-width="2.5" />
  <path d="M22 28v14M32 22v20M42 28v14" stroke="#fca5a5" stroke-width="2.5" stroke-linecap="round" />
  <path d="M14 44h36" stroke="#f87171" stroke-width="2.5" stroke-linecap="round" />
</svg>`;

const FIREWALL_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="fwGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#fb923c" />
      <stop offset="100%" stop-color="#f97316" />
    </linearGradient>
  </defs>
  <path d="M12 8h40v12H12zm0 16h40v12H12zm0 16h40v12H12z" fill="#1e1b4b" stroke="url(#fwGrad)" stroke-width="2" />
  <path d="M22 8v48M42 8v48" stroke="url(#fwGrad)" stroke-width="2" />
  <path d="M12 20h40M12 36h40" stroke="#1e1b4b" stroke-width="2.5" />
</svg>`;

const WIRELESS_AP_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="apGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#2dd4bf" />
      <stop offset="100%" stop-color="#14b8a6" />
    </linearGradient>
  </defs>
  <circle cx="32" cy="46" r="8" fill="#115e59" stroke="url(#apGrad)" stroke-width="2" />
  <path d="M32 38v-24M24 24a12 12 0 0 1 16 0M16 16a24 24 0 0 1 32 0M8 8a36 36 0 0 1 48 0" fill="none" stroke="url(#apGrad)" stroke-width="2.5" stroke-linecap="round" />
</svg>`;

const SERVER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="srvGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#c084fc" />
      <stop offset="100%" stop-color="#a855f7" />
    </linearGradient>
  </defs>
  <rect x="10" y="8" width="44" height="48" rx="4" fill="#2e1065" stroke="url(#srvGrad)" stroke-width="2.5" />
  <rect x="14" y="14" width="36" height="8" rx="2" fill="#1e1b4b" stroke="#c084fc" stroke-width="1.5" />
  <rect x="14" y="28" width="36" height="8" rx="2" fill="#1e1b4b" stroke="#c084fc" stroke-width="1.5" />
  <rect x="14" y="42" width="36" height="8" rx="2" fill="#1e1b4b" stroke="#c084fc" stroke-width="1.5" />
  <circle cx="18" cy="18" r="2" fill="#22c55e" />
  <circle cx="18" cy="32" r="2" fill="#22c55e" />
  <circle cx="18" cy="46" r="2" fill="#22c55e" />
</svg>`;

const WORKSTATION_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="wsGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#818cf8" />
      <stop offset="100%" stop-color="#6366f1" />
    </linearGradient>
  </defs>
  <rect x="4" y="12" width="34" height="24" rx="2" fill="#1e1b4b" stroke="url(#wsGrad)" stroke-width="2.5" />
  <path d="M12 36v8M8 44h18" stroke="url(#wsGrad)" stroke-width="2.5" stroke-linecap="round" />
  <rect x="44" y="8" width="16" height="40" rx="3" fill="#1e1b4b" stroke="url(#wsGrad)" stroke-width="2" />
  <rect x="48" y="42" width="8" height="2" fill="#818cf8" />
</svg>`;

const DESKTOP_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="dtGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#93c5fd" />
      <stop offset="100%" stop-color="#3b82f6" />
    </linearGradient>
  </defs>
  <rect x="8" y="14" width="38" height="26" rx="2" fill="#172554" stroke="url(#dtGrad)" stroke-width="2.5" />
  <path d="M18 40v8M12 48h22" stroke="url(#dtGrad)" stroke-width="2.5" stroke-linecap="round" />
  <rect x="50" y="14" width="6" height="34" rx="1" fill="#172554" stroke="url(#dtGrad)" stroke-width="1.5" />
</svg>`;

const LAPTOP_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="ltGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f472b6" />
      <stop offset="100%" stop-color="#ec4899" />
    </linearGradient>
  </defs>
  <rect x="12" y="16" width="40" height="26" rx="3" fill="#1e1b4b" stroke="url(#ltGrad)" stroke-width="2.5" />
  <path d="M4 46h56l-4-6H8z" fill="#0f172a" stroke="url(#ltGrad)" stroke-width="2.5" stroke-linejoin="round" />
</svg>`;

const ENDPOINT_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="epGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#a78bfa" />
      <stop offset="100%" stop-color="#8b5cf6" />
    </linearGradient>
  </defs>
  <rect x="14" y="16" width="36" height="24" rx="2" fill="#1e1b4b" stroke="url(#epGrad)" stroke-width="2.5" />
  <path d="M22 40v8M18 48h28" stroke="url(#epGrad)" stroke-width="2.5" stroke-linecap="round" />
</svg>`;

const PRINTER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="prGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#fbbf24" />
      <stop offset="100%" stop-color="#f59e0b" />
    </linearGradient>
  </defs>
  <path d="M16 26h32v24H16z" fill="#78350f" stroke="url(#prGrad)" stroke-width="2.5" />
  <path d="M20 26v-12h24v12" fill="none" stroke="url(#prGrad)" stroke-width="2" />
  <path d="M12 36h40" stroke="url(#prGrad)" stroke-width="2.5" />
  <path d="M24 42h16M24 46h12" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" />
</svg>`;

const CAMERA_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="camGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#34d399" />
      <stop offset="100%" stop-color="#10b981" />
    </linearGradient>
  </defs>
  <path d="M32 10a18 18 0 0 0-18 18v8h36v-8a18 18 0 0 0-18-18z" fill="#064e3b" stroke="url(#camGrad)" stroke-width="2.5" />
  <circle cx="32" cy="28" r="8" fill="#022c22" stroke="url(#camGrad)" stroke-width="2" />
  <circle cx="32" cy="28" r="3" fill="#10b981" />
  <path d="M10 40h44v6H10z" fill="url(#camGrad)" />
</svg>`;

const IOT_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="iotGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#a3e635" />
      <stop offset="100%" stop-color="#84cc16" />
    </linearGradient>
  </defs>
  <rect x="16" y="16" width="32" height="32" rx="4" fill="#3f6212" stroke="url(#iotGrad)" stroke-width="2.5" />
  <path d="M32 8v8M32 48v8M8 32h8M48 32h8" stroke="url(#iotGrad)" stroke-width="2.5" stroke-linecap="round" />
  <circle cx="32" cy="32" r="6" fill="#84cc16" />
</svg>`;

const PLC_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="plcGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#4ade80" />
      <stop offset="100%" stop-color="#22c55e" />
    </linearGradient>
  </defs>
  <rect x="8" y="10" width="48" height="44" rx="4" fill="#14532d" stroke="url(#plcGrad)" stroke-width="2.5" />
  <path d="M20 10v44M32 10v44M44 10v44" stroke="url(#plcGrad)" stroke-width="2" />
  <circle cx="14" cy="20" r="2" fill="#22c55e" />
  <circle cx="14" cy="28" r="2" fill="#22c55e" />
  <circle cx="26" cy="20" r="2" fill="#ef4444" />
  <circle cx="38" cy="20" r="2" fill="#22c55e" />
</svg>`;

const RTU_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="rtuGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#a7f3d0" />
      <stop offset="100%" stop-color="#34d399" />
    </linearGradient>
  </defs>
  <rect x="10" y="14" width="44" height="38" rx="6" fill="#064e3b" stroke="url(#rtuGrad)" stroke-width="2.5" />
  <path d="M22 6v8M42 6v8M18 24h28M18 32h28" stroke="url(#rtuGrad)" stroke-width="2" stroke-linecap="round" />
  <circle cx="32" cy="42" r="3" fill="#34d399" />
</svg>`;

const STORAGE_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="stGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#94a3b8" />
      <stop offset="100%" stop-color="#64748b" />
    </linearGradient>
  </defs>
  <rect x="12" y="8" width="40" height="12" rx="2" fill="#1e293b" stroke="url(#stGrad)" stroke-width="2" />
  <rect x="12" y="26" width="40" height="12" rx="2" fill="#1e293b" stroke="url(#stGrad)" stroke-width="2" />
  <rect x="12" y="44" width="40" height="12" rx="2" fill="#1e293b" stroke="url(#stGrad)" stroke-width="2" />
  <circle cx="18" cy="14" r="1.5" fill="#38bdf8" />
  <circle cx="18" cy="32" r="1.5" fill="#38bdf8" />
  <circle cx="18" cy="50" r="1.5" fill="#38bdf8" />
  <path d="M42 14h6M42 32h6M42 50h6" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" />
</svg>`;

const VIRTUAL_MACHINE_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="vmGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#e879f9" />
      <stop offset="100%" stop-color="#d946ef" />
    </linearGradient>
  </defs>
  <rect x="6" y="24" width="24" height="24" rx="2" fill="#4a044e" stroke="url(#vmGrad)" stroke-width="2" />
  <rect x="34" y="24" width="24" height="24" rx="2" fill="#4a044e" stroke="url(#vmGrad)" stroke-width="2" />
  <rect x="20" y="8" width="24" height="12" rx="2" fill="#4a044e" stroke="url(#vmGrad)" stroke-width="2" />
  <path d="M32 20v4M18 36h4M46 36h4" stroke="url(#vmGrad)" stroke-width="2" />
</svg>`;

const MOBILE_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="mobGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#6ee7b7" />
      <stop offset="100%" stop-color="#10b981" />
    </linearGradient>
  </defs>
  <rect x="18" y="8" width="28" height="48" rx="6" fill="#064e3b" stroke="url(#mobGrad)" stroke-width="2.5" />
  <circle cx="32" cy="50" r="3" fill="#10b981" />
  <rect x="28" y="12" width="8" height="2" rx="1" fill="#6ee7b7" />
</svg>`;

const LOAD_BALANCER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="lbGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#fda4af" />
      <stop offset="100%" stop-color="#f43f5e" />
    </linearGradient>
  </defs>
  <circle cx="32" cy="32" r="26" fill="#4c0519" stroke="url(#lbGrad)" stroke-width="2.5" />
  <path d="M16 32h10M38 24l8-6M38 40l8 6" stroke="url(#lbGrad)" stroke-width="2.5" stroke-linecap="round" />
  <path d="M46 14v4h-4M46 50v-4h-4" fill="none" stroke="url(#lbGrad)" stroke-width="2.5" stroke-linejoin="round" />
</svg>`;

const MODEM_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="modGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#22d3ee" />
      <stop offset="100%" stop-color="#06b6d4" />
    </linearGradient>
  </defs>
  <rect x="10" y="24" width="44" height="24" rx="4" fill="#083344" stroke="url(#modGrad)" stroke-width="2.5" />
  <path d="M16 10v14M48 6v18" stroke="url(#modGrad)" stroke-width="2" stroke-linecap="round" />
  <circle cx="20" cy="36" r="2" fill="#22d3ee" />
  <circle cx="28" cy="36" r="2" fill="#22d3ee" />
  <circle cx="36" cy="36" r="2" fill="#22d3ee" />
</svg>`;

const UNKNOWN_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="unkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#cbd5e1" />
      <stop offset="100%" stop-color="#94a3b8" />
    </linearGradient>
  </defs>
  <circle cx="32" cy="32" r="26" fill="#1e293b" stroke="url(#unkGrad)" stroke-width="2" />
  <text x="32" y="42" font-family="'Inter', sans-serif" font-size="28" font-weight="bold" fill="#cbd5e1" text-anchor="middle">?</text>
</svg>`;

const SUBNET_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="subnetGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#22d3ee" />
      <stop offset="100%" stop-color="#0891b2" />
    </linearGradient>
  </defs>
  <path d="M18 38a10 10 0 0 1 0-20 14 14 0 0 1 27.5-3A10 10 0 0 1 46 38z" fill="#083344" stroke="url(#subnetGrad)" stroke-width="2.5" stroke-linejoin="round" />
  <ellipse cx="32" cy="26" rx="6" ry="2.5" fill="#0f172a" stroke="#22d3ee" stroke-width="1.5" />
  <path d="M26 26v4c0 1.38 2.68 2.5 6 2.5s6-1.12 6-2.5v-4" fill="none" stroke="#22d3ee" stroke-width="1.5" />
  <path d="M26 30v4c0 1.38 2.68 2.5 6 2.5s6-1.12 6-2.5v-4" fill="none" stroke="#22d3ee" stroke-width="1.5" />
</svg>`;

// Map of category ID to premium SVG string
const CATEGORY_SVGS = {
  router: ROUTER_SVG,
  switch: SWITCH_SVG,
  gateway: GATEWAY_SVG,
  firewall: FIREWALL_SVG,
  wireless_ap: WIRELESS_AP_SVG,
  server: SERVER_SVG,
  workstation: WORKSTATION_SVG,
  desktop: DESKTOP_SVG,
  laptop: LAPTOP_SVG,
  endpoint: ENDPOINT_SVG,
  printer: PRINTER_SVG,
  camera: CAMERA_SVG,
  iot: IOT_SVG,
  plc: PLC_SVG,
  rtu: RTU_SVG,
  storage: STORAGE_SVG,
  virtual_machine: VIRTUAL_MACHINE_SVG,
  mobile: MOBILE_SVG,
  load_balancer: LOAD_BALANCER_SVG,
  modem: MODEM_SVG,
  unknown: UNKNOWN_SVG,
  subnet: SUBNET_SVG,
};

const getSvgDataUrl = (svgStr) =>
  `data:image/svg+xml;base64,${window.btoa(svgStr.trim())}`;

const CATEGORY_LABELS = {
  router: "Router",
  switch: "Switch",
  gateway: "Gateway",
  firewall: "Firewall",
  wireless_ap: "Wireless AP",
  server: "Server",
  workstation: "Workstation",
  desktop: "Desktop PC",
  laptop: "Laptop",
  endpoint: "Endpoint",
  printer: "Printer",
  camera: "IP Camera",
  iot: "IoT Device",
  plc: "PLC",
  rtu: "RTU",
  storage: "NAS / Storage",
  virtual_machine: "Virtual Machine",
  mobile: "Mobile Device",
  load_balancer: "Load Balancer",
  modem: "Modem",
  unknown: "Unknown Device",
  host: "Host",
};

/** Format bits-per-second into a human-readable speed string. */
/* Edge colour by the evidence backing the link. LLDP, CDP and EDP all describe
 * a physical cable and share the topology palette; ARP is L3 reachability, and
 * anything weaker (FDB) stays neutral grey. EDP is Extreme's discovery protocol
 * and is the only neighbour source on an all-Extreme estate, so it must not
 * fall through to the generic colour. */
const LINK_TYPE_COLORS = {
  lldp: "#3b82f6",
  cdp: "#f59e0b",
  edp: "#a78bfa",
  arp: "#06b6d4",
  default: "#475569",
};

const formatSpeed = (bps) => {
  if (!bps || bps <= 0) return null;
  if (bps >= 1_000_000_000)
    return `${(bps / 1_000_000_000).toFixed(bps % 1_000_000_000 === 0 ? 0 : 1)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(0)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} Kbps`;
  return `${bps} bps`;
};

export default function NetworkMap() {
  const { scanId: paramScanId } = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scanId = paramScanId || searchParams.get("scan_id") || null;

  const containerRef = useRef(null);
  const networkRef = useRef(null);

  // Raw data from API
  const allNodesRef = useRef([]);
  const allEdgesRef = useRef([]);

  // vis-network mutable DataSets
  const dsNodesRef = useRef(null);
  const dsEdgesRef = useRef(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({
    nodes: 0,
    edges: 0,
    subnets: 0,
    hosts: 0,
  });

  // Sidebar / Control States
  const [subnets, setSubnets] = useState([]);
  const [expandedSubnets, setExpandedSubnets] = useState(new Set());
  const [filteredSubnets, setFilteredSubnets] = useState(new Set()); // Subnets that are HIDDEN
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedNode, setSelectedNode] = useState(null);
  const [endpointSearch, setEndpointSearch] = useState("");
  const [endpointPage, setEndpointPage] = useState(0);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState(false);
  const [selectedActionHelp, setSelectedActionHelp] = useState(null);

  const [subnetMask, setSubnetMask] = useState(24);
  const [layoutMode, setLayoutMode] = useState("hierarchical"); // "hierarchical" or "force"
  // Links accumulate across scans. An org-wide map with no freshness window is
  // the union of every adjacency ever recorded, decommissioned hosts included,
  // so it defaults to the last 30 days. A scan-specific map needs no window —
  // the scan already defines one.
  const [activeWithinDays, setActiveWithinDays] = useState(() =>
    paramScanId || searchParams.get("scan_id") ? 0 : 30,
  );
  const endpointPageSize = 50;

  // Declared before fetchTopology, which resets them on every load.
  const expandedSubnetsRef = useRef(new Set());
  const filteredSubnetsRef = useRef(new Set());

  /* ── Fetch topology data ──────────────────────────────────────────────── */
  const fetchTopology = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    expandedSubnetsRef.current = new Set();
    filteredSubnetsRef.current = new Set();
    setExpandedSubnets(new Set());
    setFilteredSubnets(new Set());
    try {
      const baseUrl = scanId ? `/topology/map/${scanId}` : "/topology/map";
      const params = new URLSearchParams({ subnet_mask: String(subnetMask) });
      if (activeWithinDays > 0) {
        params.set("active_within_days", String(activeWithinDays));
      }
      const { data } = await api.get(`${baseUrl}?${params.toString()}`);
      if (!data.success) throw new Error("Failed to load topology data");

      allNodesRef.current = data.nodes || [];
      allEdgesRef.current = data.edges || [];
      setSubnets(data.subnets || []);

      setStats({
        nodes: (data.nodes || []).filter((n) => n.tier !== "host").length,
        edges: (data.edges || []).length,
        subnets: (data.subnets || []).length,
        hosts: data.stats?.hosts || 0,
      });
    } catch (err) {
      const msg =
        err.response?.data?.detail || err.message || "Failed to load topology";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [scanId, subnetMask, activeWithinDays]);

  useEffect(() => {
    fetchTopology();
  }, [fetchTopology]);

  const isMacOnlySubnet = useCallback((subnetOrId) => {
    const value = String(subnetOrId || "").replace(/^subnet:/, "");
    return value === "MAC-Only / FDB";
  }, []);

  const selectedEndpoints = useMemo(() => {
    if (!selectedNode || selectedNode.tier !== "subnet") return [];
    const subnet = selectedNode.subnet;
    const query = endpointSearch.trim().toLowerCase();
    return allNodesRef.current
      .filter((node) => node.tier === "host" && node.subnet === subnet)
      .filter((node) => {
        if (!query) return true;
        return [
          node.label,
          node.ip,
          node.mac,
          node.vendor,
          node.source_port,
          node.source_port_desc,
          node.link_type,
          node.vlan_id ? String(node.vlan_id) : "",
          node.speed_bps ? formatSpeed(node.speed_bps) : "",
        ].some((value) =>
          String(value || "")
            .toLowerCase()
            .includes(query),
        );
      });
  }, [selectedNode, endpointSearch]);

  const pagedEndpoints = useMemo(() => {
    const start = endpointPage * endpointPageSize;
    return selectedEndpoints.slice(start, start + endpointPageSize);
  }, [selectedEndpoints, endpointPage]);

  const topologyQuality = useMemo(() => {
    const nodes = allNodesRef.current || [];
    const edges = allEdgesRef.current || [];
    const hostNodes = nodes.filter((node) => node.tier === "host");
    const macOnly = hostNodes.filter((node) =>
      isMacOnlySubnet(node.subnet),
    ).length;
    const ipResolved = hostNodes.filter((node) => node.ip).length;
    // `source_key` is the identity of the device that observed the endpoint —
    // a MAC, `ip:<addr>` or `name:<label>` depending on what SNMP could resolve.
    const sources = new Set(
      hostNodes.map((node) => node.source_key).filter(Boolean),
    );
    // Count every protocol that backed a link, not just the strongest one: an
    // adjacency reported as "lldp" may also have been corroborated by ARP.
    const linkTypes = new Set();
    edges.forEach((edge) => {
      String(edge.observed_types || edge.link_type || "")
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
        .forEach((t) => linkTypes.add(t));
      Object.keys(edge.link_details?.type_counts || {}).forEach((t) =>
        linkTypes.add(t),
      );
    });
    return {
      macOnly,
      ipResolved,
      sources: sources.size,
      hasArp: linkTypes.has("arp"),
      hasFdb: linkTypes.has("fdb"),
      // EDP counts as neighbour discovery: on an all-Extreme network it is
      // the only protocol reporting physical adjacency, and reporting
      // "LLDP/CDP unavailable" there would be misleading.
      hasLldpOrCdp:
        linkTypes.has("lldp") || linkTypes.has("cdp") || linkTypes.has("edp"),
    };
  }, [stats, subnets, isMacOnlySubnet]);

  const handleActionClick = useCallback((action) => {
    switch (action) {
      case "Run ARP-enabled scan":
        setSelectedActionHelp({
          title: "🚀 Run ARP-enabled Scan",
          content: (
            <div>
              <p>
                To resolve MAC addresses to IP addresses, configure a new scan
                targeting your network subnets with SNMP enabled.
              </p>
              <p style={{ marginTop: "12px" }}>
                Ensure you select <strong>🗺️ Network Topology (SNMP)</strong>{" "}
                during setup and specify your router credentials.
              </p>
            </div>
          ),
          actionUrl: "/scan/new",
          actionLabel: "Configure Scan Now",
        });
        break;
      case "Add gateway/router SNMP target":
        setSelectedActionHelp({
          title: "🔌 Add SNMP target",
          content: (
            <div>
              <p>
                Add the default gateway router IP to your SNMP targets. The
                topology engine queries the gateway's ARP table to associate MAC
                addresses with their host IP addresses.
              </p>
              <p style={{ marginTop: "12px" }}>
                Go to the scan setup screen to add your network router IPs as
                scan targets.
              </p>
            </div>
          ),
          actionUrl: "/scan/new",
          actionLabel: "Go to Scan Setup",
        });
        break;
      case "Enable ARP table collection":
        setSelectedActionHelp({
          title: "🔍 Enable ARP Table Collection",
          content: (
            <div>
              <p>
                ARP (Address Resolution Protocol) mappings are critical to
                connect L2 physical switchports to L3 IP networks.
              </p>
              <p style={{ marginTop: "12px" }}>To resolve this:</p>
              <ol style={{ paddingLeft: "20px", marginTop: "8px" }}>
                <li>Configure your gateway router to allow SNMP access.</li>
                <li>
                  Ensure the router's SNMP configuration allows access to the
                  standard IP-MIB ARP table (OID <code>1.3.6.1.2.1.4.22</code>).
                </li>
                <li>
                  Add the router IP address as a target in your next scan with
                  corresponding SNMP credentials.
                </li>
              </ol>
            </div>
          ),
        });
        break;
      case "Enable LLDP/CDP on infrastructure devices":
        setSelectedActionHelp({
          title: "🌐 Enable LLDP/CDP Link Discovery",
          content: (
            <div>
              <p>
                Physical topology mapping depends on Link Layer Discovery
                Protocol (LLDP) or Cisco Discovery Protocol (CDP) to discover
                neighbor links between managed switches.
              </p>
              <p style={{ marginTop: "12px" }}>
                How to enable this on your infrastructure:
              </p>
              <ul
                style={{
                  paddingLeft: "20px",
                  marginTop: "8px",
                  listStyleType: "disc",
                }}
              >
                <li>
                  <strong>Cisco Switches/Routers:</strong> Enter global
                  configuration mode and execute <code>cdp run</code> or{" "}
                  <code>lldp run</code>.
                </li>
                <li>
                  <strong>Other Managed Switches:</strong> Log in to your switch
                  administration portal and enable LLDP globally and on all
                  uplink/downlink trunk ports.
                </li>
              </ul>
            </div>
          ),
        });
        break;
      case "Correlate with asset inventory":
        setSelectedActionHelp({
          title: "📋 Correlate with Asset Inventory",
          content: (
            <div>
              <p>
                Some endpoints are listed as MAC-only because they haven't been
                resolved to active IP addresses or matched with registered
                corporate assets.
              </p>
              <p style={{ marginTop: "12px" }}>
                Ensure these devices are properly registered in your asset
                management system, or run a credentialed scan to automatically
                match active hosts.
              </p>
            </div>
          ),
          actionUrl: "/assets",
          actionLabel: "View Asset Registry",
        });
        break;
      default:
        break;
    }
  }, []);

  // Subnet expand/collapse logic
  const formatNode = useCallback(
    (n) => {
      if (n.tier === "subnet") {
        const isExpanded = expandedSubnetsRef.current.has(n.id);
        const isMacOnly = isMacOnlySubnet(n.subnet);

        return {
          id: n.id,
          label: isMacOnly
            ? `MAC-only endpoints\n${n.host_count} devices`
            : isExpanded
              ? n.subnet
              : `${n.subnet}\n(${n.host_count} hosts)`,
          shape: "image",
          image: getSvgDataUrl(SUBNET_SVG),
          size: isMacOnly ? 42 : 36,
          font: {
            color: "#22d3ee",
            size: 11,
            bold: true,
            face: "Inter, sans-serif",
            strokeWidth: 3,
            strokeColor: "#0f172a",
            vadjust: 34,
          },
          level: 2,
          title: isMacOnly
            ? `MAC-only endpoint cluster\nDevices: ${n.host_count}\nClick to inspect evidence`
            : `${n.subnet}\nHosts: ${n.host_count}\nClick node to ${isExpanded ? "collapse" : "expand"}`,
          _data: n,
        };
      }

      const group = n.group || "unknown";
      const nodeImage = getSvgDataUrl(
        CATEGORY_SVGS[group] || CATEGORY_SVGS.unknown,
      );
      const themeColor = GROUP_COLORS[group]?.border || "#cbd5e1";

      if (n.tier === "host") {
        return {
          id: n.id,
          label: n.label || n.ip || n.id,
          shape: "image",
          image: nodeImage,
          size: 26,
          font: {
            color: "#cbd5e1",
            size: 9,
            face: "Inter, sans-serif",
            strokeWidth: 2,
            strokeColor: "#0f172a",
            vadjust: 26,
          },
          level: 3,
          title: `Host: ${n.label}\nIP: ${n.ip || "—"}\nMAC: ${n.mac || "—"}\nSubnet: ${n.subnet || "—"}\nType: ${group}`,
          _data: n,
        };
      }

      // Dynamic infrastructure node formatting (routers, switches, gateways, firewalls, etc.)
      let nodeSize = 34;
      let nodeLevel = 1;

      if (group === "router" || group === "gateway") {
        nodeSize = 42;
        nodeLevel = 0;
      } else if (
        group === "switch" ||
        group === "firewall" ||
        group === "load_balancer" ||
        group === "modem"
      ) {
        nodeSize = 38;
        nodeLevel = 1;
      } else {
        nodeSize = 34;
        nodeLevel = 2; // servers / storage / virtual machines / etc.
      }

      return {
        id: n.id,
        label: n.label || n.ip || n.mac,
        shape: "image",
        image: nodeImage,
        font: {
          color: themeColor,
          size: 13,
          bold: true,
          face: "Inter, sans-serif",
          strokeWidth: 3,
          strokeColor: "#0f172a",
          vadjust: 36,
        },
        size: nodeSize,
        level: nodeLevel,
        title: `${n.label}\nIP: ${n.ip || "—"}\nMAC: ${n.mac || "—"}\nType: ${group}`,
        _data: n,
      };
    },
    [isMacOnlySubnet],
  );

  /* ── Filter / Sync Viewable Graph ─────────────────────────────────────────── */
  const syncGraphView = useCallback(() => {
    if (!dsNodesRef.current || !dsEdgesRef.current) return;

    // Filter subnets out
    const visibleSubnetNodes = allNodesRef.current.filter(
      (n) => n.tier === "subnet" && !filteredSubnetsRef.current.has(n.subnet),
    );

    const visibleInfraNodes = allNodesRef.current.filter(
      (n) => n.tier === "infra",
    );

    // Auto-expand subnets if there is an active search query matching their children
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const subnetsToExpand = new Set();
      allNodesRef.current.forEach((n) => {
        if (n.tier === "host" && n.subnet && !isMacOnlySubnet(n.subnet)) {
          const match =
            (n.label || "").toLowerCase().includes(q) ||
            (n.ip || "").toLowerCase().includes(q) ||
            (n.mac || "").toLowerCase().includes(q);
          if (match) {
            subnetsToExpand.add(`subnet:${n.subnet}`);
          }
        }
      });
      subnetsToExpand.forEach((sId) => {
        expandedSubnetsRef.current.add(sId);
      });
      // Synchronize back to react state to update buttons
      setExpandedSubnets(new Set(expandedSubnetsRef.current));
    }

    // Reconstruct list of nodes
    const finalNodes = [...visibleInfraNodes, ...visibleSubnetNodes].map(
      formatNode,
    );

    // Get current expanded subnets that are still visible
    const activeExpanded = Array.from(expandedSubnetsRef.current).filter(
      (sNodeId) => {
        const sub = sNodeId.replace("subnet:", "");
        return !filteredSubnetsRef.current.has(sub) && !isMacOnlySubnet(sub);
      },
    );

    const activeHosts = [];
    const activeHostEdges = [];

    activeExpanded.forEach((sNodeId) => {
      const subnetStr = sNodeId.replace("subnet:", "");
      let subnetHosts = allNodesRef.current.filter(
        (n) => n.tier === "host" && n.subnet === subnetStr,
      );

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        subnetHosts = subnetHosts.filter(
          (h) =>
            (h.label || "").toLowerCase().includes(q) ||
            (h.ip || "").toLowerCase().includes(q) ||
            (h.mac || "").toLowerCase().includes(q),
        );
      }

      // Limit to 50 hosts maximum for performance
      const capped = subnetHosts.slice(0, 50);
      capped.forEach((h) => {
        activeHosts.push(formatNode(h));
        activeHostEdges.push({
          id: `edge:host:${h.id}`,
          from: sNodeId,
          to: h.id,
          color: { color: "#475569" },
          width: 1,
          smooth: { type: "continuous" },
        });
      });
    });

    // Re-populate DataSet.
    // vis-network's DataSet throws on a duplicate id and the exception unwinds
    // the whole render, blanking the map. The backend guarantees unique ids;
    // this keeps one bad payload from costing the user the entire view.
    const seenNodeIds = new Set();
    const uniqueNodes = [];
    let droppedNodes = 0;
    [...finalNodes, ...activeHosts].forEach((node) => {
      if (node?.id == null || seenNodeIds.has(node.id)) {
        droppedNodes += 1;
        return;
      }
      seenNodeIds.add(node.id);
      uniqueNodes.push(node);
    });
    if (droppedNodes) {
      console.warn(
        `NetworkMap: dropped ${droppedNodes} duplicate/invalid node(s) from the topology payload`,
      );
    }

    dsNodesRef.current.clear();
    dsNodesRef.current.add(uniqueNodes);

    // Build edges (infra-to-infra and infra-to-subnet)
    const validNodeIds = new Set(dsNodesRef.current.getIds());
    const seenEdgeIds = new Set();
    const visibleEdges = allEdgesRef.current
      .filter((e) => {
        if (!validNodeIds.has(e.from)) return false;
        if (!validNodeIds.has(e.to)) return false;
        if (e.id == null || seenEdgeIds.has(e.id)) return false;
        seenEdgeIds.add(e.id);
        return true;
      })
      .map((e) => {
        const hostCount = e.host_count || 1;
        // Dynamic thickness: base on speed for infra edges, log-proportional for subnet edges
        let thickness;
        if (e.tier === "subnet") {
          thickness = Math.max(1.5, Math.min(8, Math.log(hostCount + 1) * 1.8));
        } else if (e.speed_bps) {
          // Scale: 100Mbps=2, 1Gbps=3, 10Gbps=5
          thickness = Math.max(
            2,
            Math.min(6, Math.log10(e.speed_bps / 100_000_000 + 1) * 2.5 + 2),
          );
        } else {
          thickness = 2.5;
        }

        const speedLabel = formatSpeed(e.speed_bps);
        const details = e.link_details;
        let hoverTitle;
        if (e.tier === "subnet" && details) {
          hoverTitle = `Subnet Edge Details:\n• Hosts: ${e.host_count}\n• Distribution: ${details.summary}\n• Source Ports: ${e.source_port}`;
        } else {
          const parts = [`Link Type: ${e.link_type || "physical"}`];
          if (e.source_port_desc) parts.push(`Source: ${e.source_port_desc}`);
          else if (e.source_port) parts.push(`Source Port: ${e.source_port}`);
          if (e.target_port_desc) parts.push(`Target: ${e.target_port_desc}`);
          else if (e.target_port) parts.push(`Target Port: ${e.target_port}`);
          if (e.vlan_id) parts.push(`VLAN: ${e.vlan_id}`);
          if (speedLabel) parts.push(`Speed: ${speedLabel}`);
          hoverTitle = parts.join("\n");
        }

        return {
          id: e.id,
          from: e.from,
          to: e.to,
          label: e.label || "",
          width: thickness,
          color: {
            color: LINK_TYPE_COLORS[e.link_type] || LINK_TYPE_COLORS.default,
            highlight: "#60a5fa",
          },
          dashes: e.speed_bps && e.speed_bps < 100_000_000 ? [5, 5] : false,
          smooth: { type: "continuous" },
          font: { size: 9, color: "var(--text-faint)", strokeWidth: 0 },
          title: hoverTitle,
        };
      });

    dsEdgesRef.current.clear();
    dsEdgesRef.current.add([...visibleEdges, ...activeHostEdges]);

    // Update displayed node stats count
    setStats((prev) => ({
      ...prev,
      nodes: dsNodesRef.current.length,
      edges: dsEdgesRef.current.length,
    }));
  }, [searchQuery, formatNode, isMacOnlySubnet]);

  // Expand/collapse and filter handlers call syncGraphView outside the
  // initialisation try/catch, so a render failure there would surface as an
  // unhandled exception rather than a message the user can act on.
  const safeSyncGraphView = useCallback(() => {
    try {
      syncGraphView();
    } catch (err) {
      console.error("NetworkMap: failed to render topology view", err);
      setError("Failed to render the topology view. Try reloading the map.");
    }
  }, [syncGraphView]);

  /* ── Subnet Expand / Collapse Logic ────────────────────────────────────────── */
  const expandSubnet = useCallback(
    (subnetNodeId) => {
      expandedSubnetsRef.current.add(subnetNodeId);
      setExpandedSubnets(new Set(expandedSubnetsRef.current));
      safeSyncGraphView();
    },
    [safeSyncGraphView],
  );

  const collapseSubnet = useCallback(
    (subnetNodeId) => {
      expandedSubnetsRef.current.delete(subnetNodeId);
      setExpandedSubnets(new Set(expandedSubnetsRef.current));
      safeSyncGraphView();
    },
    [safeSyncGraphView],
  );

  /* ── Search Apply ────────────────────────────────────────────────────────── */
  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  useEffect(() => {
    safeSyncGraphView();
  }, [searchQuery, safeSyncGraphView]);

  /* ── Initialise vis-network canvas ────────────────────────────────────────── */
  useEffect(() => {
    if (
      loading ||
      error ||
      !allNodesRef.current.length ||
      !containerRef.current
    )
      return;

    const initNetwork = () => {
      try {
        dsNodesRef.current = new DataSet([]);
        dsEdgesRef.current = new DataSet([]);

        safeSyncGraphView();

        const isHierarchical = layoutMode === "hierarchical";

        const options = {
          nodes: {
            borderWidth: 2,
            borderWidthSelected: 3,
            shadow: {
              enabled: true,
              color: "rgba(0, 0, 0, 0.4)",
              size: 6,
              x: 0,
              y: 4,
            },
          },
          layout: {
            hierarchical: {
              enabled: isHierarchical,
              direction: "UD",
              sortMethod: "directed",
              levelSeparation: 150,
              nodeSpacing: 140,
              treeSpacing: 220,
              blockShifting: true,
              edgeMinimization: true,
              parentCentralization: true,
            },
          },
          physics: {
            enabled: !isHierarchical,
            barnesHut: {
              gravitationalConstant: -1800,
              centralGravity: 0.25,
              springLength: 90,
              springConstant: 0.04,
              damping: 0.09,
              avoidOverlap: 1,
            },
            stabilization: {
              enabled: true,
              iterations: 150,
              updateInterval: 25,
            },
          },
          interaction: {
            hover: true,
            tooltipDelay: 150,
            zoomView: true,
            dragView: true,
            navigationButtons: true,
          },
        };

        if (networkRef.current) {
          networkRef.current.destroy();
        }

        const network = new Network(
          containerRef.current,
          { nodes: dsNodesRef.current, edges: dsEdgesRef.current },
          options,
        );
        networkRef.current = network;

        setTimeout(() => {
          if (networkRef.current) {
            networkRef.current.fit({
              animation: { duration: 400, easingFunction: "easeInOutQuad" },
            });
          }
        }, 300);

        network.on("click", (params) => {
          if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = dsNodesRef.current.get(nodeId);
            if (node) {
              if (node._data.tier === "subnet") {
                setSelectedNode(node._data);
                setEndpointSearch("");
                setEndpointPage(0);
                if (isMacOnlySubnet(node._data.subnet)) {
                  return;
                }
                if (expandedSubnetsRef.current.has(nodeId)) {
                  collapseSubnet(nodeId);
                } else {
                  expandSubnet(nodeId);
                }
              } else {
                setSelectedNode(node._data);
              }
            }
          } else {
            setSelectedNode(null);
          }
        });
      } catch (err) {
        console.error("Failed to load vis-network:", err);
        setError("Failed to load network engine.");
      }
    };

    initNetwork();

    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
  }, [loading, error, layoutMode, fetchTopology]);

  /* ── Sidebar Filters ─────────────────────────────────────────────────────── */
  const toggleSubnetFilter = (subnet) => {
    if (filteredSubnetsRef.current.has(subnet)) {
      filteredSubnetsRef.current.delete(subnet);
    } else {
      filteredSubnetsRef.current.add(subnet);
      expandedSubnetsRef.current.delete(`subnet:${subnet}`);
    }
    setFilteredSubnets(new Set(filteredSubnetsRef.current));
    setExpandedSubnets(new Set(expandedSubnetsRef.current));
    safeSyncGraphView();
  };

  const selectAllSubnets = () => {
    filteredSubnetsRef.current = new Set();
    setFilteredSubnets(new Set());
    safeSyncGraphView();
  };

  const deselectAllSubnets = () => {
    filteredSubnetsRef.current = new Set(subnets);
    setFilteredSubnets(new Set(subnets));
    safeSyncGraphView();
  };

  /* ── Fit / View Controls ────────────────────────────────────────────────── */
  const handleFit = () => {
    if (networkRef.current) {
      networkRef.current.fit({ animation: { duration: 400 } });
    }
  };

  const handleExpandAll = () => {
    const visibleSubnets = subnets.filter(
      (s) => !filteredSubnetsRef.current.has(s) && !isMacOnlySubnet(s),
    );
    if (visibleSubnets.length > 15) {
      if (
        !window.confirm(
          "Expanding more than 15 subnets simultaneously may slow down the view. Continue?",
        )
      ) {
        return;
      }
    }
    const nextExpanded = new Set(expandedSubnetsRef.current);
    visibleSubnets.forEach((s) => {
      nextExpanded.add(`subnet:${s}`);
    });
    expandedSubnetsRef.current = nextExpanded;
    setExpandedSubnets(new Set(nextExpanded));
    safeSyncGraphView();
  };

  const handleCollapseAll = () => {
    expandedSubnetsRef.current = new Set();
    setExpandedSubnets(new Set());
    safeSyncGraphView();
  };

  const legendItems = useMemo(() => {
    const activeGroups = new Set();
    allNodesRef.current.forEach((node) => {
      if (node.tier === "infra" || node.tier === "host") {
        activeGroups.add(node.group || "endpoint");
      }
    });
    return Array.from(activeGroups)
      .map((g) => ({
        group: g,
        label: CATEGORY_LABELS[g] || g.charAt(0).toUpperCase() + g.slice(1),
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [allNodesRef.current]);

  return (
    <AppLayout>
      <div className="nmap-container">
        {/* Header */}
        <div className="nmap-header">
          <div className="nmap-title-group">
            <h1 className="nmap-title">🗺️ Network Topology Map</h1>
            <span className="nmap-subtitle">
              {scanId ? `Scan ID: ${scanId}` : "Corporate network architecture"}
            </span>
          </div>
          <div className="nmap-header-actions">
            <div className="nmap-stats">
              <span className="nmap-stat">
                <span className="nmap-stat-num">{stats.nodes}</span> Visible
                Nodes
              </span>
              <span className="nmap-stat-divider">•</span>
              <span className="nmap-stat">
                <span className="nmap-stat-num">{stats.hosts}</span> Total Hosts
              </span>
            </div>
            <button
              className="nmap-btn nmap-btn--refresh"
              onClick={fetchTopology}
              disabled={loading}
            >
              {loading ? "Syncing..." : "↻ Refresh"}
            </button>
          </div>
        </div>

        {/* Global Controls Panel */}
        <div className="nmap-controls-bar">
          <div className="nmap-controls-left">
            <button
              className="nmap-control-btn"
              onClick={handleFit}
              title="Fit Entire Network View"
            >
              🔍 Fit Screen
            </button>
            <button
              className="nmap-control-btn"
              onClick={handleExpandAll}
              title="Expand All Visible Subnets"
            >
              📂 Expand All
            </button>
            <button
              className="nmap-control-btn"
              onClick={handleCollapseAll}
              title="Collapse All Subnets"
            >
              📁 Collapse All
            </button>

            {/* Configurable Subnet size selection */}
            <div className="nmap-control-select-group">
              <span className="nmap-control-select-label">Subnet Mask:</span>
              <select
                value={subnetMask}
                onChange={(e) => setSubnetMask(Number(e.target.value))}
                className="nmap-control-select"
                title="Regroup network topology by mask bits"
              >
                <option value={16}>Class B (/16)</option>
                <option value={22}>Class C Extended (/22)</option>
                <option value={23}>Class C Extended (/23)</option>
                <option value={24}>Class C (/24)</option>
              </select>
            </div>

            {/* Freshness window — keeps decommissioned adjacency out of the map */}
            {!scanId && (
              <div className="nmap-control-select-group">
                <span className="nmap-control-select-label">Seen within:</span>
                <select
                  value={activeWithinDays}
                  onChange={(e) => setActiveWithinDays(Number(e.target.value))}
                  className="nmap-control-select"
                  title="Only show links observed within this window"
                >
                  <option value={7}>Last 7 days</option>
                  <option value={30}>Last 30 days</option>
                  <option value={90}>Last 90 days</option>
                  <option value={0}>All recorded history</option>
                </select>
              </div>
            )}

            {/* Layout Mode selection */}
            <div className="nmap-control-select-group">
              <span className="nmap-control-select-label">Layout:</span>
              <select
                value={layoutMode}
                onChange={(e) => setLayoutMode(e.target.value)}
                className="nmap-control-select"
                title="Switch layout styling engine"
              >
                <option value="hierarchical">Hierarchy</option>
                <option value="force">Force-Directed</option>
              </select>
            </div>
          </div>
          <div className="nmap-controls-right">
            <input
              type="text"
              placeholder="Search IP, Hostname, MAC..."
              value={searchQuery}
              onChange={handleSearchChange}
              className="nmap-search-input"
            />
          </div>
        </div>

        <div
          className="nmap-quality-strip"
          role="status"
          aria-label="Topology data quality summary"
        >
          <div className="nmap-quality-item">
            <span className="nmap-quality-value">
              {topologyQuality.macOnly}
            </span>
            <span className="nmap-quality-label">MAC-only endpoints</span>
          </div>
          <div className="nmap-quality-item">
            <span className="nmap-quality-value">
              {topologyQuality.ipResolved}
            </span>
            <span className="nmap-quality-label">IPs resolved</span>
          </div>
          <div className="nmap-quality-item">
            <span className="nmap-quality-value">
              {topologyQuality.sources}
            </span>
            <span className="nmap-quality-label">Topology sources</span>
          </div>
          <div
            className={`nmap-quality-pill ${topologyQuality.hasArp ? "is-good" : "is-warn"}`}
          >
            {topologyQuality.hasArp ? "ARP present" : "ARP missing"}
          </div>
          <div
            className={`nmap-quality-pill ${topologyQuality.hasLldpOrCdp ? "is-good" : "is-warn"}`}
          >
            {topologyQuality.hasLldpOrCdp
              ? "Neighbour discovery present"
              : "No neighbour discovery (LLDP/CDP/EDP)"}
          </div>
        </div>

        {/* Main content layout */}
        <div className="nmap-body">
          {/* Graph canvas */}
          <div
            className="nmap-graph-wrapper"
            role="region"
            aria-label="Interactive Topology Map View"
          >
            {loading && (
              <div className="nmap-loading">
                <div className="nmap-spinner" />
                <span>Loading topology nodes...</span>
              </div>
            )}
            {error && (
              <div className="nmap-error">
                <span className="nmap-error-icon">⚠️</span>
                <span>{error}</span>
                <button
                  className="nmap-btn nmap-btn--retry"
                  onClick={fetchTopology}
                  aria-label="Retry loading network topology map"
                >
                  Retry
                </button>
              </div>
            )}
            {!loading && !error && allNodesRef.current.length === 0 && (
              <div className="nmap-empty">
                <span className="nmap-empty-icon">🔍</span>
                <h3>No Network Nodes Discovered</h3>
                <p>
                  Run a network scan configured with SNMP to view the device
                  hierarchy.
                </p>
              </div>
            )}
            <div
              ref={containerRef}
              className="nmap-canvas"
              style={{
                display:
                  loading || error || allNodesRef.current.length === 0
                    ? "none"
                    : "block",
              }}
            />
          </div>

          {/* Sidebar for Filters & Detail Display */}
          <div
            className="nmap-sidebar"
            role="complementary"
            aria-label="Topology controls and metadata sidebar"
          >
            {/* Subnet Filtering Checkboxes */}
            <div className="nmap-filter-card">
              <h3 className="nmap-legend-title">Subnets ({subnets.length})</h3>
              <div className="nmap-filter-actions">
                <button
                  onClick={selectAllSubnets}
                  className="nmap-filter-link"
                  aria-label="Select all subnets to view on graph"
                >
                  Select All
                </button>
                <span className="nmap-filter-divider">|</span>
                <button
                  onClick={deselectAllSubnets}
                  className="nmap-filter-link"
                  aria-label="Deselect and hide all subnets on graph"
                >
                  Clear
                </button>
              </div>
              <div
                className="nmap-subnet-list"
                role="group"
                aria-label="Subnet filter list checkbox elements"
              >
                {subnets.map((subnet) => (
                  <label key={subnet} className="nmap-subnet-checkbox-item">
                    <input
                      type="checkbox"
                      checked={!filteredSubnets.has(subnet)}
                      onChange={() => toggleSubnetFilter(subnet)}
                      aria-label={`Toggle visibility of subnet ${subnet}`}
                    />
                    <span className="nmap-subnet-label">{subnet}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Legend */}
            <div className="nmap-legend-card">
              <h3 className="nmap-legend-title">Device Types</h3>
              {legendItems.map((item) => (
                <div key={item.group} className="nmap-legend-item">
                  <span
                    className="nmap-legend-dot"
                    style={{
                      background:
                        GROUP_COLORS[item.group]?.background || "#64748b",
                    }}
                  />
                  <span className="nmap-legend-label">{item.label}</span>
                </div>
              ))}
            </div>

            {/* Node metadata info */}
            {selectedNode && (
              <div className="nmap-detail-card nmap-detail-card--wide">
                <h3 className="nmap-detail-title">
                  {selectedNode.label || selectedNode.id}
                </h3>
                <div className="nmap-detail-rows">
                  {selectedNode.ip && (
                    <div className="nmap-detail-row">
                      <span className="nmap-detail-key">IP</span>
                      <span className="nmap-detail-val">{selectedNode.ip}</span>
                    </div>
                  )}
                  {selectedNode.mac && (
                    <div className="nmap-detail-row">
                      <span className="nmap-detail-key">MAC</span>
                      <span
                        className="nmap-detail-val"
                        style={{ fontFamily: "var(--mono)" }}
                      >
                        {selectedNode.mac}
                      </span>
                    </div>
                  )}
                  <div className="nmap-detail-row">
                    <span className="nmap-detail-key">Tier</span>
                    <span
                      className="nmap-detail-val"
                      style={{ textTransform: "capitalize" }}
                    >
                      {selectedNode.tier || "host"}
                    </span>
                  </div>
                  {selectedNode.subnet && (
                    <div className="nmap-detail-row">
                      <span className="nmap-detail-key">Subnet</span>
                      <span className="nmap-detail-val">
                        {selectedNode.subnet}
                      </span>
                    </div>
                  )}
                  {selectedNode.tier === "subnet" && (
                    <div className="nmap-detail-row">
                      <span className="nmap-detail-key">Total Hosts</span>
                      <span className="nmap-detail-val">
                        {selectedNode.host_count}
                      </span>
                    </div>
                  )}
                  {selectedNode.tier === "subnet" &&
                    selectedNode.host_count > 50 && (
                      <div
                        className="nmap-capped-warning"
                        style={{
                          fontSize: "0.75rem",
                          color: "#f59e0b",
                          marginTop: "8px",
                        }}
                      >
                        ⚠️ Capped at 50 hosts on graph for layout visibility.
                        Use the search bar to locate specific hosts in this
                        subnet.
                      </div>
                    )}
                </div>
                {selectedNode.tier === "subnet" &&
                  selectedNode.data_quality && (
                    <div className="nmap-quality-grid">
                      <div>
                        <strong>{selectedNode.data_quality.mac_only}</strong>
                        <span>MAC-only</span>
                      </div>
                      <div>
                        <strong>{selectedNode.data_quality.ip_resolved}</strong>
                        <span>IP resolved</span>
                      </div>
                      <div>
                        <strong>
                          {selectedNode.data_quality.asset_matches}
                        </strong>
                        <span>asset matches</span>
                      </div>
                      <div>
                        <strong>
                          {selectedNode.data_quality.source_count}
                        </strong>
                        <span>sources</span>
                      </div>
                    </div>
                  )}

                {selectedNode.tier === "subnet" && (
                  <div className="nmap-endpoint-panel">
                    <button
                      className="nmap-btn--evidence-modal"
                      onClick={() => {
                        setEndpointSearch("");
                        setEndpointPage(0);
                        setIsEvidenceModalOpen(true);
                      }}
                      title="Open detailed endpoint evidence table in overlay"
                    >
                      📊 View Endpoint Evidence ({selectedEndpoints.length}{" "}
                      devices)
                    </button>
                    {!!selectedNode.recommended_actions?.length && (
                      <div
                        className="nmap-actions-panel"
                        style={{ marginTop: "12px" }}
                      >
                        <strong>Recommended Next Actions</strong>
                        {selectedNode.recommended_actions.map((action) => (
                          <button
                            key={action}
                            type="button"
                            className="nmap-action-btn"
                            onClick={() => handleActionClick(action)}
                            aria-label={`Click to learn how to resolve: ${action}`}
                          >
                            {action}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {selectedNode.asset_id && (
                  <button
                    className="nmap-btn nmap-btn--asset"
                    onClick={() => navigate(`/assets/${selectedNode.asset_id}`)}
                    aria-label={`View asset details for ${selectedNode.label}`}
                  >
                    View Asset Details →
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {isEvidenceModalOpen &&
        selectedNode &&
        selectedNode.tier === "subnet" && (
          <Modal
            isOpen={isEvidenceModalOpen}
            onClose={() => setIsEvidenceModalOpen(false)}
            title={`📊 Endpoint Evidence — ${selectedNode.subnet === "MAC-Only / FDB" ? "MAC-Only / FDB Cluster" : selectedNode.subnet}`}
            size="large"
          >
            <div className="nmap-endpoint-head">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  width: "100%",
                }}
              >
                <div>
                  <strong>Subnet Device List</strong>
                  <span>
                    Showing{" "}
                    {pagedEndpoints.length
                      ? endpointPage * endpointPageSize + 1
                      : 0}
                    -
                    {Math.min(
                      (endpointPage + 1) * endpointPageSize,
                      selectedEndpoints.length,
                    )}{" "}
                    of {selectedEndpoints.length}
                  </span>
                </div>
              </div>
              <div className="nmap-modal-mini-stats">
                <div className="mini-stat-badge">
                  <span className="mini-stat-label">Total Devices:</span>
                  <span className="mini-stat-val">
                    {selectedEndpoints.length}
                  </span>
                </div>
                <div className="mini-stat-badge">
                  <span className="mini-stat-label">IPs Resolved:</span>
                  <span className="mini-stat-val">
                    {selectedEndpoints.filter((e) => e.ip).length}
                  </span>
                </div>
                <div className="mini-stat-badge">
                  <span className="mini-stat-label">Asset Matches:</span>
                  <span className="mini-stat-val is-match-count">
                    {
                      selectedEndpoints.filter(
                        (e) => e.asset_match_status === "matched",
                      ).length
                    }
                  </span>
                </div>
              </div>
              <input
                className="nmap-endpoint-search"
                value={endpointSearch}
                onChange={(event) => {
                  setEndpointSearch(event.target.value);
                  setEndpointPage(0);
                }}
                placeholder="Search MAC, vendor, port, description, speed, VLAN..."
                aria-label="Search endpoint evidence"
              />
            </div>
            <div
              className="nmap-endpoint-table"
              role="table"
              aria-label="Endpoint evidence table"
            >
              <div
                className="nmap-endpoint-row nmap-endpoint-row--head"
                role="row"
              >
                <span>MAC</span>
                <span>IP</span>
                <span>Hostname</span>
                <span>Vendor</span>
                <span>Port</span>
                <span>Port Description</span>
                <span>VLAN</span>
                <span>Speed</span>
                <span>Source</span>
                <span>Asset</span>
              </div>
              {pagedEndpoints.map((endpoint) => {
                const hasResolvedHostname =
                  endpoint.label &&
                  endpoint.label !== endpoint.ip &&
                  endpoint.label !== endpoint.mac;
                return (
                  <div
                    className="nmap-endpoint-row"
                    role="row"
                    key={endpoint.id}
                  >
                    <span title={endpoint.mac}>
                      {endpoint.mac || endpoint.id}
                    </span>
                    <span>{endpoint.ip || "—"}</span>
                    <span title={hasResolvedHostname ? endpoint.label : ""}>
                      {hasResolvedHostname ? endpoint.label : "—"}
                    </span>
                    <span>{endpoint.vendor || "Unknown"}</span>
                    <span>{endpoint.source_port || "—"}</span>
                    <span title={endpoint.source_port_desc || ""}>
                      {endpoint.source_port_desc || "—"}
                    </span>
                    <span>{endpoint.vlan_id || "—"}</span>
                    <span>{formatSpeed(endpoint.speed_bps) || "—"}</span>
                    <span style={{ textTransform: "uppercase" }}>
                      {endpoint.link_type || "—"}
                    </span>
                    <span>
                      {endpoint.asset_id ? (
                        <a
                          href={`/assets/${endpoint.asset_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="nmap-asset-link"
                          onClick={(e) => e.stopPropagation()}
                        >
                          🔗 Matched
                        </a>
                      ) : (
                        <span className="is-muted">Unmatched</span>
                      )}
                    </span>
                  </div>
                );
              })}
              {!pagedEndpoints.length && (
                <div className="nmap-endpoint-empty">
                  No endpoints match this filter.
                </div>
              )}
            </div>
            <div className="nmap-endpoint-pager">
              <button
                className="btn btn--secondary"
                onClick={() => setEndpointPage((page) => Math.max(0, page - 1))}
                disabled={endpointPage === 0}
              >
                Previous
              </button>
              <button
                className="btn btn--secondary"
                onClick={() => setEndpointPage((page) => page + 1)}
                disabled={
                  (endpointPage + 1) * endpointPageSize >=
                  selectedEndpoints.length
                }
              >
                Show next 50
              </button>
            </div>
          </Modal>
        )}

      {selectedActionHelp && (
        <Modal
          isOpen={!!selectedActionHelp}
          onClose={() => setSelectedActionHelp(null)}
          title={selectedActionHelp.title}
          size="medium"
        >
          <div
            style={{
              lineHeight: "1.6",
              fontSize: "0.9rem",
              color: "var(--text-mid)",
            }}
          >
            {selectedActionHelp.content}
            <div
              style={{
                marginTop: "24px",
                display: "flex",
                justifyContent: "flex-end",
              }}
            >
              {selectedActionHelp.actionUrl ? (
                <button
                  className="btn btn--primary"
                  onClick={() => {
                    navigate(selectedActionHelp.actionUrl);
                    setSelectedActionHelp(null);
                  }}
                >
                  {selectedActionHelp.actionLabel || "Proceed"}
                </button>
              ) : (
                <button
                  className="btn btn--secondary"
                  onClick={() => setSelectedActionHelp(null)}
                >
                  Got it
                </button>
              )}
            </div>
          </div>
        </Modal>
      )}
    </AppLayout>
  );
}
