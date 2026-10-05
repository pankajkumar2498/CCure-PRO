/**
 * src/modules/audit/pages/scan/NetworkMap.jsx
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
 *
 * Checkpoint 3C batch 21 — on the design system. The page around the graph is
 * design-system primitives and a token-only stylesheet. The graph itself is a
 * canvas, which cannot read CSS: every colour it draws is named by a custom
 * property that NetworkMap.css defines from a CCure token, read from the
 * page's computed style and read again whenever the theme changes.
 */
import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import { Network, DataSet } from "vis-network/standalone";
import AppLayout from "@audit/components/layout/AppLayout";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcureConfirmDialog,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcureModal,
  CcureSelect,
  CcureTable,
  CcureCheckbox,
} from "../../../../design-system";
import api from "@shell/api/axiosInstance";
import "../../styles/NetworkMap.css";

/* ── Canvas colours ──────────────────────────────────────────────────────────── */
/* vis-network draws on a <canvas>, and the node icons are SVG images; neither
 * can resolve a CSS custom property. So each colour the map draws is a role
 * here, named by the property NetworkMap.css defines for it from a CCure token,
 * and resolved from the page's computed style.
 *
 * The second value is a CSS system colour, used only when the property cannot
 * be read — under jsdom, or before the stylesheet applies. A system colour
 * keeps the map legible in the viewer's own scheme; an empty string would
 * leave vis-network drawing in whatever its defaults happen to be. */
const CANVAS_TOKENS = {
  canvas: ["--nmap-canvas", "Canvas"],
  labelMuted: ["--nmap-label-muted", "GrayText"],
  edge: ["--nmap-edge", "GrayText"],
  edgeHighlight: ["--nmap-edge-highlight", "Highlight"],
  lldp: ["--nmap-link-lldp", "CanvasText"],
  cdp: ["--nmap-link-cdp", "CanvasText"],
  edp: ["--nmap-link-edp", "CanvasText"],
  arp: ["--nmap-link-arp", "CanvasText"],
  statusOk: ["--nmap-status-ok", "CanvasText"],
  statusAlert: ["--nmap-status-alert", "CanvasText"],
  statusInfo: ["--nmap-status-info", "CanvasText"],
  dangerInk: ["--nmap-danger-ink", "CanvasText"],
  dangerFill: ["--nmap-danger-fill", "Canvas"],
  warningInk: ["--nmap-warning-ink", "CanvasText"],
  warningFill: ["--nmap-warning-fill", "Canvas"],
  successInk: ["--nmap-success-ink", "CanvasText"],
  successFill: ["--nmap-success-fill", "Canvas"],
  infoInk: ["--nmap-info-ink", "CanvasText"],
  infoFill: ["--nmap-info-fill", "Canvas"],
  primaryInk: ["--nmap-primary-ink", "CanvasText"],
  primaryFill: ["--nmap-primary-fill", "Canvas"],
  neutralInk: ["--nmap-neutral-ink", "CanvasText"],
  neutralFill: ["--nmap-neutral-fill", "Canvas"],
};

/** Every colour role, resolved from the element's computed style. */
const readCanvasPalette = (element) => {
  const style = element ? window.getComputedStyle(element) : null;
  return Object.fromEntries(
    Object.entries(CANVAS_TOKENS).map(([role, [property, fallback]]) => {
      const value = style ? style.getPropertyValue(property).trim() : "";
      // An unresolved reference is not a colour; jsdom returns one verbatim.
      return [role, value && !value.includes("var(") ? value : fallback];
    }),
  );
};

/* Device categories share six colour families: routing, perimeter and
 * printing, endpoints, wireless and links, operational technology, compute
 * and unknown. Which device a node is comes from its icon's shape and its
 * label, never from colour alone. */
const CATEGORY_FAMILY = {
  router: "danger",
  gateway: "danger",
  load_balancer: "danger",
  firewall: "warning",
  printer: "warning",
  switch: "primary",
  workstation: "primary",
  desktop: "primary",
  laptop: "primary",
  endpoint: "primary",
  wireless_ap: "info",
  modem: "info",
  subnet: "info",
  camera: "success",
  iot: "success",
  plc: "success",
  rtu: "success",
  mobile: "success",
  server: "neutral",
  virtual_machine: "neutral",
  storage: "neutral",
  unknown: "neutral",
};

const familyOf = (group) =>
  Object.prototype.hasOwnProperty.call(CATEGORY_FAMILY, group)
    ? CATEGORY_FAMILY[group]
    : "neutral";

/* ── Node icons ──────────────────────────────────────────────────────────────── */
/* Stable SVG templates for all 21 device categories and the subnet. The shapes
 * are unchanged; each colour is a slot filled from the palette: {ink} outlines
 * and marks, {fill} the body, {canvas} cut-outs, and {ok} / {alert} / {info}
 * the status lights. */
const ROUTER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <circle cx="32" cy="32" r="26" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M32 8v10M32 46v10M8 32h10M46 32h10" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
  <circle cx="32" cy="32" r="10" fill="{canvas}" stroke="{ink}" stroke-width="2" />
  <circle cx="32" cy="32" r="4" fill="{ink}" />
</svg>`;

const SWITCH_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="6" y="16" width="52" height="32" rx="6" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <rect x="12" y="24" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="24" y="24" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="36" y="24" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="48" y="24" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="12" y="34" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="24" y="34" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="36" y="34" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="48" y="34" width="8" height="6" rx="1" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <circle cx="16" cy="21" r="1.5" fill="{ok}" />
  <circle cx="28" cy="21" r="1.5" fill="{ok}" />
  <circle cx="40" cy="21" r="1.5" fill="{alert}" />
  <circle cx="52" cy="21" r="1.5" fill="{ok}" />
</svg>`;

const GATEWAY_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="8" y="12" width="48" height="40" rx="8" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M22 28v14M32 22v20M42 28v14" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
  <path d="M14 44h36" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
</svg>`;

const FIREWALL_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <path d="M12 8h40v12H12zm0 16h40v12H12zm0 16h40v12H12z" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <path d="M22 8v48M42 8v48" stroke="{ink}" stroke-width="2" />
  <path d="M12 20h40M12 36h40" stroke="{fill}" stroke-width="2.5" />
</svg>`;

const WIRELESS_AP_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <circle cx="32" cy="46" r="8" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <path d="M32 38v-24M24 24a12 12 0 0 1 16 0M16 16a24 24 0 0 1 32 0M8 8a36 36 0 0 1 48 0" fill="none" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
</svg>`;

const SERVER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="10" y="8" width="44" height="48" rx="4" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <rect x="14" y="14" width="36" height="8" rx="2" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="14" y="28" width="36" height="8" rx="2" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <rect x="14" y="42" width="36" height="8" rx="2" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <circle cx="18" cy="18" r="2" fill="{ok}" />
  <circle cx="18" cy="32" r="2" fill="{ok}" />
  <circle cx="18" cy="46" r="2" fill="{ok}" />
</svg>`;

const WORKSTATION_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="4" y="12" width="34" height="24" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M12 36v8M8 44h18" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
  <rect x="44" y="8" width="16" height="40" rx="3" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <rect x="48" y="42" width="8" height="2" fill="{ink}" />
</svg>`;

const DESKTOP_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="8" y="14" width="38" height="26" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M18 40v8M12 48h22" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
  <rect x="50" y="14" width="6" height="34" rx="1" fill="{fill}" stroke="{ink}" stroke-width="1.5" />
</svg>`;

const LAPTOP_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="12" y="16" width="40" height="26" rx="3" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M4 46h56l-4-6H8z" fill="{canvas}" stroke="{ink}" stroke-width="2.5" stroke-linejoin="round" />
</svg>`;

const ENDPOINT_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="14" y="16" width="36" height="24" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M22 40v8M18 48h28" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
</svg>`;

const PRINTER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <path d="M16 26h32v24H16z" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M20 26v-12h24v12" fill="none" stroke="{ink}" stroke-width="2" />
  <path d="M12 36h40" stroke="{ink}" stroke-width="2.5" />
  <path d="M24 42h16M24 46h12" stroke="{ink}" stroke-width="2" stroke-linecap="round" />
</svg>`;

const CAMERA_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <path d="M32 10a18 18 0 0 0-18 18v8h36v-8a18 18 0 0 0-18-18z" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <circle cx="32" cy="28" r="8" fill="{canvas}" stroke="{ink}" stroke-width="2" />
  <circle cx="32" cy="28" r="3" fill="{ink}" />
  <path d="M10 40h44v6H10z" fill="{ink}" />
</svg>`;

const IOT_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="16" y="16" width="32" height="32" rx="4" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M32 8v8M32 48v8M8 32h8M48 32h8" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
  <circle cx="32" cy="32" r="6" fill="{ink}" />
</svg>`;

const PLC_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="8" y="10" width="48" height="44" rx="4" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M20 10v44M32 10v44M44 10v44" stroke="{ink}" stroke-width="2" />
  <circle cx="14" cy="20" r="2" fill="{ok}" />
  <circle cx="14" cy="28" r="2" fill="{ok}" />
  <circle cx="26" cy="20" r="2" fill="{alert}" />
  <circle cx="38" cy="20" r="2" fill="{ok}" />
</svg>`;

const RTU_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="10" y="14" width="44" height="38" rx="6" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M22 6v8M42 6v8M18 24h28M18 32h28" stroke="{ink}" stroke-width="2" stroke-linecap="round" />
  <circle cx="32" cy="42" r="3" fill="{ink}" />
</svg>`;

const STORAGE_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="12" y="8" width="40" height="12" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <rect x="12" y="26" width="40" height="12" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <rect x="12" y="44" width="40" height="12" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <circle cx="18" cy="14" r="1.5" fill="{info}" />
  <circle cx="18" cy="32" r="1.5" fill="{info}" />
  <circle cx="18" cy="50" r="1.5" fill="{info}" />
  <path d="M42 14h6M42 32h6M42 50h6" stroke="{ink}" stroke-width="2" stroke-linecap="round" />
</svg>`;

const VIRTUAL_MACHINE_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="6" y="24" width="24" height="24" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <rect x="34" y="24" width="24" height="24" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <rect x="20" y="8" width="24" height="12" rx="2" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <path d="M32 20v4M18 36h4M46 36h4" stroke="{ink}" stroke-width="2" />
</svg>`;

const MOBILE_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="18" y="8" width="28" height="48" rx="6" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <circle cx="32" cy="50" r="3" fill="{ink}" />
  <rect x="28" y="12" width="8" height="2" rx="1" fill="{ink}" />
</svg>`;

const LOAD_BALANCER_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <circle cx="32" cy="32" r="26" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M16 32h10M38 24l8-6M38 40l8 6" stroke="{ink}" stroke-width="2.5" stroke-linecap="round" />
  <path d="M46 14v4h-4M46 50v-4h-4" fill="none" stroke="{ink}" stroke-width="2.5" stroke-linejoin="round" />
</svg>`;

const MODEM_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="10" y="24" width="44" height="24" rx="4" fill="{fill}" stroke="{ink}" stroke-width="2.5" />
  <path d="M16 10v14M48 6v18" stroke="{ink}" stroke-width="2" stroke-linecap="round" />
  <circle cx="20" cy="36" r="2" fill="{ink}" />
  <circle cx="28" cy="36" r="2" fill="{ink}" />
  <circle cx="36" cy="36" r="2" fill="{ink}" />
</svg>`;

const UNKNOWN_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <circle cx="32" cy="32" r="26" fill="{fill}" stroke="{ink}" stroke-width="2" />
  <text x="32" y="42" font-family="'Inter', sans-serif" font-size="28" font-weight="bold" fill="{ink}" text-anchor="middle">?</text>
</svg>`;

const SUBNET_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <path d="M18 38a10 10 0 0 1 0-20 14 14 0 0 1 27.5-3A10 10 0 0 1 46 38z" fill="{fill}" stroke="{ink}" stroke-width="2.5" stroke-linejoin="round" />
  <ellipse cx="32" cy="26" rx="6" ry="2.5" fill="{canvas}" stroke="{ink}" stroke-width="1.5" />
  <path d="M26 26v4c0 1.38 2.68 2.5 6 2.5s6-1.12 6-2.5v-4" fill="none" stroke="{ink}" stroke-width="1.5" />
  <path d="M26 30v4c0 1.38 2.68 2.5 6 2.5s6-1.12 6-2.5v-4" fill="none" stroke="{ink}" stroke-width="1.5" />
</svg>`;

// Map of category ID to its SVG template
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

/** Every category's icon as a data URL, painted in the given palette. */
const paintIcons = (palette) =>
  Object.fromEntries(
    Object.entries(CATEGORY_SVGS).map(([group, template]) => {
      const family = familyOf(group);
      const slots = {
        ink: palette[`${family}Ink`],
        fill: palette[`${family}Fill`],
        canvas: palette.canvas,
        ok: palette.statusOk,
        alert: palette.statusAlert,
        info: palette.statusInfo,
      };
      return [
        group,
        getSvgDataUrl(
          template.replace(
            /\{(ink|fill|canvas|ok|alert|info)\}/g,
            (_, slot) => slots[slot],
          ),
        ),
      ];
    }),
  );

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

/* Edge colour by the evidence backing the link. LLDP, CDP and EDP all describe
 * a physical cable; ARP is L3 reachability, and anything weaker (FDB) stays
 * the neutral edge colour. EDP is Extreme's discovery protocol and is the only
 * neighbour source on an all-Extreme estate, so it must not fall through to
 * the generic colour. Values are palette roles. */
const LINK_TYPE_ROLES = {
  lldp: "lldp",
  cdp: "cdp",
  edp: "edp",
  arp: "arp",
};

/** Format bits-per-second into a human-readable speed string. */
const formatSpeed = (bps) => {
  if (!bps || bps <= 0) return null;
  if (bps >= 1_000_000_000)
    return `${(bps / 1_000_000_000).toFixed(bps % 1_000_000_000 === 0 ? 0 : 1)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(0)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} Kbps`;
  return `${bps} bps`;
};

const MAC_ONLY_SUBNET = "MAC-Only / FDB";
const subnetTitle = (subnet) =>
  subnet === MAC_ONLY_SUBNET ? "MAC-Only / FDB Cluster" : subnet;

/* The endpoint evidence table. MAC identifies the row; values that may be cut
 * short keep their full text in a tooltip, as before. */
const EVIDENCE_COLUMNS = [
  {
    key: "mac",
    header: "MAC",
    isRowHeader: true,
    mono: true,
    cell: (endpoint) => (
      <span title={endpoint.mac}>{endpoint.mac || endpoint.id}</span>
    ),
  },
  {
    key: "ip",
    header: "IP",
    mono: true,
    cell: (endpoint) => endpoint.ip || "—",
  },
  {
    key: "hostname",
    header: "Hostname",
    cell: (endpoint) => {
      const hasResolvedHostname =
        endpoint.label &&
        endpoint.label !== endpoint.ip &&
        endpoint.label !== endpoint.mac;
      return (
        <span title={hasResolvedHostname ? endpoint.label : ""}>
          {hasResolvedHostname ? endpoint.label : "—"}
        </span>
      );
    },
  },
  {
    key: "vendor",
    header: "Vendor",
    cell: (endpoint) => endpoint.vendor || "Unknown",
  },
  {
    key: "port",
    header: "Port",
    cell: (endpoint) => endpoint.source_port || "—",
  },
  {
    key: "portDescription",
    header: "Port Description",
    cell: (endpoint) => (
      <span title={endpoint.source_port_desc || ""}>
        {endpoint.source_port_desc || "—"}
      </span>
    ),
  },
  {
    key: "vlan",
    header: "VLAN",
    cell: (endpoint) => endpoint.vlan_id || "—",
  },
  {
    key: "speed",
    header: "Speed",
    nowrap: true,
    cell: (endpoint) => formatSpeed(endpoint.speed_bps) || "—",
  },
  {
    key: "source",
    header: "Source",
    className: "nmap-evidence__link-type",
    cell: (endpoint) => endpoint.link_type || "—",
  },
  {
    key: "asset",
    header: "Asset",
    nowrap: true,
    cell: (endpoint) =>
      endpoint.asset_id ? (
        <a
          href={`/assets/${endpoint.asset_id}`}
          target="_blank"
          rel="noopener noreferrer"
          className="nmap-link"
          onClick={(e) => e.stopPropagation()}
        >
          <span aria-hidden="true">🔗</span> Matched
          <span className="cc-sr-only"> (opens in a new tab)</span>
        </a>
      ) : (
        <span className="nmap-muted">Unmatched</span>
      ),
  },
];

export default function NetworkMap() {
  const { scanId: paramScanId } = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scanId = paramScanId || searchParams.get("scan_id") || null;

  const pageRef = useRef(null);
  const containerRef = useRef(null);
  const networkRef = useRef(null);

  // Raw data from API
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
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
  const [, setExpandedSubnets] = useState(new Set());
  const [subnets, setSubnets] = useState([]);
  const [filteredSubnets, setFilteredSubnets] = useState(new Set()); // Subnets that are HIDDEN
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedNode, setSelectedNode] = useState(null);
  const [endpointSearch, setEndpointSearch] = useState("");
  const [endpointPage, setEndpointPage] = useState(0);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState(false);
  const [selectedActionHelp, setSelectedActionHelp] = useState(null);
  /* The subnets waiting on the expand-all confirmation; null when closed. */
  const [pendingExpand, setPendingExpand] = useState(null);

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

  // The canvas palette and the icons painted in it: read from the page's
  // computed style when the graph first needs them, and again when the theme
  // changes (below). A ref, because vis-network reads them outside rendering.
  const canvasRef = useRef(null);
  const canvasColours = useCallback(() => {
    if (!canvasRef.current) {
      const palette = readCanvasPalette(pageRef.current);
      canvasRef.current = { palette, icons: paintIcons(palette) };
    }
    return canvasRef.current;
  }, []);

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
      // The refs are what the vis-network callbacks read, and mutating one does
      // not re-render. Publishing the same array instances as state gives the
      // derived memos below a dependency they can actually observe; previously
      // they leaned on `stats`/`subnets` changing in this same batch, or named
      // `allNodesRef.current` directly, which only worked because the ref is
      // replaced rather than mutated in place.
      setTopology({
        nodes: allNodesRef.current,
        edges: allEdgesRef.current,
      });
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
    const nodes = topology.nodes || [];
    const edges = topology.edges || [];
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
  }, [topology, isMacOnlySubnet]);

  const handleActionClick = useCallback((action) => {
    switch (action) {
      case "Run ARP-enabled scan":
        setSelectedActionHelp({
          icon: "🚀",
          title: "Run ARP-enabled Scan",
          content: (
            <div>
              <p>
                To resolve MAC addresses to IP addresses, configure a new scan
                targeting your network subnets with SNMP enabled.
              </p>
              <p>
                Ensure you select{" "}
                <strong>
                  <span aria-hidden="true">🗺️</span> Network Topology (SNMP)
                </strong>{" "}
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
          icon: "🔌",
          title: "Add SNMP target",
          content: (
            <div>
              <p>
                Add the default gateway router IP to your SNMP targets. The
                topology engine queries the gateway&apos;s ARP table to
                associate MAC addresses with their host IP addresses.
              </p>
              <p>
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
          icon: "🔍",
          title: "Enable ARP Table Collection",
          content: (
            <div>
              <p>
                ARP (Address Resolution Protocol) mappings are critical to
                connect L2 physical switchports to L3 IP networks.
              </p>
              <p>To resolve this:</p>
              <ol>
                <li>Configure your gateway router to allow SNMP access.</li>
                <li>
                  Ensure the router&apos;s SNMP configuration allows access to
                  the standard IP-MIB ARP table (OID{" "}
                  <code>1.3.6.1.2.1.4.22</code>).
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
          icon: "🌐",
          title: "Enable LLDP/CDP Link Discovery",
          content: (
            <div>
              <p>
                Physical topology mapping depends on Link Layer Discovery
                Protocol (LLDP) or Cisco Discovery Protocol (CDP) to discover
                neighbor links between managed switches.
              </p>
              <p>How to enable this on your infrastructure:</p>
              <ul>
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
          icon: "📋",
          title: "Correlate with Asset Inventory",
          content: (
            <div>
              <p>
                Some endpoints are listed as MAC-only because they haven&apos;t
                been resolved to active IP addresses or matched with registered
                corporate assets.
              </p>
              <p>
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
      const { palette, icons } = canvasColours();

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
          image: icons.subnet,
          size: isMacOnly ? 42 : 36,
          font: {
            color: palette[`${familyOf("subnet")}Ink`],
            size: 11,
            bold: true,
            face: "Inter, sans-serif",
            strokeWidth: 3,
            strokeColor: palette.canvas,
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
      const nodeImage = icons[group] || icons.unknown;
      const themeColor = palette[`${familyOf(group)}Ink`];

      if (n.tier === "host") {
        return {
          id: n.id,
          label: n.label || n.ip || n.id,
          shape: "image",
          image: nodeImage,
          size: 26,
          font: {
            color: palette.labelMuted,
            size: 9,
            face: "Inter, sans-serif",
            strokeWidth: 2,
            strokeColor: palette.canvas,
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
          strokeColor: palette.canvas,
          vadjust: 36,
        },
        size: nodeSize,
        level: nodeLevel,
        title: `${n.label}\nIP: ${n.ip || "—"}\nMAC: ${n.mac || "—"}\nType: ${group}`,
        _data: n,
      };
    },
    [isMacOnlySubnet, canvasColours],
  );

  /* ── Filter / Sync Viewable Graph ─────────────────────────────────────────── */
  const syncGraphView = useCallback(() => {
    if (!dsNodesRef.current || !dsEdgesRef.current) return;
    const { palette } = canvasColours();

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
          color: { color: palette.edge },
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
            color: palette[LINK_TYPE_ROLES[e.link_type]] || palette.edge,
            highlight: palette.edgeHighlight,
          },
          dashes: e.speed_bps && e.speed_bps < 100_000_000 ? [5, 5] : false,
          smooth: { type: "continuous" },
          font: { size: 9, color: palette.labelMuted, strokeWidth: 0 },
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
  }, [searchQuery, formatNode, isMacOnlySubnet, canvasColours]);

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

  // The vis-network instance below is built once per topology load and keeps
  // long-lived event handlers. Those handlers need the current expand/collapse
  // helpers, but naming them as dependencies would tear down and rebuild the
  // whole graph whenever they changed identity — and they change on every
  // keystroke in the search box, because they chain down to `syncGraphView`,
  // which depends on `searchQuery`. Rebuilding the canvas mid-search would
  // reset the operator's zoom and pan. Reading them through a ref keeps the
  // graph alive and still calls the newest closure, which the previous code
  // did not: a click after typing ran the helpers captured at initialisation.
  const graphActionsRef = useRef(null);
  graphActionsRef.current = {
    collapseSubnet,
    expandSubnet,
    isMacOnlySubnet,
    safeSyncGraphView,
  };

  /* ── Follow the theme ─────────────────────────────────────────────────────── */
  // PreferencesContext sets or removes `data-theme` on <html>, sometimes after
  // the graph has been drawn. The palette is read again and the graph re-synced
  // in place, exactly as a filter change does, so zoom and pan survive.
  useEffect(() => {
    const observer = new MutationObserver(() => {
      const palette = readCanvasPalette(pageRef.current);
      const previous = canvasRef.current?.palette;
      if (previous && JSON.stringify(previous) === JSON.stringify(palette)) {
        return;
      }
      canvasRef.current = { palette, icons: paintIcons(palette) };
      graphActionsRef.current.safeSyncGraphView();
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    return () => observer.disconnect();
  }, []);

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

        graphActionsRef.current.safeSyncGraphView();

        const isHierarchical = layoutMode === "hierarchical";

        const options = {
          nodes: {
            borderWidth: 2,
            borderWidthSelected: 3,
            // No colour: vis-network's own shadow colour applies.
            shadow: {
              enabled: true,
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
                if (
                  graphActionsRef.current.isMacOnlySubnet(node._data.subnet)
                ) {
                  return;
                }
                if (expandedSubnetsRef.current.has(nodeId)) {
                  graphActionsRef.current.collapseSubnet(nodeId);
                } else {
                  graphActionsRef.current.expandSubnet(nodeId);
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

  const expandSubnets = (visibleSubnets) => {
    const nextExpanded = new Set(expandedSubnetsRef.current);
    visibleSubnets.forEach((s) => {
      nextExpanded.add(`subnet:${s}`);
    });
    expandedSubnetsRef.current = nextExpanded;
    setExpandedSubnets(new Set(nextExpanded));
    safeSyncGraphView();
  };

  /* Expanding a large map is slow but entirely reversible, so this asks in the
     design system's confirmation dialog rather than window.confirm — same
     threshold, same wording, and Expand keeps the focus the native prompt gave
     its OK button. */
  const handleExpandAll = () => {
    const visibleSubnets = subnets.filter(
      (s) => !filteredSubnetsRef.current.has(s) && !isMacOnlySubnet(s),
    );
    if (visibleSubnets.length > 15) {
      setPendingExpand(visibleSubnets);
      return;
    }
    expandSubnets(visibleSubnets);
  };

  const handleCollapseAll = () => {
    expandedSubnetsRef.current = new Set();
    setExpandedSubnets(new Set());
    safeSyncGraphView();
  };

  const legendItems = useMemo(() => {
    const activeGroups = new Set();
    topology.nodes.forEach((node) => {
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
  }, [topology.nodes]);

  const canvasHidden = Boolean(
    loading || error || allNodesRef.current.length === 0,
  );

  return (
    <AppLayout>
      <div className="nmap-page" ref={pageRef}>
        <header className="nmap-header">
          <div className="nmap-header__titles">
            <h1 className="nmap-title">
              <span className="nmap-glyph" aria-hidden="true">
                🗺️
              </span>{" "}
              Network Topology Map
            </h1>
            <p className="nmap-subtitle">
              {scanId ? `Scan ID: ${scanId}` : "Corporate network architecture"}
            </p>
          </div>
          <div className="nmap-header__actions">
            <p className="nmap-stats">
              <span>
                <strong className="nmap-stats__value">{stats.nodes}</strong>{" "}
                Visible Nodes
              </span>
              <span className="nmap-stats__divider" aria-hidden="true">
                •
              </span>
              <span>
                <strong className="nmap-stats__value">{stats.hosts}</strong>{" "}
                Total Hosts
              </span>
            </p>
            <CcureButton
              variant="secondary"
              size="sm"
              onClick={fetchTopology}
              loading={loading}
            >
              {loading ? (
                "Syncing..."
              ) : (
                <>
                  <span aria-hidden="true">↻</span> Refresh
                </>
              )}
            </CcureButton>
          </div>
        </header>

        <section className="nmap-toolbar" aria-label="Map controls">
          <div className="nmap-toolbar__actions">
            <CcureButton
              variant="secondary"
              size="sm"
              onClick={handleFit}
              title="Fit Entire Network View"
            >
              <span aria-hidden="true">🔍</span> Fit Screen
            </CcureButton>
            <CcureButton
              variant="secondary"
              size="sm"
              onClick={handleExpandAll}
              title="Expand All Visible Subnets"
            >
              <span aria-hidden="true">📂</span> Expand All
            </CcureButton>
            <CcureButton
              variant="secondary"
              size="sm"
              onClick={handleCollapseAll}
              title="Collapse All Subnets"
            >
              <span aria-hidden="true">📁</span> Collapse All
            </CcureButton>
          </div>

          <div className="nmap-toolbar__fields">
            {/* Configurable Subnet size selection */}
            <CcureSelect
              label="Subnet mask"
              fieldClassName="nmap-field"
              value={subnetMask}
              onChange={(e) => setSubnetMask(Number(e.target.value))}
              title="Regroup network topology by mask bits"
            >
              <option value={16}>Class B (/16)</option>
              <option value={22}>Class C Extended (/22)</option>
              <option value={23}>Class C Extended (/23)</option>
              <option value={24}>Class C (/24)</option>
            </CcureSelect>

            {/* Freshness window — keeps decommissioned adjacency out of the map */}
            {!scanId && (
              <CcureSelect
                label="Seen within"
                fieldClassName="nmap-field"
                value={activeWithinDays}
                onChange={(e) => setActiveWithinDays(Number(e.target.value))}
                title="Only show links observed within this window"
              >
                <option value={7}>Last 7 days</option>
                <option value={30}>Last 30 days</option>
                <option value={90}>Last 90 days</option>
                <option value={0}>All recorded history</option>
              </CcureSelect>
            )}

            {/* Layout Mode selection */}
            <CcureSelect
              label="Layout"
              fieldClassName="nmap-field"
              value={layoutMode}
              onChange={(e) => setLayoutMode(e.target.value)}
              title="Switch layout styling engine"
            >
              <option value="hierarchical">Hierarchy</option>
              <option value="force">Force-Directed</option>
            </CcureSelect>

            <CcureInput
              label="Search hosts"
              fieldClassName="nmap-field nmap-field--search"
              placeholder="Search IP, Hostname, MAC..."
              value={searchQuery}
              onChange={handleSearchChange}
            />
          </div>
        </section>

        <section
          className="nmap-quality"
          role="status"
          aria-label="Topology data quality summary"
        >
          <ul className="nmap-quality__metrics">
            <li className="nmap-quality__item">
              <strong className="nmap-quality__value">
                {topologyQuality.macOnly}
              </strong>{" "}
              <span className="nmap-quality__label">MAC-only endpoints</span>
            </li>
            <li className="nmap-quality__item">
              <strong className="nmap-quality__value">
                {topologyQuality.ipResolved}
              </strong>{" "}
              <span className="nmap-quality__label">IPs resolved</span>
            </li>
            <li className="nmap-quality__item">
              <strong className="nmap-quality__value">
                {topologyQuality.sources}
              </strong>{" "}
              <span className="nmap-quality__label">Topology sources</span>
            </li>
          </ul>
          <CcureBadge variant={topologyQuality.hasArp ? "success" : "warning"}>
            {topologyQuality.hasArp ? "ARP present" : "ARP missing"}
          </CcureBadge>
          <CcureBadge
            variant={topologyQuality.hasLldpOrCdp ? "success" : "warning"}
          >
            {topologyQuality.hasLldpOrCdp
              ? "Neighbour discovery present"
              : "No neighbour discovery (LLDP/CDP/EDP)"}
          </CcureBadge>
        </section>

        {/* Main content layout */}
        <div className="nmap-body">
          {/* Graph canvas */}
          <section
            className="nmap-graph"
            aria-label="Interactive Topology Map View"
          >
            {loading && (
              <CcureLoader
                className="nmap-graph__state"
                label="Loading topology nodes..."
              />
            )}
            {error && (
              <div className="nmap-graph__state">
                <CcureAlert variant="danger" className="nmap-graph__alert">
                  {error}
                </CcureAlert>
                <CcureButton variant="secondary" onClick={fetchTopology}>
                  Retry
                </CcureButton>
              </div>
            )}
            {!loading && !error && allNodesRef.current.length === 0 && (
              <CcureEmptyState
                className="nmap-graph__state"
                icon="🔍"
                title="No Network Nodes Discovered"
                description="Run a network scan configured with SNMP to view the device hierarchy."
              />
            )}
            <div
              ref={containerRef}
              className="nmap-canvas"
              hidden={canvasHidden}
            />
          </section>

          {/* Sidebar for Filters & Detail Display */}
          <aside
            className="nmap-sidebar"
            aria-label="Topology controls and metadata sidebar"
          >
            {/* The selection is made on the canvas; say what it is. */}
            <p className="cc-sr-only" role="status">
              {selectedNode
                ? `Selected ${selectedNode.tier || "host"} ${selectedNode.label || selectedNode.id}`
                : ""}
            </p>

            {/* Subnet Filtering Checkboxes */}
            <CcureCard className="nmap-panel">
              <div className="nmap-panel__header">
                <h2 className="nmap-panel__title">
                  Subnets ({subnets.length})
                </h2>
                <div className="nmap-panel__actions">
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={selectAllSubnets}
                  >
                    Select All
                  </CcureButton>
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    onClick={deselectAllSubnets}
                  >
                    Clear
                  </CcureButton>
                </div>
              </div>
              <fieldset className="nmap-subnets">
                <legend className="cc-sr-only">Visible subnets</legend>
                <ul className="nmap-subnets__list">
                  {subnets.map((subnet) => (
                    <li key={subnet}>
                      <CcureCheckbox
                        className="nmap-subnet"
                        checked={!filteredSubnets.has(subnet)}
                        onChange={() => toggleSubnetFilter(subnet)}
                      >
                        <span className="nmap-subnet__label">{subnet}</span>
                      </CcureCheckbox>
                    </li>
                  ))}
                </ul>
              </fieldset>
            </CcureCard>

            {/* Legend */}
            <CcureCard className="nmap-panel">
              <h2 className="nmap-panel__title">Device Types</h2>
              <ul className="nmap-legend">
                {legendItems.map((item) => (
                  <li key={item.group} className="nmap-legend__item">
                    <span
                      className={`nmap-swatch nmap-swatch--${familyOf(item.group)}`}
                      aria-hidden="true"
                    />
                    <span className="nmap-legend__label">{item.label}</span>
                  </li>
                ))}
              </ul>
            </CcureCard>

            {/* Node metadata info */}
            {selectedNode && (
              <CcureCard className="nmap-panel nmap-detail">
                <h2 className="nmap-panel__title nmap-detail__title">
                  {selectedNode.label || selectedNode.id}
                </h2>
                <dl className="nmap-detail__rows">
                  {selectedNode.ip && (
                    <div className="nmap-detail__row">
                      <dt>IP</dt>
                      <dd>{selectedNode.ip}</dd>
                    </div>
                  )}
                  {selectedNode.mac && (
                    <div className="nmap-detail__row">
                      <dt>MAC</dt>
                      <dd className="nmap-mono">{selectedNode.mac}</dd>
                    </div>
                  )}
                  <div className="nmap-detail__row">
                    <dt>Tier</dt>
                    <dd className="nmap-detail__tier">
                      {selectedNode.tier || "host"}
                    </dd>
                  </div>
                  {selectedNode.subnet && (
                    <div className="nmap-detail__row">
                      <dt>Subnet</dt>
                      <dd>{selectedNode.subnet}</dd>
                    </div>
                  )}
                  {selectedNode.tier === "subnet" && (
                    <div className="nmap-detail__row">
                      <dt>Total Hosts</dt>
                      <dd>{selectedNode.host_count}</dd>
                    </div>
                  )}
                </dl>
                {selectedNode.tier === "subnet" &&
                  selectedNode.host_count > 50 && (
                    <CcureAlert
                      variant="warning"
                      live={false}
                      className="nmap-detail__alert"
                    >
                      Capped at 50 hosts on graph for layout visibility. Use the
                      search bar to locate specific hosts in this subnet.
                    </CcureAlert>
                  )}
                {selectedNode.tier === "subnet" &&
                  selectedNode.data_quality && (
                    <ul className="nmap-detail__quality">
                      <li>
                        <strong>{selectedNode.data_quality.mac_only}</strong>{" "}
                        <span>MAC-only</span>
                      </li>
                      <li>
                        <strong>{selectedNode.data_quality.ip_resolved}</strong>{" "}
                        <span>IP resolved</span>
                      </li>
                      <li>
                        <strong>
                          {selectedNode.data_quality.asset_matches}
                        </strong>{" "}
                        <span>asset matches</span>
                      </li>
                      <li>
                        <strong>
                          {selectedNode.data_quality.source_count}
                        </strong>{" "}
                        <span>sources</span>
                      </li>
                    </ul>
                  )}

                {selectedNode.tier === "subnet" && (
                  <div className="nmap-detail__endpoints">
                    <CcureButton
                      variant="secondary"
                      block
                      onClick={() => {
                        setEndpointSearch("");
                        setEndpointPage(0);
                        setIsEvidenceModalOpen(true);
                      }}
                      title="Open detailed endpoint evidence table in overlay"
                    >
                      <span aria-hidden="true">📊</span> View Endpoint Evidence
                      ({selectedEndpoints.length} devices)
                    </CcureButton>
                    {!!selectedNode.recommended_actions?.length && (
                      <div className="nmap-actions">
                        <h3 className="nmap-actions__title">
                          Recommended Next Actions
                        </h3>
                        <ul className="nmap-actions__list">
                          {selectedNode.recommended_actions.map((action) => (
                            <li key={action}>
                              <CcureButton
                                variant="ghost"
                                size="sm"
                                className="nmap-actions__button"
                                onClick={() => handleActionClick(action)}
                              >
                                {action}
                              </CcureButton>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {selectedNode.asset_id && (
                  <CcureButton
                    variant="primary"
                    block
                    className="nmap-detail__asset"
                    onClick={() => navigate(`/assets/${selectedNode.asset_id}`)}
                  >
                    View Asset Details
                    <span className="cc-sr-only">
                      {" "}
                      for {selectedNode.label || selectedNode.id}
                    </span>
                    <span aria-hidden="true"> →</span>
                  </CcureButton>
                )}
              </CcureCard>
            )}
          </aside>
        </div>
      </div>

      {isEvidenceModalOpen &&
        selectedNode &&
        selectedNode.tier === "subnet" && (
          <CcureModal
            open={isEvidenceModalOpen}
            onClose={() => setIsEvidenceModalOpen(false)}
            size="lg"
            className="nmap-modal"
            title={
              <>
                <span aria-hidden="true">📊</span> Endpoint Evidence —{" "}
                {subnetTitle(selectedNode.subnet)}
              </>
            }
            footer={
              <nav className="nmap-pager" aria-label="Endpoint pages">
                <CcureButton
                  variant="secondary"
                  onClick={() =>
                    setEndpointPage((page) => Math.max(0, page - 1))
                  }
                  disabled={endpointPage === 0}
                >
                  Previous
                </CcureButton>
                <CcureButton
                  variant="secondary"
                  onClick={() => setEndpointPage((page) => page + 1)}
                  disabled={
                    (endpointPage + 1) * endpointPageSize >=
                    selectedEndpoints.length
                  }
                >
                  Show next 50
                </CcureButton>
              </nav>
            }
          >
            <div className="nmap-evidence__head">
              <p className="nmap-evidence__summary">
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
              </p>
              <dl className="nmap-evidence__stats">
                <div className="nmap-evidence__stat">
                  <dt>Total Devices:</dt>
                  <dd>{selectedEndpoints.length}</dd>
                </div>
                <div className="nmap-evidence__stat">
                  <dt>IPs Resolved:</dt>
                  <dd>{selectedEndpoints.filter((e) => e.ip).length}</dd>
                </div>
                <div className="nmap-evidence__stat">
                  <dt>Asset Matches:</dt>
                  <dd className="nmap-evidence__matches">
                    {
                      selectedEndpoints.filter(
                        (e) => e.asset_match_status === "matched",
                      ).length
                    }
                  </dd>
                </div>
              </dl>
              <CcureInput
                label="Search endpoint evidence"
                fieldClassName="nmap-evidence__search"
                value={endpointSearch}
                onChange={(event) => {
                  setEndpointSearch(event.target.value);
                  setEndpointPage(0);
                }}
                placeholder="Search MAC, vendor, port, description, speed, VLAN..."
              />
            </div>
            <CcureTable
              caption={`Endpoints in ${subnetTitle(selectedNode.subnet)}`}
              className="nmap-evidence__table"
              density="compact"
              columns={EVIDENCE_COLUMNS}
              rows={pagedEndpoints}
              rowKey={(endpoint) => endpoint.id}
              emptyMessage="No endpoints match this filter."
            />
          </CcureModal>
        )}

      {selectedActionHelp && (
        <CcureModal
          open={!!selectedActionHelp}
          onClose={() => setSelectedActionHelp(null)}
          size="md"
          className="nmap-modal"
          title={
            <>
              <span aria-hidden="true">{selectedActionHelp.icon}</span>{" "}
              {selectedActionHelp.title}
            </>
          }
          footer={
            selectedActionHelp.actionUrl ? (
              <CcureButton
                variant="primary"
                onClick={() => {
                  navigate(selectedActionHelp.actionUrl);
                  setSelectedActionHelp(null);
                }}
              >
                {selectedActionHelp.actionLabel || "Proceed"}
              </CcureButton>
            ) : (
              <CcureButton
                variant="secondary"
                onClick={() => setSelectedActionHelp(null)}
              >
                Got it
              </CcureButton>
            )
          }
        >
          <div className="nmap-help">{selectedActionHelp.content}</div>
        </CcureModal>
      )}

      <CcureConfirmDialog
        open={pendingExpand !== null}
        title="Expand every subnet?"
        warning="Expanding more than 15 subnets simultaneously may slow down the view. Continue?"
        confirmLabel="Expand all"
        tone="info"
        initialFocus="confirm"
        onConfirm={() => {
          const pending = pendingExpand;
          setPendingExpand(null);
          if (pending) expandSubnets(pending);
        }}
        onCancel={() => setPendingExpand(null)}
      />
    </AppLayout>
  );
}
