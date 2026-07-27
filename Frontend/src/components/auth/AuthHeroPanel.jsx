/**
 * src/components/auth/AuthHeroPanel.jsx
 * Enterprise Left Hero Showcase Panel for Authentication Pages.
 */
import { useState, useEffect } from "react";
import {
  ShieldLogoIcon,
  AssetIntelligenceIcon,
  ComplianceEngineIcon,
  ExecutiveTelemetryIcon,
} from "./AuthIcons";

const HERO_CONTENT = {
  login: {
    badge: "ENTERPRISE SECURITY PORTAL",
    headline: "Automated Compliance & Vulnerability Intelligence",
    subheadline:
      "Real-time asset discovery, continuous NIST CSF 2.0, PCI-DSS & ISO 27001 framework auditing, and risk prioritization.",
  },
  register: {
    badge: "ENTERPRISE ONBOARDING",
    headline: "Elevate Your Network Security Posture",
    subheadline:
      "Gain complete visibility over your network assets, compliance readiness, and automated threat scans.",
  },
  forgot: {
    badge: "SECURE RECOVERY",
    headline: "Zero-Trust Identity Pipeline",
    subheadline:
      "Encrypted password recovery and multi-factor identity verification.",
  },
  reset: {
    badge: "ACCESS RESTORATION",
    headline: "Set Secure Access Credentials",
    subheadline:
      "Establish high-entropy credentials to restore access to your compliance workspace.",
  },
};

export default function AuthHeroPanel({ pageType = "login" }) {
  const content = HERO_CONTENT[pageType] || HERO_CONTENT.login;
  const [assetCount, setAssetCount] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = 10000;
    const duration = 1200; // ms
    const stepTime = Math.abs(Math.floor(duration / (end / 200)));

    const timer = setInterval(() => {
      start += 250;
      if (start >= end) {
        clearInterval(timer);
        setAssetCount(end);
      } else {
        setAssetCount(start);
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, []);

  return (
    <div className="auth-hero-panel">
      {/* Ambient Gradient Mesh Blobs */}
      <div className="auth-hero-blob blob-cyan" />
      <div className="auth-hero-blob blob-indigo" />

      <div className="auth-hero-content">
        {/* Brand Header */}
        <div className="auth-hero-brand">
          <ShieldLogoIcon size={36} />
          <span className="auth-hero-brand-title">CCure Audit</span>
          <span className="auth-brand-badge">PRO</span>
        </div>

        {/* Dynamic Context Section */}
        <div className="auth-hero-context">
          <span className="auth-hero-badge">{content.badge}</span>
          <h1 className="auth-hero-headline">{content.headline}</h1>
          <p className="auth-hero-subheadline">{content.subheadline}</p>
        </div>

        {/* Feature Cards Grid (3-Step Pipeline Order) */}
        <div className="auth-feature-list">
          <div className="auth-feature-card">
            <div className="auth-feature-icon">
              <AssetIntelligenceIcon />
            </div>
            <div className="auth-feature-text">
              <h3>Network Asset Intelligence</h3>
              <p>
                Real-time asset discovery, port mapping, and vulnerability
                priority scoring.
              </p>
            </div>
          </div>

          <div className="auth-feature-card">
            <div className="auth-feature-icon">
              <ComplianceEngineIcon />
            </div>
            <div className="auth-feature-text">
              <h3>Automated Compliance Engine</h3>
              <p>Continuous NIST CSF 2.0, CIS & ISO framework alignment.</p>
            </div>
          </div>

          <div className="auth-feature-card">
            <div className="auth-feature-icon">
              <ExecutiveTelemetryIcon />
            </div>
            <div className="auth-feature-text">
              <h3>Executive Telemetry</h3>
              <p>
                Historical scan archives, scheduled audits, and audit report
                generation.
              </p>
            </div>
          </div>
        </div>

        {/* Security Metrics Bar */}
        <div className="auth-metrics-bar">
          <div className="auth-metric-item">
            <span className="auth-metric-val">
              {assetCount.toLocaleString()}+
            </span>
            <span className="auth-metric-lbl">Assets Audited</span>
          </div>
          <div className="auth-metric-divider" />
          <div className="auth-metric-item">
            <span className="auth-metric-val">99.9%</span>
            <span className="auth-metric-lbl">Scan Precision</span>
          </div>
          <div className="auth-metric-divider" />
          <div className="auth-metric-item">
            <span className="auth-status-pill">
              <span className="auth-status-dot" /> All Systems Operational
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
