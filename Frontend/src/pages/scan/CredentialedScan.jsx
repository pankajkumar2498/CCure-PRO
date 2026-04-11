/**
 * src/pages/scan/CredentialedScan.jsx
 * SSH credential form → POST /scan/credentialed → CredentialedResults.
 * Credentials are NEVER stored — cleared from state immediately after use.
 */
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import { runCredentialedScan } from "../../api/credentialedScan";

const SECTIONS = [
  { key: "system_info", label: "System Info",       icon: "🖥",  desc: "OS, kernel, CPU, RAM, disk"             },
  { key: "packages",    label: "Packages",           icon: "📦",  desc: "Full dpkg/rpm package list"             },
  { key: "services",    label: "Running Services",   icon: "⚙️",  desc: "Active systemd units"                   },
  { key: "ports",       label: "Open Ports",         icon: "🔌",  desc: "Live socket table via ss"               },
  { key: "users",       label: "Users",              icon: "👤",  desc: "/etc/passwd analysis"                   },
  { key: "security",    label: "Security Audit",     icon: "🔒",  desc: "SUID, sudo rules, cron, world-writable" },
  { key: "network",     label: "Network",            icon: "🌐",  desc: "Interfaces, ARP, env vars"              },
  { key: "history",     label: "Login History",      icon: "📋",  desc: "last/lastb — recent logins & failures"  },
];

export default function CredentialedScan() {
  const location   = useLocation();
  const navigate   = useNavigate();
  const prefillIp  = location.state?.prefill?.ip ?? "";

  const [ip,         setIp]         = useState(prefillIp);
  const [username,   setUsername]   = useState("");
  const [password,   setPassword]   = useState("");
  const [keyPath,    setKeyPath]    = useState("");
  const [port,       setPort]       = useState("22");
  const [authMethod, setAuthMethod] = useState("password");
  const [showPass,   setShowPass]   = useState(false);
  const [sections,   setSections]   = useState(new Set(SECTIONS.map(s => s.key)));
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState("");

  useEffect(() => {
    if (prefillIp) { setIp(prefillIp); setPassword(""); setKeyPath(""); setError(""); }
  }, [prefillIp]);

  const toggleSection = key => {
    const n = new Set(sections);
    n.has(key) ? n.delete(key) : n.add(key);
    setSections(n);
  };

  const allSelected  = sections.size === SECTIONS.length;
  const noneSelected = sections.size === 0;
  const toggleAll    = () => setSections(allSelected ? new Set() : new Set(SECTIONS.map(s => s.key)));

  const handleSubmit = async () => {
    setError("");
    if (!ip.trim())       return setError("Please enter a target IP or hostname.");
    if (!username.trim()) return setError("Please enter an SSH username.");
    if (authMethod === "password" && !password) return setError("Please enter a password.");
    if (authMethod === "key"      && !keyPath)  return setError("Please enter the SSH key path.");
    if (noneSelected) return setError("Select at least one data category to collect.");

    setLoading(true);
    try {
      const { data } = await runCredentialedScan({
        ip: ip.trim(),
        username: username.trim(),
        password:   authMethod === "password" ? password  : undefined,
        keyPath:    authMethod === "key"      ? keyPath.trim() : undefined,
        port:       parseInt(port, 10) || 22,
        authMethod,
        sections:   allSelected ? null : Array.from(sections),
      });

      if (!data.success) throw new Error(data.error || "Scan failed");

      // Clear credentials immediately from memory
      setPassword("");
      setKeyPath("");

      navigate(`/scan/credentialed/results?scan_id=${data.scan_id}`, {
        state: { result: data },
      });
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppLayout pageTitle="Credentialed Scan">
      <div className="page-inner cred-page-inner">

        <div className="cred-back-row">
          <button className="btn btn--ghost cred-back-btn" onClick={() => navigate("/dashboard") }>
            ← Back
          </button>
        </div>



        {/* Form card */}
        <div className="cred-form-card">

          {/* Target */}
          <div className="cred-section">
            <h3 className="cred-section-title">Target</h3>
            <div className="cred-row">
              <div className="cred-field cred-field--wide">
                <label className="field-label">IP / Hostname</label>
                <input className="field-input" type="text"
                  placeholder="192.168.1.10 or server.local"
                  value={ip} onChange={e => setIp(e.target.value)}
                  disabled={loading} autoComplete="off"
                />
              </div>
              <div className="cred-field cred-field--narrow">
                <label className="field-label">SSH Port</label>
                <input className="field-input" type="number" min={1} max={65535}
                  value={port} onChange={e => setPort(e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>
          </div>

          {/* Authentication */}
          <div className="cred-section">
            <h3 className="cred-section-title">Authentication</h3>

            <div className="cred-auth-toggle">
              {["password", "key"].map(method => (
                <button key={method}
                  className={`cred-auth-btn ${authMethod === method ? "cred-auth-btn--active" : ""}`}
                  onClick={() => setAuthMethod(method)}
                  disabled={loading}
                >
                  {method === "password" ? "🔑 Password" : "📄 SSH Key"}
                </button>
              ))}
            </div>

            <div className="cred-row">
              <div className="cred-field">
                <label className="field-label">Username</label>
                <input className="field-input" type="text"
                  placeholder="root" value={username}
                  onChange={e => setUsername(e.target.value)}
                  disabled={loading} autoComplete="off"
                />
              </div>

              {authMethod === "password" ? (
                <div className="cred-field cred-field--pass">
                  <label className="field-label">Password</label>
                  <div className="pass-wrap">
                    <input className="field-input"
                      type={showPass ? "text" : "password"}
                      placeholder="••••••••"
                      value={password} onChange={e => setPassword(e.target.value)}
                      disabled={loading} autoComplete="current-password"
                    />
                    <button className="pass-toggle"
                      onClick={() => setShowPass(p => !p)} tabIndex={-1}>
                      {showPass ? "🙈" : "👁"}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="cred-field cred-field--wide">
                  <label className="field-label">Private Key Path (server-side)</label>
                  <input className="field-input" type="text"
                    placeholder="/home/user/.ssh/id_rsa"
                    value={keyPath} onChange={e => setKeyPath(e.target.value)}
                    disabled={loading} autoComplete="off"
                  />
                </div>
              )}
            </div>

            <p className="cred-privacy-note">
              🔒 Credentials are used for this scan only and immediately discarded — never logged, stored, or transmitted elsewhere.
            </p>
          </div>

          {/* Data categories */}
          <div className="cred-section">
            <div className="cred-section-header">
              <h3 className="cred-section-title">Collect</h3>
              <button className="btn btn--ghost"
                style={{ fontSize: 12, padding: "4px 12px" }}
                onClick={toggleAll} disabled={loading}>
                {allSelected ? "Deselect All" : "Select All"}
              </button>
            </div>
            <div className="cred-sections-grid">
              {SECTIONS.map(s => (
                <label key={s.key}
                  className={`cred-section-chip ${sections.has(s.key) ? "cred-section-chip--on" : ""}`}>
                  <input type="checkbox" style={{ display: "none" }}
                    checked={sections.has(s.key)}
                    onChange={() => toggleSection(s.key)}
                    disabled={loading}
                  />
                  <span className="csc-icon">{s.icon}</span>
                  <span className="csc-label">{s.label}</span>
                  <span className="csc-desc">{s.desc}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Error */}
          {error && <div className="alert alert--error">⚠ {error}</div>}

          {/* Submit */}
          <div className="cred-submit-row">
            {loading && (
              <p className="muted" style={{ fontSize: 13 }}>
                SSHing in and collecting data… this takes 15–60 seconds.
              </p>
            )}
            <button
              className="btn btn--danger cred-submit-btn"
              onClick={handleSubmit}
              disabled={loading}
            >
              {loading
                ? <><span className="btn-spinner" /> Scanning…</>
                : "🔐 Start Credentialed Scan"}
            </button>
          </div>

        </div>
      </div>
    </AppLayout>
  );
}
