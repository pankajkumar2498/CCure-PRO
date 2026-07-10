/**
 * src/pages/scan/CredentialedScan.jsx
 * SSH credential form → POST /scan/credentialed → CredentialedResults.
 * Credentials are NEVER stored — cleared from state immediately after use.
 */
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import { runCredentialedScan } from "../../api/credentialedScan";
import { useAuth } from "../../context/AuthContext";
import { can, denyMessage } from "../../auth/permissions";
import api from "../../api/axiosInstance";

const SECTIONS = [
  { key: "system_info", label: "System Info", icon: "🖥", desc: "OS, kernel/build, CPU, RAM, disk" },
  { key: "packages", label: "Packages", icon: "📦", desc: "Installed software (dpkg/rpm/registry)" },
  { key: "services", label: "Running Services", icon: "⚙️", desc: "Active services / systemd units" },
  { key: "ports", label: "Open Ports", icon: "🔌", desc: "Live socket table (ss / netstat)" },
  { key: "users", label: "Users", icon: "👤", desc: "User accounts & admin analysis" },
  { key: "security", label: "Security Audit", icon: "🔒", desc: "Firewall, shares, SUID, sudo, RDP" },
  { key: "network", label: "Network", icon: "🌐", desc: "Interfaces, ARP, env vars" },
  { key: "history", label: "Login History", icon: "📋", desc: "Recent logins & failures" },
];

export default function CredentialedScan() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user } = useAuth();
  const canExecuteScans = can(user, "scans", "execute");
  const prefillIp = location.state?.prefill?.ip ?? "";

  const [ip, setIp] = useState(prefillIp);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [port, setPort] = useState("22");
  const [authMethod, setAuthMethod] = useState("password");
  const [osType, setOsType] = useState("auto");
  const [showPass, setShowPass] = useState(false);
  const [sections, setSections] = useState(new Set(SECTIONS.map(s => s.key)));
  const [loading, setLoading] = useState(false);
  const [loadPhase, setLoadPhase] = useState("");  // "detecting" | "collecting"
  const [error, setError] = useState("");

  const [credentialSource, setCredentialSource] = useState("jit"); // "jit" | "stored"
  const [credentialsList, setCredentialsList] = useState([]);
  const [selectedCredId, setSelectedCredId] = useState("");

  useEffect(() => {
    if (prefillIp) { setIp(prefillIp); setPassword(""); setKeyPath(""); setError(""); }
  }, [prefillIp]);

  useEffect(() => {
    api.get("/compliance/credentials")
      .then(res => {
        setCredentialsList(res.data || []);
      })
      .catch(err => {
        console.error("Failed to load credentials for scan", err);
      });
  }, []);

  const toggleSection = key => {
    const n = new Set(sections);
    n.has(key) ? n.delete(key) : n.add(key);
    setSections(n);
  };

  const allSelected = sections.size === SECTIONS.length;
  const noneSelected = sections.size === 0;
  const toggleAll = () => setSections(allSelected ? new Set() : new Set(SECTIONS.map(s => s.key)));

  const handleSubmit = async () => {
    setError("");
    if (!canExecuteScans) return setError(denyMessage);
    if (!ip.trim()) return setError("Please enter a target IP or hostname.");
    
    if (credentialSource === "stored") {
      if (!selectedCredId) return setError("Please select a stored credential.");
    } else {
      if (!username.trim()) return setError("Please enter an SSH username.");
      if (authMethod === "password" && !password) return setError("Please enter a password.");
      if (authMethod === "key" && !keyPath) return setError("Please enter the SSH key path.");
    }
    
    if (noneSelected) return setError("Select at least one data category to collect.");

    setLoading(true);
    setLoadPhase(osType === "auto" ? "detecting" : "collecting");
    try {
      // Give the UI a tick to render the loading state before the blocking request
      await new Promise(r => setTimeout(r, 50));
      if (osType === "auto") setLoadPhase("collecting"); // detection happens first server-side
      const { data } = await runCredentialedScan({
        ip: ip.trim(),
        username: credentialSource === "jit" ? username.trim() : undefined,
        password: credentialSource === "jit" && authMethod === "password" ? password : undefined,
        keyPath: credentialSource === "jit" && authMethod === "key" ? keyPath.trim() : undefined,
        port: parseInt(port, 10) || 22,
        authMethod: credentialSource === "jit" ? authMethod : undefined,
        sections: allSelected ? null : Array.from(sections),
        osType,
        credentialId: credentialSource === "stored" ? selectedCredId : undefined,
      });

      if (!data.success) throw new Error(data.error || "Scan failed");

      // Clear credentials immediately from memory
      setPassword("");
      setKeyPath("");

      navigate(`/scan/credentialed/results?scan_id=${data.scan_id}`, {
        state: { result: { ...data, os_type_was_auto: osType === "auto" } },
      });
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || "Scan failed";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const isUnreachableError = error && (
    error.toLowerCase().includes("reach") ||
    error.toLowerCase().includes("timeout") ||
    error.toLowerCase().includes("route") ||
    error.toLowerCase().includes("refused") ||
    error.toLowerCase().includes("down")
  );

  return (
    <AppLayout pageTitle="Credentialed Scan">
      <div className="page-inner cred-page-inner">

        <div className="cred-back-row">
          <button className="btn btn--ghost cred-back-btn" onClick={() => navigate("/dashboard")}>
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
                  placeholder="10.180.5.190 or server.local"
                  value={ip} onChange={e => setIp(e.target.value)}
                  disabled={loading || !canExecuteScans} autoComplete="off"
                />
              </div>
              <div className="cred-field cred-field--narrow">
                <label className="field-label">SSH Port</label>
                <input className="field-input" type="number" min={1} max={65535}
                  value={port} onChange={e => setPort(e.target.value)}
                  disabled={loading || !canExecuteScans}
                />
              </div>
              <div className="cred-field cred-field--narrow">
                <label className="field-label">Target OS</label>
                <select className="field-input" value={osType}
                  onChange={e => setOsType(e.target.value)} disabled={loading || !canExecuteScans}>
                  <option value="auto">Auto-detect</option>
                  <option value="linux">Linux</option>
                  <option value="windows">Windows ⚠ Beta</option>
                </select>
              </div>
            </div>

            {/* Windows Beta Warning */}
            {osType === "windows" && (
              <div className="alert alert--warn" style={{ marginTop: 10, fontSize: 13, lineHeight: 1.55 }}>
                <strong>⚠ Windows Support — Beta</strong><br />
                Windows credentialed scanning requires <strong>OpenSSH Server</strong> to be enabled on the target
                and PowerShell set as the default shell. WMI/registry-based commands work over SSH,
                but some queries (e.g. large package lists, event log) may time out on heavily patched systems.
                <br /><strong>Test on your environment before deploying to production.</strong>
              </div>
            )}

          </div>

          {/* Authentication */}
          <div className="cred-section">
            <h3 className="cred-section-title">Authentication</h3>

            <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
              <label style={{ fontSize: "0.84rem", display: "flex", alignItems: "center", gap: "6px", cursor: "pointer", fontWeight: 600 }}>
                <input type="radio" checked={credentialSource === "jit"} onChange={() => setCredentialSource("jit")} disabled={loading || !canExecuteScans} />
                One-time JIT Credentials
              </label>
              <label style={{ fontSize: "0.84rem", display: "flex", alignItems: "center", gap: "6px", cursor: "pointer", fontWeight: 600 }}>
                <input type="radio" checked={credentialSource === "stored"} onChange={() => setCredentialSource("stored")} disabled={loading || !canExecuteScans} />
                Use Stored Credential
              </label>
            </div>

            {credentialSource === "stored" ? (
              <div className="cred-row">
                <div className="cred-field cred-field--wide">
                  <label className="field-label">Select Saved Credential</label>
                  <select 
                    className="field-input" 
                    value={selectedCredId} 
                    onChange={e => setSelectedCredId(e.target.value)} 
                    disabled={loading || !canExecuteScans}
                  >
                    <option value="">-- Choose Credential --</option>
                    {credentialsList.map(c => (
                      <option key={c.id} value={c.id}>{c.name} ({c.username})</option>
                    ))}
                  </select>
                  {credentialsList.length === 0 && (
                    <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "6px", marginBottom: 0 }}>
                      No saved credentials registered. Manage your credentials under the <button type="button" className="btn-link" style={{ background: "none", border: "none", color: "var(--accent)", textDecoration: "underline", padding: 0, font: "inherit", cursor: "pointer" }} onClick={() => navigate("/compliance")}>Credentials Manager</button> tab.
                    </p>
                  )}
                </div>
              </div>
            ) : (
              <>
                <div className="cred-auth-toggle">
                  {["password", "key"].map(method => (
                    <button key={method}
                      className={`cred-auth-btn ${authMethod === method ? "cred-auth-btn--active" : ""}`}
                      onClick={() => setAuthMethod(method)}
                      disabled={loading || !canExecuteScans}
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
                      disabled={loading || !canExecuteScans} autoComplete="off"
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
                          disabled={loading || !canExecuteScans} autoComplete="current-password"
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
                        disabled={loading || !canExecuteScans} autoComplete="off"
                      />
                    </div>
                  )}
                </div>
              </>
            )}

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
                onClick={toggleAll} disabled={loading || !canExecuteScans}>
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
                    disabled={loading || !canExecuteScans}
                  />
                  <span className="csc-icon">{s.icon}</span>
                  <span className="csc-label">{s.label}</span>
                  <span className="csc-desc">{s.desc}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Status / Error */}
          {loading && (
            <p className="muted" style={{ fontSize: 13, marginBottom: 4 }}>
              {loadPhase === "detecting"
                ? <>⏳ Connecting and detecting OS&hellip; (may take ~5s)</>
                : <>⏳ Collecting system data via SSH&hellip; this takes 15&ndash;60s.</>}
            </p>
          )}

          {error && isUnreachableError && (
            <div style={{
              margin: "16px 0", padding: "16px 20px", borderRadius: 8,
              background: "rgba(245, 158, 11, 0.08)", border: "1px solid rgba(245, 158, 11, 0.3)",
              display: "flex", alignItems: "center", gap: 16, color: "#92400e"
            }}>
              <span style={{ fontSize: 24 }}>⚠️</span>
              <div>
                <strong style={{ display: "block", fontSize: 16 }}>Host is unreachable or down</strong>
                <p style={{ margin: "4px 0 0", fontSize: 14, opacity: 0.9 }}>
                  The scanner could not establish an SSH connection to <code>{ip}</code>.
                  Verify the IP address, SSH service status, and firewall rules.
                </p>
              </div>
            </div>
          )}

          {error && !isUnreachableError && <div className="alert alert--error">⚠ {error}</div>}

          {/* Submit */}
          <div className="cred-submit-row">
            <button
              className="btn btn--danger cred-submit-btn"
              onClick={handleSubmit}
              disabled={loading || !canExecuteScans}
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
