/**
 * src/pages/scan/CredentialedScan.jsx
 * SSH credential form → POST /scan/credentialed → CredentialedResults.
 * Credentials are NEVER stored — cleared from state immediately after use.
 *
 * ── Migration note (Checkpoint 3C, batch 9) ─────────────────────────────────
 * The dispatch contract is untouched: same endpoint, same method, same nine
 * payload keys, same target parsing, same JIT-vs-stored exclusivity, same
 * `scans:execute` gate, same clearing of the secret after a successful send.
 * What changed is the surface — every control is now a CCure primitive, so it
 * carries a real label association, and the page's own layout moved into
 * `credentialed-scan.css` where it is expressed in tokens rather than in the
 * light-theme literals `scan.css` held.
 */
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import {
  CcureAlert,
  CcureButton,
  CcureInput,
  CcureSelect,
} from "../../design-system";
import "../../styles/credentialed-scan.css";
import { parseTargets, runCredentialedScan } from "../../api/credentialedScan";
import { useAuth } from "@shell/auth/AuthContext";
import { can, denyMessage } from "@shell/auth/permissions";
import api from "@shell/api/axiosInstance";

const SECTIONS = [
  {
    key: "system_info",
    label: "System Info",
    icon: "🖥",
    desc: "OS, kernel/build, CPU, RAM, disk",
  },
  {
    key: "packages",
    label: "Packages",
    icon: "📦",
    desc: "Installed software (dpkg/rpm/registry)",
  },
  {
    key: "services",
    label: "Running Services",
    icon: "⚙️",
    desc: "Active services / systemd units",
  },
  {
    key: "ports",
    label: "Listening Sockets",
    icon: "🔌",
    desc: "Host socket table — not a network port scan",
  },
  {
    key: "users",
    label: "Users",
    icon: "👤",
    desc: "User accounts & admin analysis",
  },
  {
    key: "security",
    label: "Security Audit",
    icon: "🔒",
    desc: "Firewall, shares, SUID, sudo, RDP",
  },
  {
    key: "network",
    label: "Network",
    icon: "🌐",
    desc: "Interfaces, ARP, env vars",
  },
  {
    key: "history",
    label: "Login History",
    icon: "📋",
    desc: "Recent logins & failures",
  },
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
  // Empty means "discover it". The engine probes the authentication
  // services the host actually offers (WinRM, SMB, SSH) and picks one;
  // a value here pins it, for a listener on a port nothing would guess.
  const [port, setPort] = useState("");
  const [authMethod, setAuthMethod] = useState("password");
  const [osType, setOsType] = useState("auto");
  const [showPass, setShowPass] = useState(false);
  const [sections, setSections] = useState(new Set(SECTIONS.map((s) => s.key)));
  const [loading, setLoading] = useState(false);
  const [loadPhase, setLoadPhase] = useState(""); // "detecting" | "collecting"
  const [error, setError] = useState("");

  const [credentialSource, setCredentialSource] = useState("jit"); // "jit" | "stored"
  const [credentialsList, setCredentialsList] = useState([]);
  const [selectedCredId, setSelectedCredId] = useState("");

  useEffect(() => {
    if (prefillIp) {
      setIp(prefillIp);
      setPassword("");
      setKeyPath("");
      setError("");
    }
  }, [prefillIp]);

  useEffect(() => {
    api
      .get("/compliance/credentials")
      .then((res) => {
        setCredentialsList(res.data || []);
      })
      .catch((err) => {
        console.error("Failed to load credentials for scan", err);
      });
  }, []);

  const toggleSection = (key) => {
    const n = new Set(sections);
    n.has(key) ? n.delete(key) : n.add(key);
    setSections(n);
  };

  const allSelected = sections.size === SECTIONS.length;
  const noneSelected = sections.size === 0;
  const toggleAll = () =>
    setSections(allSelected ? new Set() : new Set(SECTIONS.map((s) => s.key)));

  const targetList = parseTargets(ip);

  const handleSubmit = async () => {
    setError("");
    if (!canExecuteScans) return setError(denyMessage);
    if (targetList.length === 0)
      return setError(
        "Please enter at least one target IP, hostname, or range.",
      );

    if (credentialSource === "stored") {
      if (!selectedCredId)
        return setError("Please select a stored credential.");
    } else {
      if (!username.trim()) return setError("Please enter an SSH username.");
      if (authMethod === "password" && !password)
        return setError("Please enter a password.");
      if (authMethod === "key" && !keyPath)
        return setError("Please enter the SSH key path.");
    }

    if (noneSelected)
      return setError("Select at least one data category to collect.");

    setLoading(true);
    setLoadPhase(osType === "auto" ? "detecting" : "collecting");
    try {
      // Give the UI a tick to render the loading state before the blocking request
      await new Promise((r) => setTimeout(r, 50));
      if (osType === "auto") setLoadPhase("collecting"); // detection happens first server-side
      const { data } = await runCredentialedScan({
        targets: targetList,
        username: credentialSource === "jit" ? username.trim() : undefined,
        password:
          credentialSource === "jit" && authMethod === "password"
            ? password
            : undefined,
        keyPath:
          credentialSource === "jit" && authMethod === "key"
            ? keyPath.trim()
            : undefined,
        // Undefined, not 22. The API treats a stated port as a pin and
        // its absence as "discover", so sending a default here would
        // silently turn discovery off for every scan.
        port: port.trim() ? parseInt(port, 10) : undefined,
        authMethod: credentialSource === "jit" ? authMethod : undefined,
        sections: allSelected ? null : Array.from(sections),
        osType,
        credentialId:
          credentialSource === "stored" ? selectedCredId : undefined,
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

  const isUnreachableError =
    error &&
    (error.toLowerCase().includes("reach") ||
      error.toLowerCase().includes("timeout") ||
      error.toLowerCase().includes("route") ||
      error.toLowerCase().includes("refused") ||
      error.toLowerCase().includes("down"));

  const formDisabled = loading || !canExecuteScans;

  return (
    <AppLayout>
      <div className="page-inner cs-page">
        <div className="cs-back-row">
          <CcureButton
            variant="ghost"
            size="sm"
            onClick={() => navigate("/audit-dashboard")}
          >
            ← Back
          </CcureButton>
        </div>

        <h1 className="page-title">Credentialed Scan</h1>

        {/* A control that is merely disabled says nothing about why. The
            refusal is stated in words as well, and `live={false}` because a
            banner present on first paint is not an event to announce. */}
        {!canExecuteScans && (
          <CcureAlert
            variant="warning"
            live={false}
            title="You cannot start a credentialed scan"
            className="cs-deny"
          >
            {denyMessage} Dispatching an authenticated scan needs the{" "}
            <code>scans:execute</code> permission. The form below is shown
            read-only.
          </CcureAlert>
        )}

        <div className="cs-card">
          {/* What this scan covers. Stated before the scan runs, because a
              result with no network findings is easily read as a host with no
              network exposure — and this policy never looks for that. */}
          <CcureAlert
            variant="info"
            live={false}
            title="Scope of this scan"
            className="cs-scope"
          >
            <p className="cs-scope-p">
              An authenticated audit reads each host from the inside: installed
              packages matched against the vulnerability feed, hardening policy,
              users, and the local listening-socket table. It performs{" "}
              <strong>no host discovery and no network port scan</strong>, so it
              cannot report TLS, SSH-algorithm, HTTP-header or
              default-credential findings, and cannot confirm which listening
              services are reachable from the network.
            </p>
            <p className="cs-scope-p">
              For a complete assessment, run a{" "}
              <button
                type="button"
                onClick={() => navigate("/scan/new")}
                className="cs-linkbtn"
              >
                Vulnerability Audit
              </button>{" "}
              with a stored credential attached — discovery, port scanning and
              unauthenticated checks run first, and the authenticated results
              are merged into the same report.
            </p>
          </CcureAlert>

          {/* Target */}
          <section className="cs-section" aria-labelledby="cs-h-target">
            <h2 id="cs-h-target" className="cs-section-title">
              Target
            </h2>
            <div className="cs-row">
              <CcureInput
                label="Targets"
                fieldClassName="cs-field cs-field--wide"
                placeholder="10.180.5.190, server.local, 10.180.5.10-20, 10.180.5.0/28"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                disabled={formDisabled}
                autoComplete="off"
                /* The hint is wired through `aria-describedby`, so the target
                   count is announced with the field rather than sitting beside
                   it unread. */
                hint={
                  <>
                    One or more IPs, hostnames, ranges, or CIDRs — separated by
                    commas or spaces. The same credential is used for every
                    host.
                    {targetList.length > 1 && (
                      <strong className="cs-accent">
                        {" "}
                        {targetList.length} target expressions entered.
                      </strong>
                    )}
                  </>
                }
              />
              <CcureInput
                label="Port (optional)"
                type="number"
                min={1}
                max={65535}
                fieldClassName="cs-field cs-field--narrow"
                placeholder="Auto"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                disabled={formDisabled}
                hint="Leave blank to detect the service automatically."
              />
              <CcureSelect
                label="Target OS"
                fieldClassName="cs-field cs-field--narrow"
                value={osType}
                onChange={(e) => setOsType(e.target.value)}
                disabled={formDisabled}
              >
                <option value="auto">Auto-detect</option>
                <option value="linux">Linux</option>
                <option value="windows">Windows ⚠ Beta</option>
              </CcureSelect>
            </div>

            {/* Windows Beta Warning. This one IS an event — it appears in
                response to the operator changing the OS — so it announces. */}
            {osType === "windows" && (
              <CcureAlert
                variant="info"
                title="How Windows hosts are reached"
                className="cs-inline-alert"
              >
                Supply the username and password only — the scanner detects
                which authentication service the host offers and uses it.{" "}
                <strong>WinRM</strong> (5985/5986) is preferred because it
                serves every collector item; <strong>SMB</strong> with Remote
                Registry and WMI (445/139) is used where WinRM is off, which is
                the default on Windows client editions. OpenSSH on the target is
                supported but not required. The report names the service that
                accepted the credential.
              </CcureAlert>
            )}
          </section>

          {/* Authentication */}
          <section className="cs-section" aria-labelledby="cs-h-auth">
            <h2 id="cs-h-auth" className="cs-section-title">
              Authentication
            </h2>

            {/* A fieldset, so the two radios are announced as one choice with
                a name. They also share a `name`, which is what makes the arrow
                keys move between them — without it each is an island. */}
            <fieldset className="cs-fieldset">
              <legend className="cs-legend">Credential source</legend>
              <div className="cs-source-row">
                <label className="cs-radio">
                  <input
                    type="radio"
                    name="cs-credential-source"
                    value="jit"
                    checked={credentialSource === "jit"}
                    onChange={() => setCredentialSource("jit")}
                    disabled={formDisabled}
                  />
                  One-time JIT Credentials
                </label>
                <label className="cs-radio">
                  <input
                    type="radio"
                    name="cs-credential-source"
                    value="stored"
                    checked={credentialSource === "stored"}
                    onChange={() => setCredentialSource("stored")}
                    disabled={formDisabled}
                  />
                  Use Stored Credential
                </label>
              </div>
            </fieldset>

            {credentialSource === "stored" ? (
              <div className="cs-row">
                <CcureSelect
                  label="Select saved credential"
                  fieldClassName="cs-field cs-field--wide"
                  value={selectedCredId}
                  onChange={(e) => setSelectedCredId(e.target.value)}
                  disabled={formDisabled}
                  hint={
                    credentialsList.length === 0 ? (
                      <>
                        No saved credentials registered. Manage your credentials
                        under the{" "}
                        <button
                          type="button"
                          className="cs-linkbtn"
                          onClick={() => navigate("/compliance")}
                        >
                          Credentials Manager
                        </button>{" "}
                        tab.
                      </>
                    ) : undefined
                  }
                >
                  <option value="">-- Choose Credential --</option>
                  {credentialsList.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} ({c.username})
                    </option>
                  ))}
                </CcureSelect>
              </div>
            ) : (
              <>
                {/* A segmented control. `aria-pressed` is what tells a reader
                    which of the two is in force; the active styling alone is
                    colour-only state. */}
                <div
                  className="cs-auth-toggle"
                  role="group"
                  aria-label="Authentication method"
                >
                  {["password", "key"].map((method) => (
                    <CcureButton
                      key={method}
                      variant="ghost"
                      size="sm"
                      className={`cs-auth-btn ${authMethod === method ? "cs-auth-btn--active" : ""}`}
                      aria-pressed={authMethod === method}
                      onClick={() => setAuthMethod(method)}
                      disabled={formDisabled}
                    >
                      {method === "password" ? "🔑 Password" : "📄 SSH Key"}
                    </CcureButton>
                  ))}
                </div>

                <div className="cs-row">
                  <CcureInput
                    label="Username"
                    fieldClassName="cs-field"
                    placeholder="root"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    disabled={formDisabled}
                    autoComplete="off"
                  />

                  {authMethod === "password" ? (
                    <CcureInput
                      label="Password"
                      type={showPass ? "text" : "password"}
                      fieldClassName="cs-field cs-field--pass"
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={formDisabled}
                      autoComplete="current-password"
                      /* Deliberately NOT CcurePasswordField: that pattern adds
                         a strength meter, which grades a credential the
                         operator does not own and cannot change. A reveal
                         toggle is legitimate here — the secret is being typed
                         now, not read back from the server — so it is an
                         adornment on an ordinary field, which keeps the
                         input's own id, label and describedby wiring. */
                      adornment={
                        <button
                          type="button"
                          className="cs-pass-toggle"
                          onClick={() => setShowPass((p) => !p)}
                          /* Was tabIndex={-1}, which put the only control that
                             reveals a mistyped password out of keyboard reach.
                             `aria-pressed` states which way it is set; the
                             name changes with it so the announcement says what
                             activating it will do. */
                          aria-pressed={showPass}
                          aria-label={
                            showPass ? "Hide password" : "Show password"
                          }
                          disabled={formDisabled}
                        >
                          <span aria-hidden="true">
                            {showPass ? "🙈" : "👁"}
                          </span>
                        </button>
                      }
                    />
                  ) : (
                    <CcureInput
                      label="Private key path (server-side)"
                      fieldClassName="cs-field cs-field--wide"
                      placeholder="/home/user/.ssh/id_rsa"
                      value={keyPath}
                      onChange={(e) => setKeyPath(e.target.value)}
                      disabled={formDisabled}
                      autoComplete="off"
                    />
                  )}
                </div>
              </>
            )}

            <p className="cs-privacy-note">
              🔒 Credentials are used for this scan only and immediately
              discarded — never logged, stored, or transmitted elsewhere.
            </p>
          </section>

          {/* Data categories */}
          <section className="cs-section" aria-labelledby="cs-h-collect">
            <div className="cs-section-header">
              <h2 id="cs-h-collect" className="cs-section-title">
                Collect
              </h2>
              <CcureButton
                variant="ghost"
                size="sm"
                onClick={toggleAll}
                disabled={formDisabled}
              >
                {allSelected ? "Deselect All" : "Select All"}
              </CcureButton>
            </div>
            <div className="cs-chip-grid">
              {SECTIONS.map((s) => (
                <label
                  key={s.key}
                  className={`cs-chip ${sections.has(s.key) ? "cs-chip--on" : ""}`}
                >
                  {/* Clipped, not `display: none`. See credentialed-scan.css —
                      hiding it outright took the control out of the tab order,
                      so a keyboard user could not choose what is collected. */}
                  <input
                    type="checkbox"
                    className="cs-visually-hidden"
                    checked={sections.has(s.key)}
                    onChange={() => toggleSection(s.key)}
                    disabled={formDisabled}
                  />
                  <span className="cs-chip-icon" aria-hidden="true">
                    {s.icon}
                  </span>
                  <span className="cs-chip-label">{s.label}</span>
                  <span className="cs-chip-desc">{s.desc}</span>
                </label>
              ))}
            </div>
          </section>

          {/* Status / Error */}
          {loading && (
            <CcureAlert variant="info" className="cs-inline-alert">
              {loadPhase === "detecting"
                ? "Connecting and detecting OS… (may take ~5s)"
                : "Collecting system data via SSH… this takes 15–60s."}
            </CcureAlert>
          )}

          {error && isUnreachableError && (
            <CcureAlert
              variant="warning"
              title="Host is unreachable or down"
              className="cs-inline-alert"
            >
              The scanner could not establish an SSH connection to{" "}
              <code>{ip}</code>. Verify the IP address, SSH service status, and
              firewall rules.
            </CcureAlert>
          )}

          {error && !isUnreachableError && (
            <CcureAlert variant="danger" className="cs-inline-alert">
              {error}
            </CcureAlert>
          )}

          {/* Submit */}
          <div className="cs-submit-row">
            <CcureButton
              variant="danger"
              size="lg"
              className="cs-submit-btn"
              onClick={handleSubmit}
              loading={loading}
              disabled={!canExecuteScans}
            >
              {loading ? "Scanning…" : "🔐 Start Credentialed Scan"}
            </CcureButton>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
