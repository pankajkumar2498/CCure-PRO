/**
 * modules/web-scanning/pages/NewWebScan.jsx
 * The web-scanning dispatch form.
 *
 * ── What this page does, and why it got a batch of its own ──────────────────
 * Submitting this form makes this host send ffuf and nuclei at a URL the
 * operator typed. CLAUDE.md is explicit about the consequence: "an unbounded
 * loop there is an unbounded outbound attack wearing this host's address".
 * Everything below the presentation layer is therefore preserved exactly.
 *
 * ── Preserved without change (Checkpoint 3C batch 7) ────────────────────────
 *   * `webScansApi.startScan({ ...formData, _idempotencyKey })` — same call,
 *     same argument shape, so `normalizeStartPayload` and `normalizeAuthConfig`
 *     receive byte-identical input and the wire payload is unchanged. That
 *     includes the `btoa` basic-auth encoding, which is NOT touched here;
 *   * the idempotency key: created once per attempt, reused for the in-flight
 *     request, and cleared on failure so a retry is a new logical request.
 *     That last part is a real design question and is recorded under
 *     out-of-scope findings rather than changed;
 *   * `submitInFlightRef` double-submit guard, including the fact that it is
 *     NOT reset on success — after a successful dispatch this form cannot fire
 *     again, which is correct because it navigates away;
 *   * the `authorization_confirmed` gate, in both places it exists: the handler
 *     refuses without it, and the submit control is disabled without it;
 *   * scan-id extraction (`id` → `web_scan_id` → `data.id`) and the deliberate
 *     failure when none is present;
 *   * the error message precedence: API `detail`, then `err.message`, then the
 *     generic string;
 *   * `parseInt(...) || 3` and `|| 10` on depth and concurrency, quirk included
 *     (see out-of-scope findings);
 *   * navigation: `navigate(id, { replace: true })` on success, `navigate(-1)`
 *     on cancel.
 *
 * ── Intentionally changed: presentation and accessibility only ──────────────
 * The pre-migration form rendered **ten `<label>` elements, none carrying
 * `htmlFor`**, with every input as the label's *sibling* rather than its child.
 * Not one text, url, number or select control on this form had an accessible
 * name — including the target URL and the basic-auth credentials. The error
 * banner was a plain `<div>`, so a refused launch was never announced.
 *
 * ── Why NOT CcurePasswordField ─────────────────────────────────────────────
 * It owns a visibility toggle, a caps-lock warning and a strength meter. The
 * first would change this page's password-visibility behaviour, which this
 * batch may not do; the third is meaningless for a credential the operator is
 * supplying to authenticate against somebody else's site — it is not a password
 * being chosen. `CcureInput type="password"` is the right primitive here.
 */
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { useAuth } from "@shell/auth/AuthContext";
import { can } from "@shell/auth/permissions";
import { webScansApi } from "../api/webScansApi";
import {
  CcureAlert,
  CcureButton,
  CcureCard,
  CcureInput,
  CcureSelect,
} from "../../../../design-system";
import "../styles/web-scanning-pages.css";

const createLaunchKey = () => {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  return `webscan-${Date.now()}-${Math.random().toString(36).slice(2)}`;
};

export default function NewWebScan() {
  const navigate = useNavigate();
  const { user } = useAuth();
  // Launching sends active attack traffic at the target; the API requires
  // Run scans, so the control is not offered to a role that lacks it.
  const canLaunch = can(user, "audit.scan.run");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [launchMessage, setLaunchMessage] = useState("");
  const submitInFlightRef = useRef(false);
  const launchKeyRef = useRef(null);

  const [formData, setFormData] = useState({
    scan_name: "",
    target_url: "",
    authorization_confirmed: false,
    options: {
      depth: 3,
      include_subdomains: false,
      concurrency: 10,
    },
    auth_config: {
      type: "none", // none, bearer, cookie, basic
      token: "",
      username: "",
      password: "",
    },
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (submitInFlightRef.current) return;

    if (!formData.authorization_confirmed) {
      setError("You must confirm authorization to scan this target.");
      return;
    }

    try {
      submitInFlightRef.current = true;
      launchKeyRef.current = launchKeyRef.current || createLaunchKey();
      setLoading(true);
      setError("");
      setLaunchMessage(
        "Starting scan. Creating the scan record and queueing the first pipeline task...",
      );
      const res = await webScansApi.startScan({
        ...formData,
        _idempotencyKey: launchKeyRef.current,
      });
      const scanId =
        res.data?.id || res.data?.web_scan_id || res.data?.data?.id;
      if (scanId) {
        setLaunchMessage("Scan queued. Opening live scan status...");
        navigate(`/web-scans/${scanId}`, { replace: true });
        return;
      }
      throw new Error("Scan started but the API did not return a scan id.");
    } catch (err) {
      console.error("Failed to start scan", err);
      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to launch scan. Check the target URL.",
      );
      submitInFlightRef.current = false;
      launchKeyRef.current = null;
      setLaunchMessage("");
    } finally {
      setLoading(false);
    }
  };

  const handleOptChange = (key, value) => {
    setFormData((prev) => ({
      ...prev,
      options: { ...prev.options, [key]: value },
    }));
  };

  const handleAuthChange = (key, value) => {
    setFormData((prev) => ({
      ...prev,
      auth_config: { ...prev.auth_config, [key]: value },
    }));
  };

  const authType = formData.auth_config.type;

  /* The page is reachable by URL even with the buttons hidden. Say why the
     form is absent rather than rendering one whose submit can only fail. */
  if (!canLaunch) {
    return (
      <AppLayout pageTitle="New Web Scan">
        <div className="page-inner wsp-page wsp-page--form">
          <div className="wsp-form-intro">
            <h1 className="page-title">Configure Web Scan</h1>
          </div>
          <CcureAlert variant="info" className="wsp-form-message">
            Your role cannot launch web scans. A web scan sends active test
            traffic (SQL injection, fuzzing and template probes) at the target,
            so it requires the <code>Run scans</code> permission. Ask an
            organisation administrator if you need it.
          </CcureAlert>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout pageTitle="New Web Scan">
      <div className="page-inner wsp-page wsp-page--form">
        <div className="wsp-form-intro">
          <h1 className="page-title">Configure Web Scan</h1>
          <p className="page-subtitle">
            Set up target, authentication, and crawling depth.
          </p>
        </div>

        {/* `CcureAlert variant="danger"` carries role="alert". The previous
            plain <div> meant a refused launch was never announced — on the one
            control in this product that fires an outbound scan. */}
        {error && (
          <CcureAlert variant="danger" className="wsp-form-message">
            {error}
          </CcureAlert>
        )}

        {/* Polite, and role="status" exactly as before: this is a progress
            report, not an interruption. */}
        {launchMessage && (
          <CcureAlert variant="info" className="wsp-form-message">
            {launchMessage}
          </CcureAlert>
        )}

        <form onSubmit={handleSubmit} className="wsp-form">
          <CcureCard title="Target Details" headingLevel={2}>
            <CcureInput
              id="webscan-name"
              label="Scan Name"
              placeholder="e.g. Production API Audit"
              value={formData.scan_name}
              onChange={(e) =>
                setFormData({ ...formData, scan_name: e.target.value })
              }
              required
            />
            <CcureInput
              id="webscan-target"
              type="url"
              label="Target URL"
              placeholder="https://example.com"
              hint="The scanner will send active requests to this address."
              value={formData.target_url}
              onChange={(e) =>
                setFormData({ ...formData, target_url: e.target.value })
              }
              required
            />
          </CcureCard>

          <CcureCard title="Crawler Options" headingLevel={2}>
            <div className="wsp-form-grid">
              <CcureInput
                id="webscan-depth"
                type="number"
                min="1"
                max="10"
                label="Crawl Depth"
                value={formData.options.depth}
                onChange={(e) =>
                  handleOptChange("depth", parseInt(e.target.value) || 3)
                }
              />
              <CcureInput
                id="webscan-concurrency"
                type="number"
                min="1"
                max="50"
                label="Concurrency (Threads)"
                value={formData.options.concurrency}
                onChange={(e) =>
                  handleOptChange("concurrency", parseInt(e.target.value) || 10)
                }
              />
            </div>

            {/* The checkbox stays inside its <label>, which is how the
                pre-migration page associated these two — the only two controls
                on the form that were labelled at all. */}
            <label className="wsp-check">
              <input
                type="checkbox"
                checked={formData.options.include_subdomains}
                onChange={(e) =>
                  handleOptChange("include_subdomains", e.target.checked)
                }
              />
              <span>Include Discovered Subdomains</span>
            </label>
          </CcureCard>

          <CcureCard title="Authentication" headingLevel={2}>
            <CcureSelect
              id="webscan-auth-type"
              label="Auth Type"
              value={authType}
              onChange={(e) => handleAuthChange("type", e.target.value)}
            >
              <option value="none">None (Unauthenticated)</option>
              <option value="bearer">Bearer Token</option>
              <option value="cookie">Session Cookie</option>
              <option value="basic">Basic Auth</option>
            </CcureSelect>

            {authType === "bearer" || authType === "cookie" ? (
              <CcureInput
                id="webscan-auth-token"
                label={authType === "bearer" ? "Token" : "Cookie String"}
                hint={
                  authType === "bearer"
                    ? "Sent to the target as a bearer token."
                    : "name=value pairs, separated by semicolons."
                }
                value={formData.auth_config.token}
                onChange={(e) => handleAuthChange("token", e.target.value)}
              />
            ) : null}

            {authType === "basic" ? (
              <div className="wsp-form-grid">
                <CcureInput
                  id="webscan-auth-username"
                  label="Username"
                  value={formData.auth_config.username}
                  onChange={(e) => handleAuthChange("username", e.target.value)}
                />
                {/* type="password" and nothing more. No visibility toggle: this
                    page's password-visibility behaviour is preserved. */}
                <CcureInput
                  id="webscan-auth-password"
                  type="password"
                  label="Password"
                  value={formData.auth_config.password}
                  onChange={(e) => handleAuthChange("password", e.target.value)}
                />
              </div>
            ) : null}
          </CcureCard>

          {/* The agreement panel. Amber is not the message — the words are, and
              they are what a reader without colour perception gets. */}
          <div className="wsp-agreement">
            <label className="wsp-check wsp-check--block">
              <input
                type="checkbox"
                checked={formData.authorization_confirmed}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    authorization_confirmed: e.target.checked,
                  })
                }
              />
              <span className="wsp-agreement-text">
                <strong className="wsp-agreement-title">
                  Authorization Agreement:
                </strong>{" "}
                I confirm that I am explicitly authorized to perform security
                scanning on this target. I understand that active scanning may
                cause performance degradation or data modification on the target
                system.
              </span>
            </label>
          </div>

          <div className="wsp-form-actions">
            <CcureButton
              type="button"
              variant="secondary"
              onClick={() => navigate(-1)}
              disabled={loading}
            >
              Cancel
            </CcureButton>
            <CcureButton
              type="submit"
              disabled={loading || !formData.authorization_confirmed}
              aria-busy={loading ? "true" : undefined}
            >
              {loading ? "Starting Scan..." : "Launch Scan"}
            </CcureButton>
          </div>
        </form>
      </div>
    </AppLayout>
  );
}
