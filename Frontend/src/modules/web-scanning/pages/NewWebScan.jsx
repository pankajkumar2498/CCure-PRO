import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";

const createLaunchKey = () => {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  return `webscan-${Date.now()}-${Math.random().toString(36).slice(2)}`;
};

export default function NewWebScan() {
  const navigate = useNavigate();
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

  return (
    <AppLayout pageTitle="New Web Scan">
      <div
        className="page-inner"
        style={{ maxWidth: "800px", margin: "0 auto", padding: "24px" }}
      >
        <div style={{ marginBottom: "32px" }}>
          <h1 className="page-title">Configure Web Scan</h1>
          <p className="page-subtitle">
            Set up target, authentication, and crawling depth.
          </p>
        </div>

        {error && (
          <div
            style={{
              padding: "16px",
              background: "rgba(239, 68, 68, 0.1)",
              color: "var(--danger)",
              borderRadius: "8px",
              marginBottom: "24px",
              border: "1px solid var(--danger)",
            }}
          >
            {error}
          </div>
        )}

        {launchMessage && (
          <div
            role="status"
            aria-live="polite"
            style={{
              padding: "16px",
              background: "rgba(59, 130, 246, 0.1)",
              color: "var(--info)",
              borderRadius: "8px",
              marginBottom: "24px",
              border: "1px solid var(--info)",
            }}
          >
            {launchMessage}
          </div>
        )}

        <form
          onSubmit={handleSubmit}
          style={{ display: "flex", flexDirection: "column", gap: "24px" }}
        >
          {/* Basic Target Info */}
          <div
            style={{
              background: "var(--bg-panel)",
              padding: "24px",
              borderRadius: "12px",
              border: "1px solid var(--border)",
            }}
          >
            <h3
              style={{
                marginBottom: "16px",
                fontSize: "1.1rem",
                borderBottom: "1px solid var(--border)",
                paddingBottom: "12px",
              }}
            >
              Target Details
            </h3>

            <div className="form-group" style={{ marginBottom: "16px" }}>
              <label
                className="form-label"
                style={{
                  display: "block",
                  marginBottom: "8px",
                  fontSize: "0.9rem",
                  color: "var(--text)",
                }}
              >
                Scan Name
              </label>
              <input
                type="text"
                className="form-input"
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  background: "var(--bg-app)",
                  color: "var(--text)",
                }}
                placeholder="e.g. Production API Audit"
                value={formData.scan_name}
                onChange={(e) =>
                  setFormData({ ...formData, scan_name: e.target.value })
                }
                required
              />
            </div>

            <div className="form-group">
              <label
                className="form-label"
                style={{
                  display: "block",
                  marginBottom: "8px",
                  fontSize: "0.9rem",
                  color: "var(--text)",
                }}
              >
                Target URL
              </label>
              <input
                type="url"
                className="form-input"
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  background: "var(--bg-app)",
                  color: "var(--text)",
                }}
                placeholder="https://example.com"
                value={formData.target_url}
                onChange={(e) =>
                  setFormData({ ...formData, target_url: e.target.value })
                }
                required
              />
            </div>
          </div>

          {/* Crawler Options */}
          <div
            style={{
              background: "var(--bg-panel)",
              padding: "24px",
              borderRadius: "12px",
              border: "1px solid var(--border)",
            }}
          >
            <h3
              style={{
                marginBottom: "16px",
                fontSize: "1.1rem",
                borderBottom: "1px solid var(--border)",
                paddingBottom: "12px",
              }}
            >
              Crawler Options
            </h3>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "20px",
              }}
            >
              <div className="form-group">
                <label
                  className="form-label"
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "0.9rem",
                    color: "var(--text)",
                  }}
                >
                  Crawl Depth
                </label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  className="form-input"
                  style={{
                    width: "100%",
                    padding: "10px 12px",
                    borderRadius: "6px",
                    border: "1px solid var(--border)",
                    background: "var(--bg-app)",
                    color: "var(--text)",
                  }}
                  value={formData.options.depth}
                  onChange={(e) =>
                    handleOptChange("depth", parseInt(e.target.value) || 3)
                  }
                />
              </div>
              <div className="form-group">
                <label
                  className="form-label"
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "0.9rem",
                    color: "var(--text)",
                  }}
                >
                  Concurrency (Threads)
                </label>
                <input
                  type="number"
                  min="1"
                  max="50"
                  className="form-input"
                  style={{
                    width: "100%",
                    padding: "10px 12px",
                    borderRadius: "6px",
                    border: "1px solid var(--border)",
                    background: "var(--bg-app)",
                    color: "var(--text)",
                  }}
                  value={formData.options.concurrency}
                  onChange={(e) =>
                    handleOptChange(
                      "concurrency",
                      parseInt(e.target.value) || 10,
                    )
                  }
                />
              </div>
            </div>

            <div style={{ marginTop: "16px" }}>
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  cursor: "pointer",
                  fontSize: "0.9rem",
                }}
              >
                <input
                  type="checkbox"
                  checked={formData.options.include_subdomains}
                  onChange={(e) =>
                    handleOptChange("include_subdomains", e.target.checked)
                  }
                />
                Include Discovered Subdomains
              </label>
            </div>
          </div>

          {/* Authentication */}
          <div
            style={{
              background: "var(--bg-panel)",
              padding: "24px",
              borderRadius: "12px",
              border: "1px solid var(--border)",
            }}
          >
            <h3
              style={{
                marginBottom: "16px",
                fontSize: "1.1rem",
                borderBottom: "1px solid var(--border)",
                paddingBottom: "12px",
              }}
            >
              Authentication
            </h3>

            <div className="form-group" style={{ marginBottom: "16px" }}>
              <label
                className="form-label"
                style={{
                  display: "block",
                  marginBottom: "8px",
                  fontSize: "0.9rem",
                  color: "var(--text)",
                }}
              >
                Auth Type
              </label>
              <select
                className="form-input"
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                  background: "var(--bg-app)",
                  color: "var(--text)",
                }}
                value={formData.auth_config.type}
                onChange={(e) => handleAuthChange("type", e.target.value)}
              >
                <option value="none">None (Unauthenticated)</option>
                <option value="bearer">Bearer Token</option>
                <option value="cookie">Session Cookie</option>
                <option value="basic">Basic Auth</option>
              </select>
            </div>

            {formData.auth_config.type === "bearer" ||
            formData.auth_config.type === "cookie" ? (
              <div className="form-group">
                <label
                  className="form-label"
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "0.9rem",
                    color: "var(--text)",
                  }}
                >
                  {formData.auth_config.type === "bearer"
                    ? "Token"
                    : "Cookie String"}
                </label>
                <input
                  type="text"
                  className="form-input"
                  style={{
                    width: "100%",
                    padding: "10px 12px",
                    borderRadius: "6px",
                    border: "1px solid var(--border)",
                    background: "var(--bg-app)",
                    color: "var(--text)",
                  }}
                  value={formData.auth_config.token}
                  onChange={(e) => handleAuthChange("token", e.target.value)}
                />
              </div>
            ) : null}

            {formData.auth_config.type === "basic" ? (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "20px",
                }}
              >
                <div className="form-group">
                  <label
                    className="form-label"
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "0.9rem",
                      color: "var(--text)",
                    }}
                  >
                    Username
                  </label>
                  <input
                    type="text"
                    className="form-input"
                    style={{
                      width: "100%",
                      padding: "10px 12px",
                      borderRadius: "6px",
                      border: "1px solid var(--border)",
                      background: "var(--bg-app)",
                      color: "var(--text)",
                    }}
                    value={formData.auth_config.username}
                    onChange={(e) =>
                      handleAuthChange("username", e.target.value)
                    }
                  />
                </div>
                <div className="form-group">
                  <label
                    className="form-label"
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "0.9rem",
                      color: "var(--text)",
                    }}
                  >
                    Password
                  </label>
                  <input
                    type="password"
                    className="form-input"
                    style={{
                      width: "100%",
                      padding: "10px 12px",
                      borderRadius: "6px",
                      border: "1px solid var(--border)",
                      background: "var(--bg-app)",
                      color: "var(--text)",
                    }}
                    value={formData.auth_config.password}
                    onChange={(e) =>
                      handleAuthChange("password", e.target.value)
                    }
                  />
                </div>
              </div>
            ) : null}
          </div>

          {/* Authorization Agreement */}
          <div
            style={{
              background: "rgba(234, 179, 8, 0.05)",
              padding: "16px",
              borderRadius: "8px",
              border: "1px solid var(--warning)",
            }}
          >
            <label
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "12px",
                cursor: "pointer",
                fontSize: "0.9rem",
              }}
            >
              <input
                type="checkbox"
                style={{ marginTop: "4px" }}
                checked={formData.authorization_confirmed}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    authorization_confirmed: e.target.checked,
                  })
                }
              />
              <span style={{ color: "var(--text-muted)" }}>
                <strong style={{ color: "var(--text)" }}>
                  Authorization Agreement:
                </strong>{" "}
                I confirm that I am explicitly authorized to perform security
                scanning on this target. I understand that active scanning may
                cause performance degradation or data modification on the target
                system.
              </span>
            </label>
          </div>

          <div
            style={{ display: "flex", justifyContent: "flex-end", gap: "12px" }}
          >
            <button
              type="button"
              className="btn btn--outline"
              onClick={() => navigate(-1)}
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn--primary"
              disabled={loading || !formData.authorization_confirmed}
              aria-busy={loading ? "true" : undefined}
            >
              {loading ? "Starting Scan..." : "Launch Scan"}
            </button>
          </div>
        </form>
      </div>
    </AppLayout>
  );
}
