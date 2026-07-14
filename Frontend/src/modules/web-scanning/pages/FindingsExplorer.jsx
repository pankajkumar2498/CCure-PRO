import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";
import Skeleton from "../../../components/common/Skeleton";

const getSeverityColor = (severity) => {
  const s = severity?.toLowerCase() || "";
  if (s === "critical") return "var(--danger)";
  if (s === "high") return "var(--warning)";
  if (s === "medium") return "var(--info)";
  if (s === "low") return "var(--ok)";
  return "var(--text-muted)";
};

export default function FindingsExplorer() {
  const { id } = useParams();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => {
    async function fetchFindings() {
      try {
        setLoading(true);
        const res = await webScansApi.getFindings(id, { per_page: 200 });
        setFindings(res.data?.data || res.data?.items || []);
      } catch (err) {
        console.error("Failed to load findings", err);
      } finally {
        setLoading(false);
      }
    }
    fetchFindings();
  }, [id]);

  const handleStatusChange = async (findingId, newStatus) => {
    try {
      await webScansApi.updateFindingStatus(id, findingId, {
        status: newStatus,
      });
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f)),
      );
      if (selectedFinding?.id === findingId) {
        setSelectedFinding({ ...selectedFinding, status: newStatus });
      }
    } catch (err) {
      console.error("Failed to update status", err);
      alert("Failed to update finding status.");
    }
  };

  return (
    <AppLayout pageTitle="Findings Explorer">
      <div
        className="page-inner"
        style={{
          maxWidth: "1600px",
          margin: "0 auto",
          padding: "24px",
          display: "flex",
          gap: "24px",
          height: "calc(100vh - 100px)",
        }}
      >
        {/* Left List */}
        <div
          style={{
            flex: selectedFinding ? "1" : "1",
            background: "var(--bg-panel)",
            borderRadius: "12px",
            border: "1px solid var(--border)",
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              padding: "20px",
              borderBottom: "1px solid var(--border)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <Link
                to={`/web-scans/${id}`}
                style={{
                  fontSize: "0.85rem",
                  color: "var(--accent)",
                  textDecoration: "none",
                  marginBottom: "8px",
                  display: "block",
                }}
              >
                ← Back to Scan Detail
              </Link>
              <h2 style={{ margin: 0, fontSize: "1.2rem" }}>
                Vulnerabilities ({findings.length})
              </h2>
            </div>
            {/* Filters could go here */}
          </div>

          <div style={{ flex: 1, overflowY: "auto" }}>
            {loading ? (
              <div
                style={{
                  padding: "20px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "12px",
                }}
              >
                <Skeleton height="64px" borderRadius="6px" />
                <Skeleton height="64px" borderRadius="6px" />
                <Skeleton height="64px" borderRadius="6px" />
                <Skeleton height="64px" borderRadius="6px" />
                <Skeleton height="64px" borderRadius="6px" />
              </div>
            ) : findings.length === 0 ? (
              <div
                style={{
                  padding: "40px",
                  textAlign: "center",
                  color: "var(--text-muted)",
                }}
              >
                No findings discovered.
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column" }}>
                {findings.map((finding) => (
                  <div
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    style={{
                      padding: "16px 20px",
                      borderBottom: "1px solid var(--border)",
                      cursor: "pointer",
                      background:
                        selectedFinding?.id === finding.id
                          ? "var(--bg-app)"
                          : "transparent",
                      borderLeft: `4px solid ${getSeverityColor(finding.severity)}`,
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        marginBottom: "8px",
                      }}
                    >
                      <span
                        style={{
                          fontWeight: "600",
                          fontSize: "0.95rem",
                          color: "var(--text)",
                        }}
                      >
                        {finding.title}
                      </span>
                      <span
                        style={{
                          fontSize: "0.75rem",
                          padding: "2px 8px",
                          borderRadius: "12px",
                          background: `${getSeverityColor(finding.severity)}20`,
                          color: getSeverityColor(finding.severity),
                          fontWeight: "bold",
                          textTransform: "uppercase",
                        }}
                      >
                        {finding.severity}
                      </span>
                    </div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        fontSize: "0.8rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      <span>
                        {finding.request_method || "GET"}{" "}
                        {finding.request_url?.substring(0, 40)}
                        {finding.request_url?.length > 40 ? "..." : ""}
                      </span>
                      <span>{finding.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Detail Pane */}
        {selectedFinding && (
          <div
            style={{
              flex: "2",
              background: "var(--bg-panel)",
              borderRadius: "12px",
              border: "1px solid var(--border)",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "24px",
                borderBottom: "1px solid var(--border)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: "16px",
                }}
              >
                <h2 style={{ margin: 0, fontSize: "1.4rem" }}>
                  {selectedFinding.title}
                </h2>
                <button
                  onClick={() => setSelectedFinding(null)}
                  style={{
                    background: "none",
                    border: "none",
                    color: "var(--text-muted)",
                    cursor: "pointer",
                    fontSize: "1.2rem",
                  }}
                >
                  ×
                </button>
              </div>
              <div
                style={{ display: "flex", gap: "12px", marginBottom: "16px" }}
              >
                <span
                  style={{
                    padding: "4px 10px",
                    borderRadius: "4px",
                    background: `${getSeverityColor(selectedFinding.severity)}20`,
                    color: getSeverityColor(selectedFinding.severity),
                    fontWeight: "bold",
                    fontSize: "0.85rem",
                    textTransform: "uppercase",
                  }}
                >
                  {selectedFinding.severity}
                </span>
                <span
                  style={{
                    padding: "4px 10px",
                    borderRadius: "4px",
                    background: "var(--bg-app)",
                    border: "1px solid var(--border)",
                    fontSize: "0.85rem",
                    color: "var(--text-muted)",
                  }}
                >
                  {selectedFinding.finding_type}
                </span>
                {selectedFinding.cve_id && (
                  <span
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      background: "var(--bg-app)",
                      border: "1px solid var(--border)",
                      fontSize: "0.85rem",
                      color: "var(--info)",
                    }}
                  >
                    {selectedFinding.cve_id}
                  </span>
                )}
                {selectedFinding.owasp_category && (
                  <span
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      background: "var(--bg-app)",
                      border: "1px solid var(--border)",
                      fontSize: "0.85rem",
                      color: "var(--warning)",
                    }}
                  >
                    OWASP: {selectedFinding.owasp_category}
                  </span>
                )}
              </div>

              <div style={{ display: "flex", gap: "12px", marginTop: "16px" }}>
                <select
                  style={{
                    padding: "6px 12px",
                    borderRadius: "6px",
                    background: "var(--bg-app)",
                    border: "1px solid var(--border)",
                    color: "var(--text)",
                    outline: "none",
                  }}
                  value={selectedFinding.status}
                  onChange={(e) =>
                    handleStatusChange(selectedFinding.id, e.target.value)
                  }
                >
                  <option value="open">Open</option>
                  <option value="confirmed">Confirmed</option>
                  <option value="false_positive">False Positive</option>
                  <option value="accepted_risk">Accepted Risk</option>
                  <option value="fixed">Fixed</option>
                </select>
              </div>
            </div>

            <div style={{ flex: 1, overflowY: "auto", padding: "24px" }}>
              <div style={{ marginBottom: "32px" }}>
                <h3
                  style={{
                    fontSize: "1rem",
                    marginBottom: "8px",
                    color: "var(--text)",
                  }}
                >
                  Description
                </h3>
                <p
                  style={{
                    color: "var(--text-muted)",
                    lineHeight: "1.6",
                    fontSize: "0.95rem",
                  }}
                >
                  {selectedFinding.description || "No description provided."}
                </p>
              </div>

              {(selectedFinding.request_method ||
                selectedFinding.request_url) && (
                <div style={{ marginBottom: "32px" }}>
                  <h3
                    style={{
                      fontSize: "1rem",
                      marginBottom: "8px",
                      color: "var(--text)",
                    }}
                  >
                    Endpoint
                  </h3>
                  <div
                    style={{
                      background: "var(--bg-app)",
                      padding: "12px",
                      borderRadius: "6px",
                      border: "1px solid var(--border)",
                      fontFamily: "monospace",
                      color: "var(--accent)",
                    }}
                  >
                    {selectedFinding.request_method}{" "}
                    {selectedFinding.request_url}
                  </div>
                </div>
              )}

              {selectedFinding.request_body && (
                <div style={{ marginBottom: "32px" }}>
                  <h3
                    style={{
                      fontSize: "1rem",
                      marginBottom: "8px",
                      color: "var(--text)",
                    }}
                  >
                    Request Body Evidence
                  </h3>
                  <pre
                    style={{
                      background: "#1e1e1e",
                      color: "#d4d4d4",
                      padding: "16px",
                      borderRadius: "6px",
                      overflowX: "auto",
                      fontSize: "0.85rem",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {selectedFinding.request_body}
                  </pre>
                </div>
              )}

              {selectedFinding.response_body && (
                <div style={{ marginBottom: "32px" }}>
                  <h3
                    style={{
                      fontSize: "1rem",
                      marginBottom: "8px",
                      color: "var(--text)",
                    }}
                  >
                    Response Evidence
                  </h3>
                  <pre
                    style={{
                      background: "#1e1e1e",
                      color: "#d4d4d4",
                      padding: "16px",
                      borderRadius: "6px",
                      overflowX: "auto",
                      fontSize: "0.85rem",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {selectedFinding.response_body.substring(0, 2000)}
                    {selectedFinding.response_body.length > 2000
                      ? "\n...[truncated]"
                      : ""}
                  </pre>
                </div>
              )}

              {selectedFinding.curl_command && (
                <div style={{ marginBottom: "32px" }}>
                  <h3
                    style={{
                      fontSize: "1rem",
                      marginBottom: "8px",
                      color: "var(--text)",
                    }}
                  >
                    Reproduction (cURL)
                  </h3>
                  <pre
                    style={{
                      background: "#1e1e1e",
                      color: "#d4d4d4",
                      padding: "16px",
                      borderRadius: "6px",
                      overflowX: "auto",
                      fontSize: "0.85rem",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {selectedFinding.curl_command}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
