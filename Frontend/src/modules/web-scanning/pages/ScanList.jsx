import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";
import Skeleton from "../../../components/common/Skeleton";

const getStatusColor = (status) => {
  const s = status?.toLowerCase() || "";
  if (s === "complete" || s === "completed") return "var(--ok)";
  if (s === "running") return "var(--info)";
  if (s === "queued" || s === "pending") return "var(--warning)";
  if (s === "failed") return "var(--danger)";
  if (s === "cancelled") return "var(--warning)";
  return "var(--text-muted)";
};

export default function ScanList() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchScans() {
      try {
        setLoading(true);
        const res = await webScansApi.getScans({ per_page: 100 });
        setScans(res.data?.data || res.data?.items || []);
      } catch (err) {
        console.error("Failed to load scans", err);
      } finally {
        setLoading(false);
      }
    }
    fetchScans();
  }, []);

  return (
    <AppLayout pageTitle="Web Scans">
      <div
        className="page-inner"
        style={{ maxWidth: "1400px", margin: "0 auto", padding: "24px" }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "24px",
          }}
        >
          <div>
            <h1 className="page-title">Web Scans</h1>
            <p className="page-subtitle">Manage and monitor DAST assessments</p>
          </div>
          <button
            className="btn btn--primary"
            onClick={() => navigate("/web-scans/new")}
          >
            + New Scan
          </button>
        </div>

        <div
          style={{
            background: "var(--bg-panel)",
            borderRadius: "12px",
            border: "1px solid var(--border)",
            overflow: "hidden",
          }}
        >
          {loading ? (
            <div
              style={{
                padding: "24px",
                display: "flex",
                flexDirection: "column",
                gap: "16px",
              }}
            >
              <Skeleton height="40px" borderRadius="8px" />
              <Skeleton height="60px" borderRadius="8px" />
              <Skeleton height="60px" borderRadius="8px" />
              <Skeleton height="60px" borderRadius="8px" />
            </div>
          ) : scans.length === 0 ? (
            <div
              style={{
                padding: "60px 20px",
                textAlign: "center",
                color: "var(--text-muted)",
              }}
            >
              <div style={{ fontSize: "2rem", marginBottom: "16px" }}>🕸️</div>
              <h3>No Web Scans Found</h3>
              <p>Create your first scan to begin vulnerability assessment.</p>
            </div>
          ) : (
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                textAlign: "left",
              }}
            >
              <thead>
                <tr
                  style={{
                    background: "rgba(0,0,0,0.2)",
                    borderBottom: "1px solid var(--border)",
                  }}
                >
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    SCAN NAME
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    TARGET
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    STATUS
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    PHASE
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    FINDINGS
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    DATE
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                      textAlign: "right",
                    }}
                  >
                    ACTIONS
                  </th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    style={{ borderBottom: "1px solid var(--border)" }}
                  >
                    <td style={{ padding: "16px", fontWeight: "500" }}>
                      <button
                        onClick={() => navigate(`/web-scans/${scan.id}`)}
                        style={{
                          background: "none",
                          border: "none",
                          color: "var(--text)",
                          cursor: "pointer",
                          textAlign: "left",
                          fontWeight: "600",
                          padding: 0,
                        }}
                      >
                        {scan.scan_name}
                      </button>
                    </td>
                    <td
                      style={{
                        padding: "16px",
                        color: "var(--text-muted)",
                        fontSize: "0.9rem",
                      }}
                    >
                      {scan.target_url}
                    </td>
                    <td style={{ padding: "16px" }}>
                      <span
                        style={{
                          padding: "4px 10px",
                          borderRadius: "12px",
                          fontSize: "0.75rem",
                          fontWeight: "bold",
                          textTransform: "uppercase",
                          color: getStatusColor(scan.status),
                          border: `1px solid ${getStatusColor(scan.status)}40`,
                          background: `${getStatusColor(scan.status)}15`,
                        }}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td
                      style={{
                        padding: "16px",
                        fontSize: "0.85rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      {scan.pipeline_phase || "-"}
                    </td>
                    <td style={{ padding: "16px" }}>
                      <div style={{ display: "flex", gap: "8px" }}>
                        {scan.critical_count > 0 && (
                          <span
                            style={{
                              fontSize: "0.75rem",
                              background: "var(--danger)",
                              color: "#fff",
                              padding: "2px 6px",
                              borderRadius: "4px",
                            }}
                          >
                            {scan.critical_count} C
                          </span>
                        )}
                        {scan.high_count > 0 && (
                          <span
                            style={{
                              fontSize: "0.75rem",
                              background: "var(--warning)",
                              color: "#fff",
                              padding: "2px 6px",
                              borderRadius: "4px",
                            }}
                          >
                            {scan.high_count} H
                          </span>
                        )}
                        {scan.critical_count === 0 && scan.high_count === 0 && (
                          <span
                            style={{
                              color: "var(--text-muted)",
                              fontSize: "0.85rem",
                            }}
                          >
                            -
                          </span>
                        )}
                      </div>
                    </td>
                    <td
                      style={{
                        padding: "16px",
                        fontSize: "0.85rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td style={{ padding: "16px", textAlign: "right" }}>
                      <button
                        className="btn btn--outline"
                        style={{ padding: "4px 12px", fontSize: "0.8rem" }}
                        onClick={() => navigate(`/web-scans/${scan.id}`)}
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
