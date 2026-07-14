import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";
import Skeleton from "../../../components/common/Skeleton";

const getMethodColor = (method) => {
  const m = method?.toUpperCase() || "";
  if (m === "GET") return "var(--info)";
  if (m === "POST") return "var(--ok)";
  if (m === "PUT") return "var(--warning)";
  if (m === "DELETE") return "var(--danger)";
  return "var(--text-muted)";
};

export default function AssetInventory() {
  const { id } = useParams();
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    async function fetchAssets() {
      try {
        setLoading(true);
        const res = await webScansApi.getAssets(id, { per_page: 200 });
        setAssets(res.data?.data || res.data?.items || []);
      } catch (err) {
        console.error("Failed to load assets", err);
      } finally {
        setLoading(false);
      }
    }
    fetchAssets();
  }, [id]);

  const filteredAssets = assets.filter(
    (a) =>
      a.url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.content_type?.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  return (
    <AppLayout pageTitle="Asset Inventory">
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
            <Link
              to={`/web-scans/${id}`}
              style={{
                fontSize: "0.85rem",
                color: "var(--accent)",
                textDecoration: "none",
                marginBottom: "8px",
                display: "inline-block",
              }}
            >
              ← Back to Scan Detail
            </Link>
            <h1 className="page-title" style={{ margin: 0 }}>
              Asset Inventory
            </h1>
            <p className="page-subtitle">
              Discovered endpoints, APIs, and technologies
            </p>
          </div>
          <div style={{ width: "300px" }}>
            <input
              type="text"
              placeholder="Search URLs or Content-Types..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="form-input"
              style={{
                width: "100%",
                padding: "10px 12px",
                borderRadius: "6px",
                border: "1px solid var(--border)",
                background: "var(--bg-app)",
                color: "var(--text)",
              }}
            />
          </div>
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
              <Skeleton height="50px" borderRadius="8px" />
              <Skeleton height="50px" borderRadius="8px" />
              <Skeleton height="50px" borderRadius="8px" />
              <Skeleton height="50px" borderRadius="8px" />
            </div>
          ) : filteredAssets.length === 0 ? (
            <div
              style={{
                padding: "60px 20px",
                textAlign: "center",
                color: "var(--text-muted)",
              }}
            >
              <div style={{ fontSize: "2rem", marginBottom: "16px" }}>📂</div>
              <h3>No Assets Found</h3>
              <p>The scanner has not discovered any unique endpoints yet.</p>
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
                    METHOD
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    URL
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
                    CONTENT TYPE
                  </th>
                  <th
                    style={{
                      padding: "16px",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      color: "var(--text-muted)",
                      textAlign: "center",
                    }}
                  >
                    FLAGS
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
                    SIZE / TIME
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredAssets.map((asset) => (
                  <tr
                    key={asset.id}
                    style={{ borderBottom: "1px solid var(--border)" }}
                  >
                    <td
                      style={{
                        padding: "16px",
                        fontWeight: "bold",
                        fontSize: "0.85rem",
                        color: getMethodColor(asset.method),
                      }}
                    >
                      {asset.method || "GET"}
                    </td>
                    <td
                      style={{
                        padding: "16px",
                        color: "var(--text)",
                        wordBreak: "break-all",
                      }}
                    >
                      <a
                        href={asset.url}
                        target="_blank"
                        rel="noreferrer"
                        style={{ color: "var(--text)", textDecoration: "none" }}
                      >
                        {asset.url}
                      </a>
                    </td>
                    <td style={{ padding: "16px" }}>
                      <span
                        style={{
                          color:
                            asset.response_code >= 400
                              ? "var(--danger)"
                              : asset.response_code >= 300
                                ? "var(--warning)"
                                : "var(--ok)",
                          fontWeight: "bold",
                          fontSize: "0.9rem",
                        }}
                      >
                        {asset.response_code || 200}
                      </span>
                    </td>
                    <td
                      style={{
                        padding: "16px",
                        fontSize: "0.85rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      {asset.content_type || "text/html"}
                    </td>
                    <td style={{ padding: "16px", textAlign: "center" }}>
                      <div
                        style={{
                          display: "flex",
                          gap: "8px",
                          justifyContent: "center",
                        }}
                      >
                        {asset.auth_required && (
                          <span
                            title="Auth Required"
                            style={{ fontSize: "1.1rem" }}
                          >
                            🔒
                          </span>
                        )}
                        {asset.is_api && (
                          <span
                            title="API Endpoint"
                            style={{ fontSize: "1.1rem" }}
                          >
                            ⚙️
                          </span>
                        )}
                        {asset.is_form && (
                          <span
                            title="HTML Form"
                            style={{ fontSize: "1.1rem" }}
                          >
                            📝
                          </span>
                        )}
                        {asset.has_file_upload && (
                          <span
                            title="File Upload"
                            style={{ fontSize: "1.1rem" }}
                          >
                            📤
                          </span>
                        )}
                      </div>
                    </td>
                    <td
                      style={{
                        padding: "16px",
                        textAlign: "right",
                        fontSize: "0.85rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      <div>
                        {asset.response_size
                          ? `${(asset.response_size / 1024).toFixed(1)} KB`
                          : "-"}
                      </div>
                      <div style={{ fontSize: "0.75rem", marginTop: "4px" }}>
                        {asset.response_time ? `${asset.response_time}s` : "-"}
                      </div>
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
