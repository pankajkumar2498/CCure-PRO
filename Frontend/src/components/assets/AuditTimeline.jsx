import React, { useState } from "react";
import "../../styles/audit-timeline.css";

function ago(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (isNaN(date.getTime())) return "—";
  const now = new Date();
  const nowMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const dateMidnight = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  const d = Math.round((nowMidnight - dateMidnight) / 86400000);
  if (d <= 0) return "Today";
  if (d === 1) return "Yesterday";
  return `${d}d ago`;
}

function formatTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function TechDetailsPanel({ rawEvent }) {
  if (!rawEvent) return null;
  return (
    <div className="audit-tech-panel">
      <pre>{JSON.stringify(rawEvent, null, 2)}</pre>
    </div>
  );
}

function EventRow({ event, rawEvent }) {
  const [showTech, setShowTech] = useState(false);
  const sevClass = event.severity ? `audit-sev-badge--${event.severity.toLowerCase()}` : "audit-sev-badge--info";

  return (
    <div className="audit-event-row">
      <div className="audit-event-indicator">{event.icon || "📌"}</div>
      
      <div className="audit-event-content">
        <div className="audit-event-header">
          <div className="audit-event-title">
            {event.event_title}
            {event.is_new_discovery && (
              <span style={{ 
                display: "inline-block", 
                width: 6, height: 6, 
                borderRadius: "50%", 
                background: "var(--ok)", 
                marginLeft: 4, 
                boxShadow: "0 0 4px var(--ok)"
              }} title="New Discovery" />
            )}
          </div>
          <div className="audit-event-badges">
            <span className={`audit-sev-badge ${sevClass}`}>{event.severity}</span>
            <span className="audit-category-badge">{event.category.replace("_", " ")}</span>
          </div>
        </div>

        {event.is_new_discovery ? (
          <div className="audit-discovery-text">
            {event.event_description}
          </div>
        ) : event.change_type === "field_update" ? (
          <div className="audit-change-display">
            <div className="audit-value-box audit-value-box--old">
              {event.old_value_display || "Unknown"}
            </div>
            <div className="audit-change-arrow">→</div>
            <div className="audit-value-box audit-value-box--new">
              {event.new_value_display || "Unknown"}
            </div>
          </div>
        ) : (
          <div className="audit-discovery-text">
            {event.event_description}
          </div>
        )}

        <div className="audit-tech-toggle">
          <button type="button" className="audit-tech-btn" onClick={() => setShowTech(!showTech)}>
            {showTech ? "Hide Technical Details" : "View Technical Details"}
          </button>
          {showTech && <TechDetailsPanel rawEvent={rawEvent} />}
        </div>
      </div>
    </div>
  );
}

function ScanGroupCard({ group, rawChangelog }) {
  const [expanded, setExpanded] = useState(false);
  
  const sevClass = group.highest_severity 
    ? `audit-group-card--${group.highest_severity.toLowerCase()}` 
    : "audit-group-card--info";

  return (
    <div className={`audit-group-card ${sevClass} ${expanded ? "expanded" : ""}`}>
      <div className="audit-group-header" onClick={() => setExpanded(!expanded)}>
        <div className="audit-group-info">
          <div className="audit-group-icon">{group.group_icon}</div>
          <div>
            <div className="audit-group-title">{group.summary_title}</div>
            <div className="audit-group-subtitle">{group.summary_subtitle}</div>
          </div>
        </div>
        <div className="audit-group-meta">
          <div className="audit-group-time">
            {ago(group.detected_at)} ({formatTime(group.detected_at)})
          </div>
          <div className="audit-group-chevron">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </div>
        </div>
      </div>

      {expanded && (
        <div className="audit-group-body">
          {group.events.map((event) => {
            const rawEvent = rawChangelog.find(r => r.id === event.id);
            return <EventRow key={event.id} event={event} rawEvent={rawEvent} />;
          })}
        </div>
      )}
    </div>
  );
}

export default function AuditTimeline({ changelogData }) {
  const [activeCategory, setActiveCategory] = useState("all");
  const [viewMode, setViewMode] = useState("timeline"); // timeline | admin

  // If we haven't loaded or there's no data
  if (!changelogData || !changelogData.timeline) {
    return (
      <div className="audit-empty">
        <div className="audit-empty-icon">⏳</div>
        <div className="audit-empty-title">Loading Timeline...</div>
      </div>
    );
  }

  const { timeline, raw_changelog, admin_logs, category_meta } = changelogData;

  // Render empty state if absolutely no events
  if (timeline.length === 0 && raw_changelog?.length === 0) {
    return (
      <div className="audit-empty">
        <div className="audit-empty-icon">📭</div>
        <div className="audit-empty-title">No Audit Logs</div>
        <div className="audit-empty-text">No activity or changes have been recorded for this asset yet.</div>
      </div>
    );
  }

  // Filter groups if a category is selected
  const filteredTimeline = activeCategory === "all" 
    ? timeline 
    : timeline.map(group => ({
        ...group,
        events: group.events.filter(e => e.category === activeCategory)
      })).filter(group => group.events.length > 0);

  return (
    <div className="audit-timeline-container">
      {/* Header & Controls */}
      <div className="audit-header">
        <div className="audit-title-block">
          <h3>Asset Activity Timeline</h3>
          <p>Complete history of discoveries, changes, and lifecycle events.</p>
        </div>
        <div className="audit-controls">
          <div className="db-tabs" style={{ marginBottom: 0 }}>
            <button 
              className={`db-tab ${viewMode === "timeline" ? "active" : ""}`}
              onClick={() => setViewMode("timeline")}
            >
              Activity Timeline
            </button>
            <button 
              className={`db-tab ${viewMode === "admin" ? "active" : ""}`}
              onClick={() => setViewMode("admin")}
            >
              Administrative Audit
            </button>
          </div>
        </div>
      </div>

      {viewMode === "timeline" ? (
        <>
          {/* Category Filter Pills */}
          {category_meta && Object.keys(category_meta).length > 0 && (
            <div className="audit-filter-bar">
              <button 
                className={`audit-filter-pill ${activeCategory === "all" ? "active" : ""}`}
                onClick={() => setActiveCategory("all")}
              >
                <span className="audit-filter-icon">🔍</span> All Events
              </button>
              {Object.entries(category_meta).map(([catId, meta]) => {
                // Only show categories that exist in our data
                if (!changelogData.categories?.includes(catId)) return null;
                return (
                  <button 
                    key={catId}
                    className={`audit-filter-pill ${activeCategory === catId ? "active" : ""}`}
                    onClick={() => setActiveCategory(catId)}
                  >
                    <span className="audit-filter-icon">{meta.icon}</span> {meta.label}
                  </button>
                );
              })}
            </div>
          )}

          {/* Timeline Groups */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {filteredTimeline.length === 0 ? (
              <div className="audit-empty" style={{ padding: "40px 20px" }}>
                <div className="audit-empty-icon">🗂️</div>
                <div className="audit-empty-title">No events match filter</div>
                <div className="audit-empty-text">Try selecting a different category or viewing all events.</div>
                <button 
                  className="db-btn" 
                  style={{ marginTop: 16 }}
                  onClick={() => setActiveCategory("all")}
                >
                  Clear Filters
                </button>
              </div>
            ) : (
              filteredTimeline.map(group => (
                <ScanGroupCard 
                  key={group.group_id} 
                  group={group} 
                  rawChangelog={raw_changelog} 
                />
              ))
            )}
          </div>
        </>
      ) : (
        /* Administrative Audit Trail View */
        <div style={{ position: "relative", paddingLeft: 20, borderLeft: "2px solid var(--border)", marginTop: 20 }}>
          {(!admin_logs || admin_logs.length === 0) ? (
            <div className="audit-empty" style={{ padding: "40px 20px" }}>
              <div className="audit-empty-icon">🛡️</div>
              <div className="audit-empty-title">No Administrative Actions</div>
              <div className="audit-empty-text">No users have performed administrative actions on this asset.</div>
            </div>
          ) : (
            admin_logs.map((log_entry) => (
              <div key={log_entry.id} style={{ marginBottom: 20, position: "relative" }}>
                <div
                  style={{
                    position: "absolute",
                    left: -27,
                    top: 2,
                    width: 12,
                    height: 12,
                    borderRadius: "50%",
                    background: "var(--accent)",
                    border: "3px solid var(--bg-white)",
                  }}
                />
                <div style={{ fontSize: "0.65rem", color: "var(--text-faint)", marginBottom: 4 }}>
                  {formatTime(log_entry.created_at)}
                </div>
                <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text)", display: "flex", alignItems: "center", gap: 8 }}>
                  {log_entry.action.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}
                  <span className={`audit-sev-badge ${log_entry.status === 'success' ? 'audit-sev-badge--low' : 'audit-sev-badge--critical'}`}>
                    {log_entry.status}
                  </span>
                </div>
                <div style={{ fontSize: "0.75rem", color: "var(--text-mid)", marginTop: 4 }}>
                  Actor: <span style={{ fontWeight: 600 }}>{log_entry.user_email}</span>
                </div>
                {log_entry.changes && Object.keys(log_entry.changes).length > 0 && (
                  <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 8 }}>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>Changes:</div>
                    <pre style={{ margin: 0, background: "var(--bg-app)", padding: 8, borderRadius: 6, fontSize: "0.7rem", color: "var(--text-mid)" }}>
                      {JSON.stringify(log_entry.changes, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
