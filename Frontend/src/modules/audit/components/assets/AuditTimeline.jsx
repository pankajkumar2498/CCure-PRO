/**
 * src/modules/audit/components/assets/AuditTimeline.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * The asset's activity timeline and administrative audit trail, rendered from
 * the `/assets/{id}/changelog` payload. AssetDetail is its only consumer
 * (SecurityDashboard's `AuditTimeline` is a separate, local component).
 *
 * Checkpoint 3C batch 11: presentation moved onto the CCure design system.
 * The data reads, grouping, filtering and the two view modes are unchanged.
 * What changed for assistive technology: the view switch is a real tab list,
 * the category filters are toggle buttons that say whether they are pressed,
 * a scan group's header is a button that says whether it is expanded, and the
 * "new discovery" dot has a text equivalent. The sixteen inline styles and
 * the `db-tabs` / `db-btn` borrowings from dashboard.css are gone; every
 * colour comes from a CCure token, so the timeline follows the theme.
 */
import { useId, useState } from "react";
import {
  CcureLoader,
  CcureBadge,
  CcureButton,
  CcureEmptyState,
  CcureSeverityBadge,
  CcureTabs,
  CcureTabPanel,
} from "../../../../design-system";
import "../../styles/audit-timeline.css";

function ago(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (isNaN(date.getTime())) return "—";
  const now = new Date();
  const nowMidnight = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
  );
  const dateMidnight = new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
  );
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

function TechDetailsPanel({ id, rawEvent }) {
  if (!rawEvent) return null;
  return (
    <div className="audit-tech-panel" id={id}>
      <pre>{JSON.stringify(rawEvent, null, 2)}</pre>
    </div>
  );
}

function EventRow({ event, rawEvent }) {
  const [showTech, setShowTech] = useState(false);
  const techId = useId();

  return (
    <div className="audit-event-row">
      <div className="audit-event-indicator" aria-hidden="true">
        {event.icon || "📌"}
      </div>

      <div className="audit-event-content">
        <div className="audit-event-header">
          <div className="audit-event-title">
            {event.event_title}
            {event.is_new_discovery && (
              <>
                {/* The dot alone was the only signal; a reader needs the words. */}
                <span
                  className="audit-new-dot"
                  title="New Discovery"
                  aria-hidden="true"
                />
                <span className="cc-sr-only">New discovery</span>
              </>
            )}
          </div>
          <div className="audit-event-badges">
            <CcureSeverityBadge severity={event.severity || "info"} />
            <CcureBadge variant="neutral">
              {event.category.replace("_", " ")}
            </CcureBadge>
          </div>
        </div>

        {event.is_new_discovery ? (
          <div className="audit-discovery-text">{event.event_description}</div>
        ) : event.change_type === "field_update" ? (
          <div className="audit-change-display">
            <div className="audit-value-box audit-value-box--old">
              <span className="cc-sr-only">Previous value: </span>
              {event.old_value_display || "Unknown"}
            </div>
            <div className="audit-change-arrow" aria-hidden="true">
              →
            </div>
            <div className="audit-value-box audit-value-box--new">
              <span className="cc-sr-only">New value: </span>
              {event.new_value_display || "Unknown"}
            </div>
          </div>
        ) : (
          <div className="audit-discovery-text">{event.event_description}</div>
        )}

        <div className="audit-tech-toggle">
          <CcureButton
            variant="ghost"
            size="sm"
            type="button"
            className="audit-tech-btn"
            aria-expanded={showTech}
            aria-controls={showTech ? techId : undefined}
            onClick={() => setShowTech(!showTech)}
          >
            {showTech ? "Hide Technical Details" : "View Technical Details"}
          </CcureButton>
          {showTech && <TechDetailsPanel id={techId} rawEvent={rawEvent} />}
        </div>
      </div>
    </div>
  );
}

function ScanGroupCard({ group, rawChangelog }) {
  const [expanded, setExpanded] = useState(false);
  const bodyId = useId();

  const sevClass = group.highest_severity
    ? `audit-group-card--${group.highest_severity.toLowerCase()}`
    : "audit-group-card--info";

  return (
    <div
      className={`audit-group-card ${sevClass} ${expanded ? "expanded" : ""}`}
    >
      {/* Was a `<div onClick>`: unreachable by keyboard and silent about its
          state. A button with aria-expanded is both. */}
      <CcureButton
        variant="ghost"
        size="sm"
        type="button"
        className="audit-group-header"
        aria-expanded={expanded}
        aria-controls={expanded ? bodyId : undefined}
        onClick={() => setExpanded(!expanded)}
      >
        <span className="audit-group-info">
          <span className="audit-group-icon" aria-hidden="true">
            {group.group_icon}
          </span>
          <span>
            <span className="audit-group-title">{group.summary_title}</span>
            <span className="audit-group-subtitle">
              {group.summary_subtitle}
            </span>
          </span>
        </span>
        <span className="audit-group-meta">
          <span className="audit-group-time">
            {ago(group.detected_at)} ({formatTime(group.detected_at)})
          </span>
          <span className="audit-group-chevron" aria-hidden="true">
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              focusable="false"
            >
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </span>
        </span>
      </CcureButton>

      {expanded && (
        <div className="audit-group-body" id={bodyId}>
          {group.events.map((event) => {
            const rawEvent = rawChangelog.find((r) => r.id === event.id);
            return (
              <EventRow key={event.id} event={event} rawEvent={rawEvent} />
            );
          })}
        </div>
      )}
    </div>
  );
}

const VIEW_TABS = [
  { id: "timeline", label: "Activity Timeline" },
  { id: "admin", label: "Administrative Audit" },
];

export default function AuditTimeline({ changelogData, headingLevel = 3 }) {
  const [activeCategory, setActiveCategory] = useState("all");
  const [viewMode, setViewMode] = useState("timeline"); // timeline | admin
  const Heading = `h${headingLevel}`;

  // If we haven't loaded or there's no data
  if (!changelogData || !changelogData.timeline) {
    return <CcureLoader label="Loading Timeline..." />;
  }

  const { timeline, raw_changelog, admin_logs, category_meta } = changelogData;

  // Render empty state if absolutely no events
  if (timeline.length === 0 && raw_changelog?.length === 0) {
    return (
      <CcureEmptyState
        icon="📭"
        title="No Audit Logs"
        description="No activity or changes have been recorded for this asset yet."
        className="audit-empty"
      />
    );
  }

  // Filter groups if a category is selected
  const filteredTimeline =
    activeCategory === "all"
      ? timeline
      : timeline
          .map((group) => ({
            ...group,
            events: group.events.filter((e) => e.category === activeCategory),
          }))
          .filter((group) => group.events.length > 0);

  return (
    <div className="audit-timeline-container">
      {/* Header & Controls */}
      <div className="audit-header">
        <div className="audit-title-block">
          <Heading className="audit-title">Asset Activity Timeline</Heading>
          <p>Complete history of discoveries, changes, and lifecycle events.</p>
        </div>
        <div className="audit-controls">
          <CcureTabs
            id="asset-activity"
            tabs={VIEW_TABS}
            value={viewMode}
            onChange={setViewMode}
            label="Audit views"
            className="audit-view-tabs"
          />
        </div>
      </div>

      <CcureTabPanel tabsId="asset-activity" id={viewMode} active>
        {viewMode === "timeline" ? (
          <>
            {/* Category Filter Pills — toggle buttons that announce their state. */}
            {category_meta && Object.keys(category_meta).length > 0 && (
              <div
                className="audit-filter-bar"
                role="group"
                aria-label="Filter events by category"
              >
                <CcureButton
                  variant="ghost"
                  size="sm"
                  type="button"
                  className="audit-filter-pill"
                  aria-pressed={activeCategory === "all"}
                  onClick={() => setActiveCategory("all")}
                >
                  <span className="audit-filter-icon" aria-hidden="true">
                    🔍
                  </span>{" "}
                  All Events
                </CcureButton>
                {Object.entries(category_meta).map(([catId, meta]) => {
                  // Only show categories that exist in our data
                  if (!changelogData.categories?.includes(catId)) return null;
                  return (
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      key={catId}
                      type="button"
                      className="audit-filter-pill"
                      aria-pressed={activeCategory === catId}
                      onClick={() => setActiveCategory(catId)}
                    >
                      <span className="audit-filter-icon" aria-hidden="true">
                        {meta.icon}
                      </span>{" "}
                      {meta.label}
                    </CcureButton>
                  );
                })}
              </div>
            )}

            {/* Timeline Groups */}
            <div className="audit-groups">
              {filteredTimeline.length === 0 ? (
                <CcureEmptyState
                  icon="🗂️"
                  title="No events match filter"
                  description="Try selecting a different category or viewing all events."
                  className="audit-empty"
                  action={
                    <CcureButton
                      variant="secondary"
                      onClick={() => setActiveCategory("all")}
                    >
                      Clear Filters
                    </CcureButton>
                  }
                />
              ) : (
                filteredTimeline.map((group) => (
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
          <div className="audit-admin-trail">
            {!admin_logs || admin_logs.length === 0 ? (
              <CcureEmptyState
                icon="🛡️"
                title="No Administrative Actions"
                description="No users have performed administrative actions on this asset."
                className="audit-empty"
              />
            ) : (
              admin_logs.map((log_entry) => (
                <div key={log_entry.id} className="audit-admin-entry">
                  <div className="audit-admin-dot" aria-hidden="true" />
                  <div className="audit-admin-time">
                    {formatTime(log_entry.created_at)}
                  </div>
                  <div className="audit-admin-action">
                    {log_entry.action
                      .replace(/_/g, " ")
                      .replace(/\b\w/g, (l) => l.toUpperCase())}
                    <CcureBadge
                      variant={
                        log_entry.status === "success" ? "success" : "danger"
                      }
                    >
                      {log_entry.status}
                    </CcureBadge>
                  </div>
                  <div className="audit-admin-actor">
                    Actor:{" "}
                    <span className="audit-admin-actor-name">
                      {log_entry.user_email}
                    </span>
                  </div>
                  {log_entry.changes &&
                    Object.keys(log_entry.changes).length > 0 && (
                      <div className="audit-admin-changes">
                        <div className="audit-admin-changes-title">
                          Changes:
                        </div>
                        <pre className="audit-admin-pre">
                          {JSON.stringify(log_entry.changes, null, 2)}
                        </pre>
                      </div>
                    )}
                </div>
              ))
            )}
          </div>
        )}
      </CcureTabPanel>
    </div>
  );
}
