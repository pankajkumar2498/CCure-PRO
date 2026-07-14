export default function EmptyState({
  icon = "📭",
  title = "No items found",
  description = "Try adjusting your filters.",
  action,
}) {
  return (
    <div className="empty-state">
      <span className="empty-state-icon" aria-hidden="true">
        {icon}
      </span>
      <div className="empty-state-title">{title}</div>
      <div className="empty-state-desc">{description}</div>
      {action ? <div style={{ marginTop: 16 }}>{action}</div> : null}
    </div>
  );
}
