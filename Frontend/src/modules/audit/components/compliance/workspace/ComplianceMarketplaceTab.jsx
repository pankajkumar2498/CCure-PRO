/**
 * The compliance workspace's Marketplace tab. The workspace keeps the state,
 * the requests and the handlers, and passes them in; this renders them.
 * Moved from `pages/ComplianceWorkspace.jsx` (F1) unchanged.
 */

import {
  CcureCard,
  CcureIcon,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
} from "../../../../../design-system";

export default function ComplianceMarketplaceTab({
  handleInstallFramework,
  handleUninstallFramework,
  isComplianceAdmin,
  marketplace,
  setUninstallBusy,
  setUninstallTarget,
  uninstallBusy,
  uninstallTarget,
}) {
  return (
    <section
      className="cww-marketplace"
      aria-labelledby="cww-marketplace-title"
    >
      <h2 id="cww-marketplace-title" className="cww-title">
        Framework Marketplace
      </h2>
      <div className="cww-marketplace__grid">
        {marketplace.map((fw) => (
          <CcureCard
            key={fw.framework_id}
            headingLevel={3}
            title={fw.name}
            className="cww-framework"
          >
            <span className="cww-framework__icon" aria-hidden="true">
              <CcureIcon name="lock" />
            </span>
            <p className="cww-framework__meta">
              Code: {fw.code} | Version: {fw.version}
            </p>
            <p className="cww-framework__reqs">
              Total Requirements: {fw.controls_count}
            </p>
            <div className="cww-framework__actions">
              {fw.is_installed ? (
                <>
                  <CcureBadge variant="success" dot>
                    Installed
                  </CcureBadge>
                  <CcureButton
                    variant="danger"
                    size="sm"
                    disabled={!isComplianceAdmin}
                    title={
                      !isComplianceAdmin
                        ? "Requires Org Admin or Superadmin permission"
                        : ""
                    }
                    aria-describedby={
                      !isComplianceAdmin
                        ? `cww-permission-${fw.framework_id}`
                        : undefined
                    }
                    aria-haspopup="dialog"
                    onClick={() => isComplianceAdmin && setUninstallTarget(fw)}
                  >
                    Uninstall
                  </CcureButton>
                </>
              ) : (
                <CcureButton
                  variant="primary"
                  size="sm"
                  disabled={!isComplianceAdmin}
                  title={
                    !isComplianceAdmin
                      ? "Requires Org Admin or Superadmin permission"
                      : ""
                  }
                  aria-describedby={
                    !isComplianceAdmin
                      ? `cww-permission-${fw.framework_id}`
                      : undefined
                  }
                  onClick={() =>
                    isComplianceAdmin && handleInstallFramework(fw.framework_id)
                  }
                >
                  Install
                </CcureButton>
              )}
            </div>
            {!isComplianceAdmin && (
              <p
                id={`cww-permission-${fw.framework_id}`}
                className="cww-framework__hint"
              >
                Requires Org Admin or Superadmin permission
              </p>
            )}
          </CcureCard>
        ))}
      </div>
      {/* Uninstalling hides a framework's policies, findings, approvals
                  and dashboard averages, so it asks first: Cancel takes focus,
                  Escape backs out, and the question cannot be answered twice
                  while its request is out. */}
      <CcureConfirmDialog
        open={uninstallTarget !== null}
        title="Uninstall framework"
        subtitle={uninstallTarget?.name}
        warning="Are you sure you want to uninstall this compliance framework? This will hide its policies, findings, approvals, and dashboard averages."
        confirmLabel="Uninstall"
        cancelLabel="Cancel"
        tone="danger"
        busy={uninstallBusy}
        onCancel={() => setUninstallTarget(null)}
        onConfirm={async () => {
          if (uninstallBusy || !uninstallTarget) return;
          setUninstallBusy(true);
          await handleUninstallFramework(uninstallTarget.framework_id);
          setUninstallBusy(false);
          setUninstallTarget(null);
        }}
      />
    </section>
  );
}
