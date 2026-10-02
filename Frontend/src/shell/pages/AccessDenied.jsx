/**
 * src/shell/pages/AccessDenied.jsx — a refused platform route, said in place.
 * ─────────────────────────────────────────────────────────────────────────────
 * A signed-in user who opens a platform page (an `/admin/*` screen) they may not
 * see stays in the Platform Shell and is told so. The route guard used to
 * redirect them to the first page of a product they could open — Audit's
 * dashboard — which put a refused *platform* page inside another product. The
 * address is kept, the sidebar is the platform's, and the way out is CCure Home.
 *
 * Unauthenticated visitors never reach this: they go to sign-in as before.
 */
import { Link } from "react-router-dom";
import { CcureAlert, CcureButton } from "../../design-system";
import PlatformLayout from "../layout/PlatformLayout";

export default function AccessDenied() {
  return (
    <PlatformLayout>
      <h1 className="pl-title">Access denied</h1>
      <CcureAlert variant="warning" title="You do not have access to this page">
        Your account does not have the permission this page needs. If you think
        it should, ask an administrator of your organisation.
      </CcureAlert>
      <CcureButton as={Link} to="/" variant="secondary" className="pm-back">
        Back to CCure Home
      </CcureButton>
    </PlatformLayout>
  );
}
