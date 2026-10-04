/**
 * src/shell/pages/ModuleEntryPage.jsx — a product's entry page, from the registry.
 * ─────────────────────────────────────────────────────────────────────────────
 * Mounted on the single-segment route `/:entry`, which every static route
 * outranks (Phase 12 §3.5). It looks the address up in the fetched product
 * list, so there is one component for every product rather than a route per
 * product, and a product gains a page here by being in the registry.
 *
 *   - not yet available  → the module page: name, description, a statement
 *                          that the product is not available yet, and the way
 *                          back to CCure Home. No chart, count, table or
 *                          disabled control: each reads as "the feature exists
 *                          and has nothing in it".
 *   - status unknown     → says so; never rendered as available.
 *   - available          → this build has no page at that address (a static
 *                          route would have matched). Said explicitly, never a
 *                          blank page or the not-yet-available text.
 *   - no product         → today's catch-all: to `/`.
 *   - the list failed    → the error and a retry. Whether the address is a
 *                          product cannot be known, so nothing is assumed.
 */
import { Link, Navigate, useLocation } from "react-router-dom";
import { CcureAlert, CcureBadge, CcureButton } from "../../design-system";
import PlatformLayout from "../layout/PlatformLayout";
import useProductList from "../products/useProductList";
import { AVAILABILITY, availabilityOf } from "../products/productList";
import {
  ProductListError,
  ProductListLoading,
} from "../products/ProductListStatus";

function BackToHome() {
  return (
    <CcureButton as={Link} to="/" variant="secondary" className="pm-back">
      Back to CCure Home
    </CcureButton>
  );
}

function Statement({ product, availability }) {
  const name = product.title || "This product";

  if (availability === AVAILABILITY.NOT_YET_AVAILABLE) {
    return (
      <CcureAlert variant="info" title={`${name} is not available yet`}>
        There are no {name} features, data or settings in this installation.
      </CcureAlert>
    );
  }
  if (availability === AVAILABILITY.AVAILABLE) {
    return (
      <CcureAlert variant="warning" title={`${name} has no page in this build`}>
        The platform reports {name} as available, but this build of the CCure
        frontend has no page at {product.entryPath}. Nothing is shown in its
        place.
      </CcureAlert>
    );
  }
  return (
    <CcureAlert
      variant="warning"
      title={`The availability of ${name} is unknown`}
    >
      The platform reported a state this page does not recognise
      {product.tileState ? ` (“${product.tileState}”)` : ""}, so it is not shown
      as available.
    </CcureAlert>
  );
}

const BADGE = {
  [AVAILABILITY.AVAILABLE]: ["Available", "success"],
  [AVAILABILITY.NOT_YET_AVAILABLE]: ["Not yet available", "neutral"],
  [AVAILABILITY.UNKNOWN]: ["Status unknown", "warning"],
};

function EntryContent() {
  const { pathname } = useLocation();
  const { status, products, tileStates, error, retry } = useProductList();
  const address = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;

  if (status === "ready") {
    const product = products.find((p) => p.entryPath === address);
    if (!product) return <Navigate to="/" replace />;

    const availability = availabilityOf(product, tileStates);
    const [badge, variant] = BADGE[availability];
    return (
      <>
        <h1 className="pl-title">{product.title || "Unnamed product"}</h1>
        <p className="pl-lead">
          <CcureBadge variant={variant} dot>
            {badge}
          </CcureBadge>
        </p>
        {product.description ? (
          <p className="pm-statement">{product.description}</p>
        ) : null}
        <Statement product={product} availability={availability} />
        <BackToHome />
      </>
    );
  }

  return (
    <>
      {status === "loading" ? (
        <ProductListLoading />
      ) : (
        <>
          <ProductListError error={error} onRetry={retry} />
          <BackToHome />
        </>
      )}
    </>
  );
}

export default function ModuleEntryPage() {
  return (
    <PlatformLayout>
      <div className="page-inner">
        <EntryContent />
      </div>
    </PlatformLayout>
  );
}
