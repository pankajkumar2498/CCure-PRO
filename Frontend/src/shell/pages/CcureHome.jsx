/**
 * src/shell/pages/CcureHome.jsx — CCure Home, the Product Hub at `/`.
 * ─────────────────────────────────────────────────────────────────────────────
 * Renders exactly what `GET /platform/modules` says (Phase 12 §3.3): every
 * product, in the registry's order, with its name, description, availability
 * and an entry action. This page names no product — the order, names,
 * descriptions and addresses all come from the response.
 *
 * What it must never do:
 *   - hide a product, whatever its state (D12-4);
 *   - word the action for a product that is not available as opening a
 *     dashboard;
 *   - render a state it does not recognise as available;
 *   - render a failed request as zero products or as a built-in list.
 */
import { Link } from "react-router-dom";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureCard,
  CcurePage,
  CcurePageHeader,
} from "../../design-system";
import PlatformLayout from "../layout/PlatformLayout";
import useProductList from "../products/useProductList";
import { AVAILABILITY, availabilityOf } from "../products/productList";
import {
  ProductListError,
  ProductListLoading,
} from "../products/ProductListStatus";

const PRESENTATION = {
  [AVAILABILITY.AVAILABLE]: {
    badge: "Available",
    variant: "success",
    action: "Open dashboard",
    buttonVariant: "primary",
  },
  [AVAILABILITY.NOT_YET_AVAILABLE]: {
    badge: "Not yet available",
    variant: "neutral",
    action: "About this product",
    buttonVariant: "secondary",
  },
  [AVAILABILITY.UNKNOWN]: {
    badge: "Status unknown",
    variant: "warning",
    action: "About this product",
    buttonVariant: "secondary",
  },
};

function ProductCard({ product, tileStates }) {
  const availability = availabilityOf(product, tileStates);
  const view = PRESENTATION[availability];
  const name = product.title || "Unnamed product";

  return (
    <CcureCard
      className="ph-card"
      title={name}
      headingLevel={2}
      data-product={product.key || undefined}
      data-availability={availability}
    >
      <div>
        <CcureBadge variant={view.variant} dot>
          {view.badge}
        </CcureBadge>
      </div>
      <p className="ph-card__description">
        {product.description || "No description was provided."}
      </p>
      {product.entryPath ? (
        <CcureButton
          as={Link}
          to={product.entryPath}
          variant={view.buttonVariant}
          size="sm"
          className="ph-card__action"
          aria-label={`${view.action}, ${name}`}
        >
          {view.action}
        </CcureButton>
      ) : (
        <p className="ph-card__description">
          No entry address was provided for this product.
        </p>
      )}
    </CcureCard>
  );
}

function HomeContent() {
  const { status, products, tileStates, error, retry } = useProductList();

  return (
    <>
      <CcurePageHeader
        title="CCurePRO Home"
        subtitle="The CCurePRO products and what each is responsible for. Choose where to go."
      />

      {status === "loading" ? <ProductListLoading /> : null}

      {status === "error" ? (
        <ProductListError error={error} onRetry={retry} />
      ) : null}

      {status === "ready" && products.length === 0 ? (
        <CcureAlert variant="warning" title="No products were listed">
          The server answered with an empty product list. This is not expected;
          every CCurePRO product is listed whatever its state.
        </CcureAlert>
      ) : null}

      {status === "ready" && products.length > 0 ? (
        <ul className="ph-grid" aria-label="CCurePRO products">
          {products.map((product, index) => (
            <li key={product.key || index}>
              <ProductCard product={product} tileStates={tileStates} />
            </li>
          ))}
        </ul>
      ) : null}
    </>
  );
}

export default function CcureHome() {
  return (
    <PlatformLayout>
      <CcurePage>
        <HomeContent />
      </CcurePage>
    </PlatformLayout>
  );
}
