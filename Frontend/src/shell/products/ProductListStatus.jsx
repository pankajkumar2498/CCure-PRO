import { CcureAlert, CcureButton, CcureLoader } from "../../design-system";
import { describeLoadError } from "./productList";

/**
 * The two states in which there is no product list to show: still loading, and
 * the request failed. Neither renders a card — a placeholder card would read as
 * a product, and zero cards would read as "there are no products".
 */
export function ProductListLoading() {
  return <CcureLoader label="Loading the CCure PRO products…" />;
}

export function ProductListError({ error, onRetry }) {
  return (
    <div>
      <CcureAlert
        variant="danger"
        title="The CCure PRO product list could not be loaded"
      >
        {describeLoadError(error)} No product is shown rather than a guess.
      </CcureAlert>
      <CcureButton className="ph-retry" variant="secondary" onClick={onRetry}>
        Retry
      </CcureButton>
    </div>
  );
}
