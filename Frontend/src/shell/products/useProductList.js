import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { fetchProductList, parseProductList } from "./productList";

const LOADING = {
  status: "loading",
  tileStates: [],
  products: [],
  error: null,
};

/**
 * Fetch the product list once per mount, and again on `retry()`.
 *
 * `status` is `loading`, `ready` or `error`. On error there is deliberately no
 * product list at all — not an empty one and not a built-in fallback — so a
 * page cannot render a failed request as "no products" or as a guessed list.
 */
function useFetchedProductList(enabled = true) {
  const [state, setState] = useState(LOADING);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!enabled) return undefined;
    let cancelled = false;
    setState(LOADING);
    fetchProductList()
      .then((response) => {
        if (cancelled) return;
        const { tileStates, products } = parseProductList(response?.data);
        setState({ status: "ready", tileStates, products, error: null });
      })
      .catch((error) => {
        if (cancelled) return;
        setState({ status: "error", tileStates: [], products: [], error });
      });
    return () => {
      cancelled = true;
    };
  }, [attempt, enabled]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return { ...state, retry };
}

const ProductListContext = createContext(null);

/**
 * One fetch for the whole platform frame: `PlatformLayout` provides the list,
 * so its sidebar and the page inside it (CCure Home, an entry page) read the
 * same answer instead of asking the server twice.
 */
export function ProductListProvider({ children }) {
  const value = useFetchedProductList(true);
  return createElement(ProductListContext.Provider, { value }, children);
}

/** The provided list inside the platform frame; its own fetch outside one. */
export default function useProductList() {
  const provided = useContext(ProductListContext);
  const own = useFetchedProductList(provided === null);
  return provided ?? own;
}
