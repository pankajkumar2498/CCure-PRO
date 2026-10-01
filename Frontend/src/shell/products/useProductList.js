import { useCallback, useEffect, useState } from "react";
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
export default function useProductList() {
  const [state, setState] = useState(LOADING);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
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
  }, [attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return { ...state, retry };
}
