/**
 * src/shell/products/productList.js
 * ─────────────────────────────────────────────────────────────────────────────
 * The CCure product list, read from the platform registry through
 * `GET /platform/modules` (Phase 12.1). This file holds no product: no name, no
 * description, no address and no list of availability states. All of that is
 * fetched, so the frontend can never offer a product the platform removed or
 * omit one it gained — "a vocabulary is fetched, not copied".
 *
 * What it does hold is the meaning of the two availability states this build
 * knows how to render. A state the server reports that is outside the fetched
 * vocabulary, or inside it but unknown to this build, is UNKNOWN — never
 * available, never "not yet available".
 */
import api from "../api/axiosInstance";

export const AVAILABILITY = Object.freeze({
  AVAILABLE: "available",
  NOT_YET_AVAILABLE: "not_yet_available",
  UNKNOWN: "unknown",
});

const KNOWN_STATES = new Set([
  AVAILABILITY.AVAILABLE,
  AVAILABILITY.NOT_YET_AVAILABLE,
]);

export const fetchProductList = () => api.get("/platform/modules");

/** The error raised when the response is not the shape §3.2 defines. */
export class MalformedProductList extends Error {
  constructor(message) {
    super(message);
    this.name = "MalformedProductList";
  }
}

/**
 * Validate the response body and return `{ tileStates, products }`.
 *
 * A body that is not the documented shape is an error, not an empty list:
 * "the server sent something we cannot read" and "there are no products" are
 * different facts, and only the first is true here.
 */
export function parseProductList(body) {
  if (!body || typeof body !== "object") {
    throw new MalformedProductList("The response carried no product list.");
  }
  if (!Array.isArray(body.modules)) {
    throw new MalformedProductList("The response carried no product list.");
  }
  const tileStates = Array.isArray(body.tile_states)
    ? body.tile_states.filter((s) => typeof s === "string")
    : [];
  const products = body.modules
    .filter((p) => p && typeof p === "object")
    .map((p) => ({
      key: typeof p.key === "string" ? p.key : "",
      title: typeof p.title === "string" ? p.title : "",
      kind: typeof p.kind === "string" ? p.kind : "",
      description: typeof p.description === "string" ? p.description : "",
      entryPath: isEntryPath(p.entry_path) ? p.entry_path : null,
      tileState: typeof p.tile_state === "string" ? p.tile_state : null,
    }));
  return { tileStates, products };
}

/** An entry address is one absolute path segment, as the registry enforces. */
export function isEntryPath(value) {
  return typeof value === "string" && /^\/[a-z0-9][a-z0-9-]*$/.test(value);
}

/** The availability this build renders for a product. */
export function availabilityOf(product, tileStates) {
  const state = product?.tileState;
  if (!state || !Array.isArray(tileStates) || !tileStates.includes(state)) {
    return AVAILABILITY.UNKNOWN;
  }
  return KNOWN_STATES.has(state) ? state : AVAILABILITY.UNKNOWN;
}

/** A short sentence naming why a request failed, for the error state. */
export function describeLoadError(error) {
  if (error instanceof MalformedProductList) return error.message;
  const status = error?.response?.status;
  if (status) return `The server answered HTTP ${status}.`;
  return "The server could not be reached.";
}
