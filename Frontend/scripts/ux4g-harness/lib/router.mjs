/**
 * Answers `/api` from fixtures. Every write except the session refresh is
 * refused with 403 and recorded, so a capture can never change anything and a
 * write the page attempts is visible in the report rather than silent. The one
 * exception a state can opt into is the WebSocket ticket (below).
 */
import { SHELL_STUBS } from "./fixtures.mjs";

export function route(state, method, pathname) {
  const p = pathname.replace(/^\/api/, "");

  if (method === "POST" && p === "/auth/refresh") {
    return {
      body: { access_token: "harness-token", token_type: "bearer" },
      kind: "session",
    };
  }
  // A state that follows a live scan answers the ticket with the fixed
  // placeholder it declares. Nothing is issued or stored, and the socket the
  // ticket names is the state's scripted one (fixtures.mjs), never a real
  // connection: run.mjs blocks ws:// and wss:// regardless.
  if (method === "POST" && p === "/auth/ticket" && state.ticket) {
    return { body: { ticket: state.ticket }, kind: "ticket" };
  }
  if (method !== "GET") {
    return {
      status: 403,
      body: { detail: "harness: writes are refused" },
      kind: "refusedWrite",
    };
  }
  if (p === "/auth/me") return { body: state.persona };
  if (p === "/user/preferences") {
    return {
      body: {
        theme: state.theme,
        sidebar_collapsed: false,
        default_rows_per_page: 10,
      },
    };
  }

  const stubs = { ...SHELL_STUBS, ...(state.stubs || {}) };
  if (Object.prototype.hasOwnProperty.call(stubs, p)) {
    const s = stubs[p];
    // Never answered: the request stays open for the whole capture, so a page
    // can be measured while it is still loading.
    if (s && typeof s === "object" && s.__pending === true) {
      return { pending: true };
    }
    // A finite server-sent event stream: the recorded events, then the end of
    // the response. Answered in full, so a capture is deterministic.
    if (s && typeof s === "object" && "__eventStream" in s) {
      return {
        status: s.__status || 200,
        raw: s.__eventStream,
        contentType: "text/event-stream",
      };
    }
    if (s && typeof s === "object" && "__status" in s) {
      return {
        status: s.__status,
        body: s.body ?? { detail: "harness stub failure" },
      };
    }
    return { body: s };
  }
  return { status: 404, body: { detail: "not stubbed" }, kind: "unstubbed" };
}
