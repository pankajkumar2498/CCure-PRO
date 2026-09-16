/**
 * Legacy Toast — Checkpoint 3C batch 12 shim.
 *
 * It keeps its API; these tests pin the behaviour that did not change (timing,
 * dismiss) and the semantics that were added (live regions that exist before a
 * toast does).
 *
 * The Modal half of this file went with `components/layout/Modal.jsx`, deleted
 * in the post-migration cleanup once OrganizationManagement — its last
 * consumer — moved to CcureModal, whose own focus trap, Escape and overlay
 * behaviour are covered in src/__tests__/design-system/components.test.jsx.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { useToasts, ToastContainer } from "../../../components/common/Toast";

function Harness() {
  const { toasts, push, dismiss } = useToasts();
  return (
    <>
      <button type="button" onClick={() => push("Saved the thing", "success")}>
        ok
      </button>
      <button type="button" onClick={() => push("It broke", "error", 1000)}>
        bad
      </button>
      <ToastContainer toasts={toasts} dismiss={dismiss} />
    </>
  );
}

afterEach(() => vi.useRealTimers());

describe("Toast shim", () => {
  it("mounts its live regions before any toast exists", () => {
    const { container } = render(<Harness />);
    expect(
      container.querySelector('[aria-live="assertive"]'),
    ).toBeEmptyDOMElement();
    expect(
      container.querySelector('[aria-live="polite"]'),
    ).toBeEmptyDOMElement();
  });

  it("routes errors to the assertive region and the rest to the polite one", async () => {
    const u = userEvent.setup();
    render(<Harness />);
    await u.click(screen.getByText("ok"));
    await u.click(screen.getByText("bad"));
    expect(document.querySelector('[aria-live="polite"]')).toHaveTextContent(
      "Saved the thing",
    );
    expect(document.querySelector('[aria-live="assertive"]')).toHaveTextContent(
      "It broke",
    );
  });

  it("keeps the 4 s default and the 220 ms exit, and honours a custom duration", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const u = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<Harness />);
    await u.click(screen.getByText("ok"));
    await u.click(screen.getByText("bad"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000 + 220);
    });
    expect(screen.queryByText("It broke")).not.toBeInTheDocument();
    expect(screen.getByText("Saved the thing")).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000 + 220);
    });
    expect(screen.queryByText("Saved the thing")).not.toBeInTheDocument();
  });

  it("dismisses from the named button and from a click on the toast", async () => {
    const u = userEvent.setup();
    render(<Harness />);
    await u.click(screen.getByText("ok"));
    await u.click(screen.getByRole("button", { name: "Dismiss notification" }));
    await waitFor(() =>
      expect(screen.queryByText("Saved the thing")).not.toBeInTheDocument(),
    );
    await u.click(screen.getByText("ok"));
    await u.click(screen.getByText("Saved the thing"));
    await waitFor(() =>
      expect(screen.queryByText("Saved the thing")).not.toBeInTheDocument(),
    );
  });
});
