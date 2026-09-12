/**
 * Legacy Toast and Modal — Checkpoint 3C batch 12 shims.
 *
 * Both keep their APIs; these tests pin the behaviour that did not change
 * (timing, dismiss, Escape, overlay close) and the semantics that were added
 * (live regions that exist before a toast does; a named modal dialog with a
 * focus trap and focus restoration).
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { useToasts, ToastContainer } from "../../../components/common/Toast";
import Modal from "../../../components/layout/Modal";

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

describe("Modal shim", () => {
  const Host = ({ open, onClose }) => (
    <>
      <button type="button">opener</button>
      <Modal
        isOpen={open}
        onClose={onClose}
        title="Edit organisation"
        subtitle="Details"
      >
        <input aria-label="Name" />
        <button type="button">Save</button>
      </Modal>
    </>
  );

  it("renders nothing when closed and a named modal dialog when open", () => {
    const { rerender } = render(<Host open={false} onClose={() => {}} />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    rerender(<Host open onClose={() => {}} />);
    const dlg = screen.getByRole("dialog", { name: "Edit organisation" });
    expect(dlg).toHaveAttribute("aria-modal", "true");
    expect(screen.getByText("Details")).toBeInTheDocument();
  });

  it("moves focus in, keeps Tab inside, and restores focus on close", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    const { rerender } = render(<Host open={false} onClose={onClose} />);
    screen.getByText("opener").focus();
    rerender(<Host open onClose={onClose} />);
    const dlg = screen.getByRole("dialog");
    await waitFor(() =>
      expect(dlg.contains(document.activeElement)).toBe(true),
    );
    for (let i = 0; i < 8; i += 1) {
      await u.tab();
      expect(dlg.contains(document.activeElement)).toBe(true);
    }
    rerender(<Host open={false} onClose={onClose} />);
    await waitFor(() => expect(screen.getByText("opener")).toHaveFocus());
  });

  it("closes on Escape, on the overlay and on the Close control", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    const { container } = render(<Host open onClose={onClose} />);
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    await u.click(container.querySelector(".modal-overlay"));
    expect(onClose).toHaveBeenCalledTimes(2);
    await u.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(3);
  });
});
