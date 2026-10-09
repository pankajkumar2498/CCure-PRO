import { useState } from "react";
import { createPortal } from "react-dom";
import { render, screen, waitFor, within } from "@testing-library/react";
import { it, expect } from "vitest";
import userEvent from "@testing-library/user-event";
import { CcureButton, CcureModal } from "../../design-system";

it("moves focus before isolating the opener and restores original background attributes", async () => {
  function Host() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <CcureButton onClick={() => setOpen(true)}>Open</CcureButton>
        <CcureModal open={open} onClose={() => setOpen(false)} title="Review">
          <CcureButton>Action</CcureButton>
        </CcureModal>
      </>
    );
  }
  const { container } = render(<Host />);
  container.setAttribute("aria-hidden", "false");
  const user = userEvent.setup();
  const opener = screen.getByRole("button", { name: "Open", exact: true });
  await user.click(opener);
  const dialog = screen.getByRole("dialog");
  expect(dialog.contains(document.activeElement)).toBe(true);
  expect(
    document.activeElement.closest('[aria-hidden="true"],[inert]'),
  ).toBeNull();
  expect(container).toHaveAttribute("inert");
  await user.keyboard("{Escape}");
  expect(opener).toHaveFocus();
  expect(container).toHaveAttribute("aria-hidden", "false");
  expect(container).not.toHaveAttribute("inert");
});

it("isolates portals appended while open and keeps only the inner dialog in the accessibility tree", async () => {
  function Host() {
    const [outer, setOuter] = useState(false),
      [inner, setInner] = useState(false);
    return (
      <>
        <CcureButton onClick={() => setOuter(true)}>Open outer</CcureButton>
        <CcureModal open={outer} onClose={() => setOuter(false)} title="Outer">
          <CcureButton onClick={() => setInner(true)}>Open inner</CcureButton>
          {inner &&
            createPortal(
              <div data-testid="late-message">Late message</div>,
              document.body,
            )}
          <CcureModal
            open={inner}
            onClose={() => setInner(false)}
            title="Inner"
          >
            <CcureButton>Inner action</CcureButton>
          </CcureModal>
        </CcureModal>
      </>
    );
  }
  const { container } = render(<Host />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Open outer" }));
  const outer = screen.getByRole("dialog", { name: "Outer" });
  const trigger = within(outer).getByRole("button", { name: "Open inner" });
  await user.click(trigger);
  expect(screen.queryByRole("dialog", { name: "Outer" })).toBeNull();
  expect(outer.parentElement).toHaveAttribute("inert");
  await waitFor(() =>
    expect(screen.getByTestId("late-message")).toHaveAttribute("inert"),
  );
  expect(
    screen
      .getByRole("dialog", { name: "Inner" })
      .contains(document.activeElement),
  ).toBe(true);
  await user.keyboard("{Escape}");
  expect(trigger).toHaveFocus();
  expect(outer.parentElement).not.toHaveAttribute("inert");
  expect(container).toHaveAttribute("inert");
  await user.keyboard("{Escape}");
  expect(screen.getByRole("button", { name: "Open outer" })).toHaveFocus();
  expect(container).not.toHaveAttribute("inert");
});

it("restores focus to the current main landmark when navigation removes the opener", async () => {
  function Host() {
    const [open, setOpen] = useState(false),
      [removed, setRemoved] = useState(false);
    return (
      <main tabIndex={-1}>
        {!removed && (
          <CcureButton onClick={() => setOpen(true)}>Open</CcureButton>
        )}
        <CcureModal
          open={open}
          title="Navigate"
          onClose={() => {
            setRemoved(true);
            setOpen(false);
          }}
        >
          Details
        </CcureModal>
      </main>
    );
  }
  render(<Host />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Open", exact: true }));
  await user.keyboard("{Escape}");
  expect(screen.getByRole("main")).toHaveFocus();
});
