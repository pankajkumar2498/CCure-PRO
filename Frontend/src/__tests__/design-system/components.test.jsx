/**
 * Accessibility behaviour of the CCure primitives.
 *
 * Each block below pins one of the five categorical gaps Phase 0 measured
 * across the existing application — zero aria-describedby, zero aria-current,
 * zero skip links, zero table semantics, and a Modal with no dialog role or
 * focus trap. The primitives are where those get fixed once, and these tests
 * are what stop them regressing as pages migrate onto them.
 */

import { describe, it, expect, vi } from "vitest";
import { useState } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CcureButton from "../../design-system/components/CcureButton";
import CcureInput from "../../design-system/components/CcureInput";
import CcureAlert from "../../design-system/components/CcureAlert";
import CcureModal from "../../design-system/components/CcureModal";
import CcureToastProvider, {
  useCcureToast,
} from "../../design-system/components/CcureToast";
import CcureAppShell from "../../design-system/patterns/CcureAppShell";

describe("CcureButton", () => {
  it("defaults to type=button so it cannot submit a form it merely sits in", () => {
    render(<CcureButton>Go</CcureButton>);
    expect(screen.getByRole("button", { name: "Go" })).toHaveAttribute(
      "type",
      "button",
    );
  });

  it("is disabled as well as aria-busy while loading", async () => {
    const onClick = vi.fn();
    render(
      <CcureButton loading onClick={onClick}>
        Save
      </CcureButton>,
    );
    const btn = screen.getByRole("button", { name: /Save/ });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute("aria-busy", "true");

    // Announcing "busy" while remaining clickable is what produces the double
    // submit the loading state exists to prevent.
    await userEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("keeps its accessible name while loading", () => {
    render(<CcureButton loading>Start scan</CcureButton>);
    // A spinner that replaces the label leaves a screen reader announcing
    // "busy, button" with no idea which button.
    expect(
      screen.getByRole("button", { name: /Start scan/ }),
    ).toBeInTheDocument();
  });

  it("is reachable and activatable by keyboard", async () => {
    const onClick = vi.fn();
    render(<CcureButton onClick={onClick}>Run</CcureButton>);
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "Run" })).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    await userEvent.keyboard(" ");
    expect(onClick).toHaveBeenCalledTimes(2);
  });
});

describe("CcureInput", () => {
  it("associates its label with the control", () => {
    render(<CcureInput label="Target range" />);
    // getByLabelText resolves through the accessibility tree, so this passes
    // only if for/id actually connect.
    expect(screen.getByLabelText(/Target range/)).toBeInstanceOf(
      HTMLInputElement,
    );
  });

  it("attaches a hint via aria-describedby", () => {
    render(<CcureInput label="CIDR" hint="For example 10.180.6.0/24" />);
    expect(screen.getByLabelText(/CIDR/)).toHaveAccessibleDescription(
      "For example 10.180.6.0/24",
    );
  });

  it("attaches an error via aria-describedby and sets aria-invalid", () => {
    render(<CcureInput label="CIDR" error="Not a valid network." />);
    const input = screen.getByLabelText(/CIDR/);
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription("Not a valid network.");
  });

  it("replaces the hint with the error rather than announcing both", () => {
    render(
      <CcureInput
        label="CIDR"
        hint="For example 10.180.6.0/24"
        error="Required."
      />,
    );
    // Queueing both makes the reader say "for example 10.180.6.0/24. Required."
    // which buries the actionable half.
    expect(screen.getByLabelText(/CIDR/)).toHaveAccessibleDescription(
      "Required.",
    );
  });

  it("announces the error without the user having to go looking for it", () => {
    render(<CcureInput label="CIDR" error="Required." />);
    expect(screen.getByRole("alert")).toHaveTextContent("Required.");
  });

  it("marks a required field in text, not only with an asterisk", () => {
    render(<CcureInput label="Password" required />);
    // "*" is aria-hidden; the announced name must still say required.
    expect(screen.getByLabelText(/required/i)).toBeInstanceOf(HTMLInputElement);
  });

  it("gives each instance a unique id so labels cannot cross-wire", () => {
    render(
      <>
        <CcureInput label="Port" />
        <CcureInput label="Timeout" />
      </>,
    );
    const a = screen.getByLabelText("Port");
    const b = screen.getByLabelText("Timeout");
    expect(a.id).not.toBe(b.id);
  });
});

describe("CcureAlert", () => {
  it("interrupts for danger and warning", () => {
    const { rerender } = render(<CcureAlert variant="danger">Boom</CcureAlert>);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    rerender(<CcureAlert variant="warning">Careful</CcureAlert>);
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });

  it("waits politely for info and success", () => {
    render(<CcureAlert variant="success">Done</CcureAlert>);
    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("is not a live region when it is page furniture", () => {
    // A standing banner is not an event. Announcing it on every page load is
    // the misuse `live={false}` exists to prevent.
    render(
      <CcureAlert variant="warning" live={false}>
        This scan ran without credentials.
      </CcureAlert>,
    );
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("names its dismiss control", () => {
    render(
      <CcureAlert variant="info" onDismiss={() => {}}>
        Hi
      </CcureAlert>,
    );
    expect(screen.getByRole("button", { name: "Dismiss" })).toBeInTheDocument();
  });
});

describe("CcureModal", () => {
  const Harness = ({ onClose = () => {}, ...props }) => (
    <>
      <button type="button">outside before</button>
      <CcureModal open onClose={onClose} title="Confirm" {...props}>
        <button type="button">inside one</button>
        <button type="button">inside two</button>
      </CcureModal>
      <button type="button">outside after</button>
    </>
  );

  it("is a dialog, modal, and named by its title", () => {
    render(<Harness />);
    const dialog = screen.getByRole("dialog", { name: "Confirm" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("moves focus into the dialog on open", async () => {
    render(<Harness />);
    const dialog = screen.getByRole("dialog");
    await vi.waitFor(() =>
      expect(dialog.contains(document.activeElement)).toBe(true),
    );
  });

  it("keeps Tab inside the dialog", async () => {
    render(<Harness />);
    const dialog = screen.getByRole("dialog");
    const user = userEvent.setup();

    // Enough presses to leave a three-control dialog several times over if the
    // trap were absent.
    for (let i = 0; i < 8; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("cycles backwards without escaping either", async () => {
    render(<Harness />);
    const dialog = screen.getByRole("dialog");
    const user = userEvent.setup();
    for (let i = 0; i < 5; i += 1) {
      await user.tab({ shift: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("closes on Escape", async () => {
    const onClose = vi.fn();
    render(<Harness onClose={onClose} />);
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });

  it("does not close on Escape when the caller forbids it", async () => {
    const onClose = vi.fn();
    render(<Harness onClose={onClose} closeOnEscape={false} />);
    await userEvent.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
  });

  it("restores focus to the element that opened it", async () => {
    function Host() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Open
          </button>
          <CcureModal
            open={open}
            onClose={() => setOpen(false)}
            title="Confirm"
          >
            <button type="button">inside</button>
          </CcureModal>
        </>
      );
    }
    render(<Host />);
    const opener = screen.getByRole("button", { name: "Open" });
    opener.focus();
    await userEvent.click(opener);
    await vi.waitFor(() =>
      expect(screen.getByRole("dialog")).toBeInTheDocument(),
    );
    await userEvent.keyboard("{Escape}");
    // Without restoration focus lands on <body>, and the next Tab restarts at
    // the top of the document — which here means the whole sidebar.
    await vi.waitFor(() => expect(opener).toHaveFocus());
  });

  /* Batch 14: two traps at once. Before the nesting stack, each trap's
     focusin listener pulled focus back into its own root and the two looped
     until the stack overflowed. The inner dialog must own focus while open
     and hand it back to its opener inside the outer dialog when it closes. */
  it("nests: the inner dialog owns Tab and focus, and restores to its opener in the outer one", async () => {
    function Nested() {
      const [inner, setInner] = useState(false);
      return (
        <CcureModal open onClose={() => {}} title="Outer">
          <button type="button">Outer A</button>
          <button type="button" onClick={() => setInner(true)}>
            Open inner
          </button>
          {inner && (
            <CcureModal open onClose={() => setInner(false)} title="Inner">
              <button type="button">Inner A</button>
              <button type="button">Inner B</button>
            </CcureModal>
          )}
        </CcureModal>
      );
    }
    render(<Nested />);
    const outer = screen.getByRole("dialog", { name: "Outer" });
    await vi.waitFor(() =>
      expect(outer.contains(document.activeElement)).toBe(true),
    );
    const opener = screen.getByRole("button", { name: "Open inner" });
    await userEvent.click(opener);
    const innerDlg = screen.getByRole("dialog", { name: "Inner" });
    await vi.waitFor(() =>
      expect(innerDlg.contains(document.activeElement)).toBe(true),
    );
    for (let i = 0; i < 6; i += 1) {
      await userEvent.tab();
      expect(innerDlg.contains(document.activeElement)).toBe(true);
    }
    await userEvent.keyboard("{Escape}");
    await vi.waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: "Inner" }),
      ).not.toBeInTheDocument(),
    );
    await vi.waitFor(() => expect(opener).toHaveFocus());
    // The outer trap is in charge again.
    await userEvent.tab();
    expect(outer.contains(document.activeElement)).toBe(true);
  });

  it("names its close control", () => {
    render(<Harness />);
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByRole("button", { name: "Close dialog" }),
    ).toBeInTheDocument();
  });
});

describe("CcureToast", () => {
  function Trigger() {
    const toast = useCcureToast();
    return (
      <button type="button" onClick={() => toast.success("Report ready")}>
        fire
      </button>
    );
  }

  it("mounts its live regions before any toast exists", () => {
    // The whole reason this component exists. Assistive technology announces
    // *mutations* of a live region it is already watching; a region created
    // together with its first message frequently announces nothing at all.
    const { container } = render(
      <CcureToastProvider>
        <span />
      </CcureToastProvider>,
    );
    const regions = document.querySelectorAll("[aria-live]");
    expect(regions.length).toBe(2);
    expect(container).toBeTruthy();
  });

  it("separates assertive from polite", () => {
    render(
      <CcureToastProvider>
        <span />
      </CcureToastProvider>,
    );
    const levels = [...document.querySelectorAll("[aria-live]")].map((n) =>
      n.getAttribute("aria-live"),
    );
    // One region cannot be both, and picking one is wrong half the time.
    expect(levels.sort()).toEqual(["assertive", "polite"]);
  });

  it("renders a toast into the existing region", async () => {
    render(
      <CcureToastProvider>
        <Trigger />
      </CcureToastProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "fire" }));
    expect(screen.getByText("Report ready")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Dismiss notification" }),
    ).toBeInTheDocument();
  });
});

describe("CcureAppShell", () => {
  const sections = [
    {
      label: "Overview",
      items: [
        { id: "a", label: "Dashboard", route: "/" },
        { id: "b", label: "Assets", route: "/assets" },
      ],
    },
  ];

  it("provides a skip link as the first tab stop", async () => {
    render(
      <CcureAppShell title="T" sections={sections} currentPath="/">
        <p>body</p>
      </CcureAppShell>,
    );
    await userEvent.tab();
    expect(
      screen.getByRole("link", { name: /Skip to main content/i }),
    ).toHaveFocus();
  });

  it("targets a focusable main landmark", () => {
    render(
      <CcureAppShell title="T" sections={sections} currentPath="/">
        <p>body</p>
      </CcureAppShell>,
    );
    const main = screen.getByRole("main");
    expect(main).toHaveAttribute("id", "cc-main");
    // Without tabindex the skip link scrolls but leaves focus at the top of the
    // document, so the next Tab re-enters the navigation just skipped.
    expect(main).toHaveAttribute("tabindex", "-1");
  });

  it("marks the current route with aria-current=page", () => {
    render(
      <CcureAppShell title="T" sections={sections} currentPath="/assets">
        <p>body</p>
      </CcureAppShell>,
    );
    expect(screen.getByRole("link", { name: /Assets/ })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByRole("link", { name: /Dashboard/ })).not.toHaveAttribute(
      "aria-current",
    );
  });

  it("names every landmark that can appear more than once", () => {
    render(
      <CcureAppShell
        title="T"
        sections={sections}
        currentPath="/"
        footerLinks={[{ href: "#a", label: "Help" }]}
      >
        <p>body</p>
      </CcureAppShell>,
    );
    // Two unnamed <nav>s are announced as "navigation, navigation".
    expect(
      screen.getByRole("navigation", { name: "Sections" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: "Footer" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("complementary", { name: "Primary" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
  });

  it("exposes exactly one h1, naming the page", () => {
    render(
      <CcureAppShell title="Asset Registry" sections={sections} currentPath="/">
        <p>body</p>
      </CcureAppShell>,
    );
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "Asset Registry",
    );
  });
});
