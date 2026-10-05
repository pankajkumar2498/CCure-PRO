import { useState } from "react";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  CcureButton,
  CcureIconButton,
  CcureTextarea,
  CcureSelect,
  CcureCombobox,
  CcureRadio,
  CcureCheckbox,
  CcureSwitch,
  CcureDropdown,
  CcureMenuItem,
  CcureDrawer,
  CcureModal,
  CcureTabs,
  useCcureToasts,
} from "../../design-system";

describe("official UX4G adapters preserve native contracts", () => {
  it("maps supported button variants and sizes to actual official classes", () => {
    render(
      <CcureButton variant="secondary" size="sm">
        Refresh
      </CcureButton>,
    );
    expect(screen.getByRole("button", { name: "Refresh" })).toHaveClass(
      "ux4g-btn-outline-neutral",
      "ux4g-btn-s",
      "cc-ux4g",
    );
  });
  it("prevents a disabled anchor's action and navigation", async () => {
    const click = vi.fn();
    render(
      <CcureButton as="a" href="/example" disabled onClick={click}>
        Unavailable
      </CcureButton>,
    );
    await userEvent.click(screen.getByRole("link"));
    expect(click).not.toHaveBeenCalled();
    expect(screen.getByRole("link")).toHaveAttribute("aria-disabled", "true");
  });
  it("preserves caller supplied accessible names instead of replacing them with rich labels", () => {
    render(
      <>
        <CcureCheckbox aria-label="audit.scan.read">
          Read scans and results
        </CcureCheckbox>
        <CcureSwitch aria-label="Email preference">
          Long presentation label
        </CcureSwitch>
      </>,
    );
    expect(
      screen.getByRole("checkbox", { name: "audit.scan.read" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("switch", { name: "Email preference" }),
    ).toBeInTheDocument();
  });
  it("names an icon button while keeping loading disabled", () => {
    render(
      <CcureIconButton label="Save preferences" loading>
        <span aria-hidden="true">✓</span>
      </CcureIconButton>,
    );
    expect(
      screen.getByRole("button", { name: "Save preferences" }),
    ).toBeDisabled();
  });
  it("associates textarea labels, validation and caller descriptions", async () => {
    const change = vi.fn();
    render(
      <>
        <p id="extra">Additional instructions</p>
        <CcureTextarea
          label="Reason"
          error="Reason required"
          aria-describedby="extra"
          required
          onChange={change}
        />
      </>,
    );
    const input = screen.getByRole("textbox", { name: /Reason/ });
    expect(input).toHaveAccessibleDescription(
      "Reason required Additional instructions",
    );
    expect(input).toHaveAttribute("aria-invalid", "true");
    await userEvent.type(input, "Review");
    expect(change).toHaveBeenCalled();
  });
  it("keeps the native select event/value and options API", async () => {
    const change = vi.fn();
    render(
      <CcureSelect label="Organization" defaultValue="one" onChange={change}>
        <option value="one">One</option>
        <option value="two">Two</option>
      </CcureSelect>,
    );
    await userEvent.selectOptions(screen.getByLabelText("Organization"), "two");
    expect(screen.getByLabelText("Organization")).toHaveValue("two");
    expect(change.mock.calls[0][0].target.value).toBe("two");
  });
  it("uses native radio selection and a named keyboard-operable switch", async () => {
    render(
      <>
        <CcureRadio name="theme" value="light" defaultChecked>
          Light
        </CcureRadio>
        <CcureRadio name="theme" value="dark">
          Dark
        </CcureRadio>
        <CcureSwitch>Notifications</CcureSwitch>
      </>,
    );
    await userEvent.click(screen.getByRole("radio", { name: "Dark" }));
    expect(screen.getByRole("radio", { name: "Light" })).not.toBeChecked();
    screen.getByRole("switch", { name: "Notifications" }).focus();
    await userEvent.keyboard(" ");
    expect(screen.getByRole("switch")).toBeChecked();
  });
});

function Menu({ selected = vi.fn() }) {
  const [open, setOpen] = useState(false);
  return (
    <CcureDropdown
      open={open}
      onOpenChange={setOpen}
      label="Account"
      trigger={({ ref, buttonProps }) => (
        <CcureButton ref={ref} {...buttonProps}>
          Account
        </CcureButton>
      )}
    >
      <CcureMenuItem onClick={() => selected("account")}>
        My Account
      </CcureMenuItem>
      <CcureMenuItem disabled>Disabled</CcureMenuItem>
      <CcureMenuItem onClick={() => selected("logout")}>Sign Out</CcureMenuItem>
    </CcureDropdown>
  );
}
describe("React menu semantics", () => {
  it("ArrowDown opens and focuses the first enabled item; arrows skip disabled and wrap", async () => {
    render(<Menu />);
    screen.getByRole("button", { name: "Account" }).focus();
    await userEvent.keyboard("{ArrowDown}");
    await waitFor(() =>
      expect(
        screen.getByRole("menuitem", { name: "My Account" }),
      ).toHaveFocus(),
    );
    await userEvent.keyboard("{ArrowDown}");
    expect(screen.getByRole("menuitem", { name: "Sign Out" })).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(screen.getByRole("menuitem", { name: "My Account" })).toHaveFocus();
  });
  it("ArrowUp opens at the end; Home and typeahead navigate; Escape restores the trigger", async () => {
    render(<Menu />);
    const trigger = screen.getByRole("button", { name: "Account" });
    trigger.focus();
    await userEvent.keyboard("{ArrowUp}");
    await waitFor(() =>
      expect(screen.getByRole("menuitem", { name: "Sign Out" })).toHaveFocus(),
    );
    await userEvent.keyboard("{Home}s");
    expect(screen.getByRole("menuitem", { name: "Sign Out" })).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
  it("selects once and closes without changing the caller's callback", async () => {
    const selected = vi.fn();
    render(<Menu selected={selected} />);
    await userEvent.click(screen.getByRole("button", { name: "Account" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "My Account" }));
    expect(selected).toHaveBeenCalledExactlyOnceWith("account");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });
  it("closes on outside interaction without stealing the clicked control's focus", async () => {
    render(
      <>
        <Menu />
        <button>Outside</button>
      </>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Account" }));
    await userEvent.click(screen.getByRole("button", { name: "Outside" }));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Outside" })).toHaveFocus();
  });
});

describe("searchable select adapter", () => {
  it("requires a committed option rather than arbitrary search text", async () => {
    render(
      <CcureCombobox
        label="Required theme"
        required
        options={[{ value: "light", label: "Light" }]}
      />,
    );
    const input = screen.getByRole("combobox");
    await userEvent.type(input, "Unknown");
    expect(input.checkValidity()).toBe(false);
  });
  it("filters, skips disabled options, selects by keyboard and posts the actual value", async () => {
    function Host() {
      const [value, setValue] = useState("");
      return (
        <form aria-label="Preferences">
          <CcureCombobox
            label="Theme"
            name="theme"
            value={value}
            onChange={setValue}
            options={[
              { value: "light", label: "Light" },
              { value: "locked", label: "Locked", disabled: true },
              { value: "dark", label: "Dark" },
            ]}
          />
        </form>
      );
    }
    render(<Host />);
    const input = screen.getByRole("combobox");
    await userEvent.click(input);
    await userEvent.keyboard("{End}{Enter}");
    expect(input).toHaveValue("Dark");
    expect(new FormData(screen.getByRole("form")).get("theme")).toBe("dark");
    await userEvent.click(input);
    await userEvent.type(input, "Li");
    expect(screen.getAllByRole("option")).toHaveLength(1);
    await userEvent.keyboard("{Enter}");
    expect(input).toHaveValue("Light");
  });
  it("Escape discards uncommitted input without changing the chosen value", async () => {
    const change = vi.fn();
    render(
      <CcureCombobox
        label="Theme"
        value="light"
        onChange={change}
        options={[{ value: "light", label: "Light" }]}
      />,
    );
    const input = screen.getByRole("combobox");
    await userEvent.click(input);
    await userEvent.type(input, "none");
    await userEvent.keyboard("{Escape}");
    expect(change).not.toHaveBeenCalled();
    expect(input).toHaveValue("Light");
    expect(input).toHaveAttribute("aria-expanded", "false");
  });
});

it("choice controls associate their errors and descriptions without changing their names", () => {
  render(
    <>
      <CcureCheckbox error="Select this option">Consent</CcureCheckbox>
      <CcureSwitch hint="Use email for notices">Email notices</CcureSwitch>
      <CcureRadio hint="The default mode">Standard mode</CcureRadio>
    </>,
  );
  expect(
    screen.getByRole("checkbox", { name: "Consent" }),
  ).toHaveAccessibleDescription("Select this option");
  expect(
    screen.getByRole("switch", { name: "Email notices" }),
  ).toHaveAccessibleDescription("Use email for notices");
  expect(
    screen.getByRole("radio", { name: "Standard mode" }),
  ).toHaveAccessibleDescription("The default mode");
});

describe("shared overlay isolation", () => {
  it("only the inner drawer handles Escape, then restores parent focus and background state", async () => {
    const outerClose = vi.fn();
    function Host() {
      const [inner, setInner] = useState(false);
      return (
        <>
          <button>Background</button>
          <CcureModal open title="Outer" onClose={outerClose}>
            <CcureButton onClick={() => setInner(true)}>
              Open drawer
            </CcureButton>
            {inner ? (
              <CcureDrawer open title="Inner" onClose={() => setInner(false)}>
                Details
              </CcureDrawer>
            ) : null}
          </CcureModal>
        </>
      );
    }
    const { container, unmount } = render(<Host />);
    expect(container).toHaveAttribute("inert");
    await userEvent.click(screen.getByRole("button", { name: "Open drawer" }));
    expect(screen.getByRole("dialog", { name: "Inner" })).toHaveAttribute(
      "aria-modal",
      "true",
    );
    await userEvent.keyboard("{Escape}");
    expect(outerClose).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("dialog", { name: "Inner" }),
    ).not.toBeInTheDocument();
    expect(
      within(screen.getByRole("dialog", { name: "Outer" })).getByRole(
        "button",
        { name: "Open drawer" },
      ),
    ).toHaveFocus();
    unmount();
    expect(container).not.toHaveAttribute("inert");
    expect(document.body.style.overflow).toBe("");
  });
  it("overlay dismissal uses the original mouse-down target", () => {
    const close = vi.fn();
    render(
      <CcureModal open title="Dialog" onClose={close}>
        Text
      </CcureModal>,
    );
    const overlay = screen.getByRole("dialog").parentElement;
    fireEvent.mouseDown(overlay);
    fireEvent.mouseUp(overlay);
    expect(close).toHaveBeenCalledOnce();
  });
});

it("manual tabs move from the focused tab while leaving selection to Enter", async () => {
  const change = vi.fn();
  render(
    <CcureTabs
      label="Views"
      value="one"
      activateOnFocus={false}
      onChange={change}
      tabs={[
        { id: "one", label: "One" },
        { id: "two", label: "Two" },
        { id: "three", label: "Three" },
      ]}
    />,
  );
  screen.getByRole("tab", { name: "One" }).focus();
  await userEvent.keyboard("{ArrowRight}{ArrowRight}");
  expect(screen.getByRole("tab", { name: "Three" })).toHaveFocus();
  expect(change).not.toHaveBeenCalled();
  await userEvent.keyboard("{Enter}");
  expect(change).toHaveBeenCalledWith("three");
});

it("clears all toast timers when an adapter host unmounts", () => {
  vi.useFakeTimers();
  function Host() {
    const { push } = useCcureToasts({ exitDuration: 220 });
    return <button onClick={() => push("Saved")}>Save</button>;
  }
  const { unmount } = render(<Host />);
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  expect(vi.getTimerCount()).toBeGreaterThan(0);
  unmount();
  act(() => vi.runAllTimers());
  expect(vi.getTimerCount()).toBe(0);
  vi.useRealTimers();
});
