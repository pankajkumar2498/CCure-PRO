/**
 * Checkpoint 3A primitives: Table, Tabs, Pagination, Breadcrumb, Card, Badge,
 * Loader, Skeleton, EmptyState, Progress.
 *
 * The four priority components exist because of measured application-wide
 * gaps — 46 tables with zero `scope`, four tab bars with zero `role="tab"`,
 * seven hand-rolled paginations, no breadcrumb at all. The assertions below
 * are what stop those gaps reappearing once pages start migrating onto these.
 */

import { describe, it, expect, vi } from "vitest";
import { useState } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CcureTable, {
  CcureTableStatus,
} from "../../design-system/components/CcureTable";
import CcureTabs, {
  CcureTabPanel,
  useCcureTabs,
} from "../../design-system/components/CcureTabs";
import CcurePagination from "../../design-system/components/CcurePagination";
import CcureBreadcrumb from "../../design-system/components/CcureBreadcrumb";
import CcureCard from "../../design-system/components/CcureCard";
import CcureBadge from "../../design-system/components/CcureBadge";
import {
  CcureLoader,
  CcureSkeleton,
  CcureEmptyState,
  CcureProgress,
} from "../../design-system/components/CcureFeedback";

/* ══════════════════════════════════════════════════════════════════════════
   Table
   ══════════════════════════════════════════════════════════════════════════ */

const COLUMNS = [
  { key: "host", header: "Host", isRowHeader: true, sortable: true },
  { key: "port", header: "Port", mono: true, align: "end", sortable: true },
  { key: "service", header: "Service" },
];

const ROWS = [
  { id: 1, host: "10.180.6.14", port: 5985, service: "wsman" },
  { id: 2, host: "10.180.6.20", port: 22, service: "ssh" },
];

describe("CcureTable", () => {
  it("gives the table an accessible name from its caption", () => {
    render(
      <CcureTable
        caption="Open services"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
      />,
    );
    // 46 tables in the application currently have no caption at all, so they
    // are announced as "table" with no indication of what they contain.
    expect(
      screen.getByRole("table", { name: "Open services" }),
    ).toBeInTheDocument();
  });

  it("keeps the caption available to assistive tech when visually hidden", () => {
    const { container } = render(
      <CcureTable
        caption="Open services"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
      />,
    );
    const caption = container.querySelector("caption");
    expect(caption).toHaveClass("cc-sr-only");
    expect(caption).toHaveTextContent("Open services");
  });

  it("marks every column header with scope=col", () => {
    render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
      />,
    );
    const headers = screen.getAllByRole("columnheader");
    expect(headers).toHaveLength(3);
    for (const h of headers) expect(h).toHaveAttribute("scope", "col");
  });

  it("renders the identifying cell as a row header with scope=row", () => {
    render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
      />,
    );
    // This is what lets a reader announce "10.180.6.14, Port, 5985" while
    // moving across, instead of reading a naked number.
    const rowHeaders = screen.getAllByRole("rowheader");
    expect(rowHeaders).toHaveLength(2);
    expect(rowHeaders[0]).toHaveAttribute("scope", "row");
    expect(rowHeaders[0]).toHaveTextContent("10.180.6.14");
  });

  it("exposes sort state through aria-sort", async () => {
    const onSortChange = vi.fn();
    const { rerender } = render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
        onSortChange={onSortChange}
      />,
    );
    const hostHeader = screen.getByRole("columnheader", { name: /Host/ });
    expect(hostHeader).toHaveAttribute("aria-sort", "none");

    await userEvent.click(screen.getByRole("button", { name: /Host/ }));
    expect(onSortChange).toHaveBeenCalledWith({
      key: "host",
      direction: "ascending",
    });

    rerender(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
        sort={{ key: "host", direction: "ascending" }}
        onSortChange={onSortChange}
      />,
    );
    expect(screen.getByRole("columnheader", { name: /Host/ })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
  });

  it("toggles ascending to descending on the sorted column", async () => {
    const onSortChange = vi.fn();
    render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
        sort={{ key: "host", direction: "ascending" }}
        onSortChange={onSortChange}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /Host/ }));
    expect(onSortChange).toHaveBeenCalledWith({
      key: "host",
      direction: "descending",
    });
  });

  it("makes sort controls real buttons, reachable by keyboard", async () => {
    const onSortChange = vi.fn();
    render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
        onSortChange={onSortChange}
      />,
    );
    // A click handler on the <th> would be unreachable without a mouse.
    const button = screen.getByRole("button", { name: /Port/ });
    button.focus();
    await userEvent.keyboard("{Enter}");
    expect(onSortChange).toHaveBeenCalled();
  });

  it("does not render a sort control for a non-sortable column", () => {
    render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={ROWS}
        rowKey={(r) => r.id}
        onSortChange={vi.fn()}
      />,
    );
    expect(screen.queryByRole("button", { name: /Service/ })).toBeNull();
    expect(
      screen.getByRole("columnheader", { name: "Service" }),
    ).not.toHaveAttribute("aria-sort");
  });

  it("shows an empty message inside the table, keeping the header", () => {
    render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={[]}
        emptyMessage="No open services."
      />,
    );
    expect(screen.getByText("No open services.")).toBeInTheDocument();
    // Replacing the whole table would remove the header row and reflow the
    // page on every filter change.
    expect(screen.getAllByRole("columnheader")).toHaveLength(3);
  });

  it("does not show the empty message while loading", () => {
    render(
      <CcureTable
        caption="t"
        columns={COLUMNS}
        rows={[]}
        loading
        emptyMessage="No rows."
      />,
    );
    // "No findings" and "not assessed yet" mean opposite things on a security
    // console; showing the former while still loading is a real defect.
    expect(screen.queryByText("No rows.")).toBeNull();
  });

  it("accepts a caller-supplied body while keeping table semantics", () => {
    render(
      <CcureTable caption="Custom" columns={COLUMNS}>
        <tr>
          <th scope="row">bespoke</th>
          <td>1</td>
          <td>2</td>
        </tr>
      </CcureTable>,
    );
    expect(screen.getByRole("table", { name: "Custom" })).toBeInTheDocument();
    expect(
      screen.getByRole("rowheader", { name: "bespoke" }),
    ).toBeInTheDocument();
  });

  it("announces loading and result counts through a live region", () => {
    const { rerender } = render(<CcureTableStatus loading count={0} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading results");
    rerender(<CcureTableStatus loading={false} count={2} noun="services" />);
    expect(screen.getByRole("status")).toHaveTextContent("2 services");
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Tabs
   ══════════════════════════════════════════════════════════════════════════ */

const TABS = [
  { id: "info", label: "Asset Information" },
  { id: "services", label: "Services & Ports", count: 12 },
  { id: "vulns", label: "Vulnerabilities", count: 3 },
];

function TabHarness({ activateOnFocus = true }) {
  const tabs = useCcureTabs("info");
  return (
    <>
      <CcureTabs
        {...tabs.listProps}
        tabs={TABS}
        label="Asset sections"
        activateOnFocus={activateOnFocus}
      />
      {TABS.map((t) => (
        <CcureTabPanel key={t.id} {...tabs.panelProps(t.id)}>
          Panel for {t.label}
        </CcureTabPanel>
      ))}
    </>
  );
}

describe("CcureTabs", () => {
  it("uses the ARIA tabs pattern", () => {
    render(<TabHarness />);
    expect(
      screen.getByRole("tablist", { name: "Asset sections" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("tab")).toHaveLength(3);
    expect(screen.getByRole("tabpanel")).toBeInTheDocument();
  });

  it("marks exactly one tab selected", () => {
    render(<TabHarness />);
    const selected = screen
      .getAllByRole("tab")
      .filter((t) => t.getAttribute("aria-selected") === "true");
    expect(selected).toHaveLength(1);
    expect(selected[0]).toHaveAccessibleName(/Asset Information/);
  });

  it("associates each panel with its tab, both directions", () => {
    render(<TabHarness />);
    const tab = screen.getByRole("tab", { selected: true });
    const panel = screen.getByRole("tabpanel");
    // A mismatch here is invisible without a screen reader — the ids simply
    // point at nothing and everything still looks correct.
    expect(tab.getAttribute("aria-controls")).toBe(panel.id);
    expect(panel.getAttribute("aria-labelledby")).toBe(tab.id);
  });

  it("is a single tab stop, not one per tab", () => {
    render(<TabHarness />);
    const tabs = screen.getAllByRole("tab");
    const inOrder = tabs.filter((t) => t.getAttribute("tabindex") !== "-1");
    // Roving tabindex: with eight tabs the naive version costs eight Tab
    // presses to get past the bar.
    expect(inOrder).toHaveLength(1);
    expect(inOrder[0]).toHaveAttribute("aria-selected", "true");
  });

  it("moves between tabs with arrow keys and wraps", async () => {
    render(<TabHarness />);
    const user = userEvent.setup();
    await user.tab();
    expect(
      screen.getByRole("tab", { name: /Asset Information/ }),
    ).toHaveFocus();

    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: /Services/ })).toHaveFocus();

    await user.keyboard("{ArrowLeft}{ArrowLeft}");
    expect(screen.getByRole("tab", { name: /Vulnerabilities/ })).toHaveFocus();
  });

  it("supports Home and End", async () => {
    render(<TabHarness />);
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: /Vulnerabilities/ })).toHaveFocus();
    await user.keyboard("{Home}");
    expect(
      screen.getByRole("tab", { name: /Asset Information/ }),
    ).toHaveFocus();
  });

  it("switches the panel when a tab is chosen", async () => {
    render(<TabHarness />);
    await userEvent.click(screen.getByRole("tab", { name: /Vulnerabilities/ }));
    expect(screen.getByRole("tabpanel")).toHaveTextContent(
      "Panel for Vulnerabilities",
    );
  });

  it("does not activate on focus when the caller opts out", async () => {
    render(<TabHarness activateOnFocus={false} />);
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard("{ArrowRight}");
    // Manual activation is right when selecting a tab triggers real work.
    expect(screen.getByRole("tabpanel")).toHaveTextContent(
      "Panel for Asset Information",
    );
    await user.keyboard("{Enter}");
    expect(screen.getByRole("tabpanel")).toHaveTextContent(
      "Panel for Services",
    );
  });

  it("renders a count without it becoming part of nothing", () => {
    render(<TabHarness />);
    expect(
      within(screen.getByRole("tab", { name: /Services/ })).getByText("12"),
    ).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Pagination
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcurePagination", () => {
  const base = { page: 2, pageSize: 25, total: 213, onPageChange: vi.fn() };

  it("is a labelled navigation landmark", () => {
    render(<CcurePagination {...base} />);
    expect(
      screen.getByRole("navigation", { name: "Pagination" }),
    ).toBeInTheDocument();
  });

  it("summarises the range using 1-based pages", () => {
    render(<CcurePagination {...base} />);
    // 1-based matches all seven existing call sites and the backend query
    // parameters; a 0-based component would put an off-by-one at each.
    expect(
      screen.getByText(/Showing 26–50 of 213 results/),
    ).toBeInTheDocument();
  });

  it("announces the page through a live region", () => {
    render(<CcurePagination {...base} />);
    // Paging replaces rows without moving focus, so nothing is announced
    // otherwise.
    expect(screen.getByRole("status")).toHaveTextContent("Page 2 of 9");
  });

  it("disables Previous on the first page and Next on the last", () => {
    const { rerender } = render(<CcurePagination {...base} page={1} />);
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();

    rerender(<CcurePagination {...base} page={9} />);
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("moves a page at a time", async () => {
    const onPageChange = vi.fn();
    render(<CcurePagination {...base} onPageChange={onPageChange} />);
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onPageChange).toHaveBeenCalledWith(3);
    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    expect(onPageChange).toHaveBeenCalledWith(1);
  });

  it("labels the page-size control", async () => {
    const onPageSizeChange = vi.fn();
    render(<CcurePagination {...base} onPageSizeChange={onPageSizeChange} />);
    // The existing implementations put a bare <select> next to the word
    // "Show", which associates nothing.
    const select = screen.getByLabelText("Rows per page");
    await userEvent.selectOptions(select, "50");
    expect(onPageSizeChange).toHaveBeenCalledWith(50);
  });

  it("handles an empty result set without going below zero", () => {
    render(<CcurePagination {...base} page={1} total={0} />);
    expect(screen.getByText(/Showing 0–0 of 0 results/)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Page 1 of 1");
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Breadcrumb
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcureBreadcrumb", () => {
  const items = [
    { label: "Assets", href: "/assets" },
    { label: "10.180.6.14", href: "/assets/1" },
    { label: "Services" },
  ];

  it("is a labelled navigation containing a list", () => {
    render(<CcureBreadcrumb items={items} />);
    const nav = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(nav).getByRole("list")).toBeInTheDocument();
    expect(within(nav).getAllByRole("listitem")).toHaveLength(3);
  });

  it("marks the last item as the current page and not a link", () => {
    render(<CcureBreadcrumb items={items} />);
    const current = screen.getByText("Services");
    expect(current).toHaveAttribute("aria-current", "page");
    // A link to where you already are is a trap and announces an action that
    // does nothing.
    expect(screen.queryByRole("link", { name: "Services" })).toBeNull();
  });

  it("renders ancestors as links", () => {
    render(<CcureBreadcrumb items={items} />);
    expect(screen.getByRole("link", { name: "Assets" })).toHaveAttribute(
      "href",
      "/assets",
    );
  });

  it("supports router navigation via onClick", async () => {
    const onClick = vi.fn();
    render(
      <CcureBreadcrumb
        items={[{ label: "Assets", onClick }, { label: "Detail" }]}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Assets" }));
    expect(onClick).toHaveBeenCalled();
  });

  it("hides separators from assistive technology", () => {
    const { container } = render(<CcureBreadcrumb items={items} />);
    const seps = container.querySelectorAll(".cc-breadcrumb__separator");
    expect(seps).toHaveLength(2);
    for (const s of seps) expect(s).toHaveAttribute("aria-hidden", "true");
  });

  it("renders nothing when there are no items", () => {
    const { container } = render(<CcureBreadcrumb items={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Card
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcureCard", () => {
  it("renders its title as a real heading", () => {
    render(<CcureCard title="Open ports">body</CcureCard>);
    // A styled <div> is invisible to heading navigation, which is how most
    // screen-reader users move around a dense page.
    expect(
      screen.getByRole("heading", { level: 2, name: "Open ports" }),
    ).toBeInTheDocument();
  });

  it("honours the requested heading level", () => {
    render(
      <CcureCard title="Sub" headingLevel={3}>
        body
      </CcureCard>,
    );
    expect(
      screen.getByRole("heading", { level: 3, name: "Sub" }),
    ).toBeInTheDocument();
  });

  it("names its region from the title", () => {
    render(<CcureCard title="Findings">body</CcureCard>);
    expect(
      screen.getByRole("region", { name: "Findings" }),
    ).toBeInTheDocument();
  });

  it("is not a named region when it has no title", () => {
    // An unnamed landmark is worse than none — it adds a stop that says
    // nothing.
    render(<CcureCard>body</CcureCard>);
    expect(screen.queryByRole("region")).toBeNull();
  });

  it("renders actions and footer when supplied", () => {
    render(
      <CcureCard
        title="T"
        actions={<button type="button">Act</button>}
        footer={<span>foot</span>}
      >
        body
      </CcureCard>,
    );
    expect(screen.getByRole("button", { name: "Act" })).toBeInTheDocument();
    expect(screen.getByText("foot")).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Badge
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcureBadge", () => {
  it("always renders text, never colour alone", () => {
    render(<CcureBadge variant="danger">Failed</CcureBadge>);
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  it("hides the decorative dot from assistive technology", () => {
    const { container } = render(<CcureBadge dot>Running</CcureBadge>);
    expect(container.querySelector(".cc-badge__dot")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });

  it("falls back to neutral for an unknown variant", () => {
    // Rather than emitting a class with no rule behind it, which renders as an
    // unstyled span and reads as a CSS bug.
    const { container } = render(<CcureBadge variant="critical">X</CcureBadge>);
    expect(container.querySelector(".cc-badge")).toHaveClass(
      "cc-badge--neutral",
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Feedback: Loader / Skeleton / EmptyState / Progress
   ══════════════════════════════════════════════════════════════════════════ */

describe("CcureLoader", () => {
  it("does not duplicate an existing domain loading announcement", () => {
    const { container } = render(
      <span role="status">
        <CcureLoader decorative size="sm" /> Port scan running
      </span>,
    );
    expect(screen.getAllByRole("status")).toHaveLength(1);
    expect(screen.getByRole("status")).toHaveTextContent("Port scan running");
    expect(container.querySelector(".cc-loader__spinner")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });
  it("announces itself politely with accessible text", () => {
    render(<CcureLoader label="Loading findings" />);
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveTextContent("Loading findings");
  });

  it("still has accessible text when no label is given", () => {
    render(<CcureLoader label="" />);
    // A spinner with no text is silent.
    expect(screen.getByRole("status")).toHaveTextContent("Loading…");
  });
});

describe("CcureSkeleton", () => {
  it("is hidden from assistive technology", () => {
    const { container } = render(<CcureSkeleton />);
    // A screen reader must not announce a row of grey boxes; the surrounding
    // region carries the status message instead.
    expect(container.querySelector(".cc-skeleton")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });
});

describe("CcureEmptyState", () => {
  it("renders title, description and action", () => {
    render(
      <CcureEmptyState
        icon="∅"
        title="No findings"
        description="This host passed every check."
        action={<button type="button">Rescan</button>}
      />,
    );
    expect(screen.getByText("No findings")).toBeInTheDocument();
    expect(
      screen.getByText("This host passed every check."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rescan" })).toBeInTheDocument();
  });

  it("hides the decorative icon", () => {
    const { container } = render(<CcureEmptyState icon="∅" title="t" />);
    expect(container.querySelector(".cc-empty__icon")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });
});

describe("CcureProgress", () => {
  it("reports a determinate value", () => {
    render(<CcureProgress value={40} label="Scan progress" />);
    const bar = screen.getByRole("progressbar", { name: "Scan progress" });
    expect(bar).toHaveAttribute("aria-valuenow", "40");
    expect(bar).toHaveAttribute("aria-valuemin", "0");
    expect(bar).toHaveAttribute("aria-valuemax", "100");
  });

  it("omits aria-valuenow when the value is unknown", () => {
    render(<CcureProgress value={null} label="Scanning" />);
    const bar = screen.getByRole("progressbar", { name: "Scanning" });
    // "0% done" is a measurement; "we do not know" is not. A scan whose
    // progress cannot be determined must not report no progress.
    expect(bar).not.toHaveAttribute("aria-valuenow");
    expect(bar).toHaveAttribute("aria-valuetext", "In progress");
  });

  it("clamps a value outside the range", () => {
    render(<CcureProgress value={150} label="p" />);
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "100",
    );
  });

  it("has an accessible name even with no label", () => {
    render(<CcureProgress value={10} />);
    expect(
      screen.getByRole("progressbar", { name: "Progress" }),
    ).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Theme: the primitives must not hardcode colour
   ══════════════════════════════════════════════════════════════════════════ */

describe("theming", () => {
  it("renders under data-theme=dark without inline colour overrides", () => {
    document.documentElement.setAttribute("data-theme", "dark");
    try {
      const { container } = render(
        <>
          <CcureBadge variant="danger">Critical</CcureBadge>
          <CcureCard title="T">b</CcureCard>
          <CcureProgress value={50} label="p" />
        </>,
      );
      // Colour comes from tokens under [data-theme], so no primitive may pin a
      // colour inline — that is what makes one attribute switch the theme.
      for (const el of container.querySelectorAll("*")) {
        const style = el.getAttribute("style") ?? "";
        expect(style).not.toMatch(/(^|;)\s*(color|background)/);
      }
    } finally {
      document.documentElement.removeAttribute("data-theme");
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Controlled usage — React owns the state
   ══════════════════════════════════════════════════════════════════════════ */

describe("controlled state", () => {
  it("lets the caller own the selected tab", async () => {
    function Controlled() {
      const [value, setValue] = useState("services");
      const tabs = useCcureTabs("info", { value, onChange: setValue });
      return (
        <>
          <span data-testid="value">{value}</span>
          <CcureTabs {...tabs.listProps} tabs={TABS} label="l" />
        </>
      );
    }
    render(<Controlled />);
    expect(screen.getByTestId("value")).toHaveTextContent("services");
    await userEvent.click(screen.getByRole("tab", { name: /Vulnerabilities/ }));
    expect(screen.getByTestId("value")).toHaveTextContent("vulns");
  });
});

// URL-controlled report and registry tabs use an empty value for their default view.
describe("URL-controlled default tabs", () => {
  it("returns to the empty-id view with arrows and Home, with panel association", async () => {
    const user = userEvent.setup();
    function RegistryTabs() {
      const [value, setValue] = useState("services");
      return (
        <>
          <CcureTabs
            id="registry-test"
            label="Registry views"
            tabs={[
              { id: "", label: "Inventory" },
              { id: "services", label: "Services" },
            ]}
            value={value}
            onChange={setValue}
          />
          <CcureTabPanel tabsId="registry-test" id={value} active>
            Current view
          </CcureTabPanel>
        </>
      );
    }
    render(<RegistryTabs />);
    screen.getByRole("tab", { name: "Services" }).focus();
    await user.keyboard("{ArrowLeft}");
    const inventory = screen.getByRole("tab", { name: "Inventory" });
    expect(inventory).toHaveFocus();
    expect(inventory).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveAccessibleName("Inventory");
    expect(inventory).toHaveAttribute(
      "aria-controls",
      screen.getByRole("tabpanel").id,
    );
    await user.keyboard("{ArrowRight}{Home}");
    expect(inventory).toHaveFocus();
    expect(inventory).toHaveAttribute("aria-selected", "true");
  });
});
