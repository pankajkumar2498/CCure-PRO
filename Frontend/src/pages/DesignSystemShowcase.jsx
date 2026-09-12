import { useEffect, useState } from "react";
import {
  CcureAppShell,
  CcureAlert,
  CcureBadge,
  CcureBreadcrumb,
  CcureButton,
  CcureCard,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcureModal,
  CcurePagination,
  CcureProgress,
  CcureScanProgress,
  CcureScanStatus,
  CcureSelect,
  CcureSeverityBadge,
  CcureSkeleton,
  CcureTable,
  CcureTabPanel,
  CcureTabs,
  CcureToastProvider,
  useCcureTabs,
  useCcureToast,
} from "../design-system";

/**
 * src/pages/DesignSystemShowcase.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Development-only showcase for the CCure design system. Reachable at
 * /design-system in a dev build and absent from every production build — see
 * the `import.meta.env.DEV` guard in App.jsx, which a guardrail test verifies
 * against dist/.
 *
 * It is a verification surface, not a product page: it renders no application
 * data, calls no API, and holds no state a user could persist. Its job is to
 * exercise every primitive in both themes so a change to the token layer is
 * visible somewhere before it is visible on a page a customer uses.
 *
 * Everything below composes `../design-system`. Nothing imports
 * `ux4g-web-components`, and nothing uses a `ux4g-` class — production ships
 * tokens only, so such a class would match no rule and style nothing. Both
 * rules are enforced by src/__tests__/design-system/guardrails.test.js.
 */

/* Literal mock data only — the showcase makes no API call and has no auth or
   backend dependency. */
const SEVERITY_BANDS = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "none",
  "unscored",
];

const SCAN_STATES = [
  "running",
  "queued",
  "pending",
  "complete",
  "failed",
  "unreachable",
  "cancelled",
  "something_the_api_added_later",
];

const SHOWCASE_TABS = [
  { id: "info", label: "Asset Information" },
  { id: "services", label: "Services & Ports", count: 4 },
  { id: "vulns", label: "Vulnerabilities", count: 12 },
  { id: "changelog", label: "Audit & Changelog" },
];

const TABLE_COLUMNS = [
  {
    key: "host",
    header: "Host",
    isRowHeader: true,
    sortable: true,
    mono: true,
  },
  { key: "port", header: "Port", sortable: true, mono: true, align: "end" },
  { key: "proto", header: "Proto", nowrap: true },
  { key: "service", header: "Service", sortable: true },
  { key: "state", header: "State" },
];

const TABLE_ROWS = [
  {
    id: 1,
    host: "10.180.6.14",
    port: 5985,
    proto: "tcp",
    service: "wsman",
    state: "open",
  },
  {
    id: 2,
    host: "10.180.6.14",
    port: 3389,
    proto: "tcp",
    service: "ms-wbt-server",
    state: "open",
  },
  {
    id: 3,
    host: "10.180.6.20",
    port: 22,
    proto: "tcp",
    service: "ssh",
    state: "open",
  },
  {
    id: 4,
    host: "10.180.6.31",
    port: 161,
    proto: "udp",
    service: "snmp",
    state: "filtered",
  },
];

/**
 * Sorting belongs to the caller. CcureTable reports the intent through
 * onSortChange and renders whatever rows it is handed, so a page backed by a
 * paginated API sorts on the server instead of in the browser.
 */
function sortRows(rows, sort) {
  if (!sort || !sort.key) return rows;
  const dir = sort.direction === "descending" ? -1 : 1;
  return [...rows].sort((a, b) => {
    const x = a[sort.key];
    const y = b[sort.key];
    if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
    return String(x).localeCompare(String(y)) * dir;
  });
}

const SECTIONS = [
  {
    label: "Overview",
    items: [
      {
        id: "dash",
        label: "Security Dashboard",
        route: "/design-system",
        icon: "▤",
      },
      {
        id: "reports",
        label: "Executive Report",
        route: "/design-system#reports",
        icon: "▦",
      },
    ],
  },
  {
    label: "Assessment",
    items: [
      {
        id: "assets",
        label: "Asset Registry",
        route: "/design-system#assets",
        icon: "▣",
      },
      {
        id: "vulns",
        label: "Vulnerabilities",
        route: "/design-system#vulns",
        icon: "⚠",
      },
      {
        id: "compliance",
        label: "Compliance",
        route: "/design-system#compliance",
        icon: "✓",
      },
    ],
  },
];

/** Showcase-local theme switch.
 *
 *  It writes the SAME attribute PreferencesContext writes — documentElement's
 *  `data-theme` — because the entire point of Test 6 is that one attribute
 *  drives both UX4G's 217 dark tokens and CCure's. It deliberately does not
 *  call the preferences API: persisting a theme is the real toggle's job, and
 *  a showcase must not write to a user's account.
 */
function useShowcaseTheme() {
  const [theme, setTheme] = useState(() => {
    // `?theme=dark` exists so a headless browser can capture the dark render
    // without needing to click. Development-only, like the route itself.
    const q = new URLSearchParams(window.location.search).get("theme");
    if (q === "dark" || q === "light") return q;
    return document.documentElement.getAttribute("data-theme") || "light";
  });

  useEffect(() => {
    const root = document.documentElement;
    const previous = root.getAttribute("data-theme");
    if (theme === "dark") root.setAttribute("data-theme", "dark");
    else root.removeAttribute("data-theme");
    return () => {
      // Restore on unmount so navigating away cannot leave the
      // application on a theme the user's stored preference disagrees with.
      if (previous) root.setAttribute("data-theme", previous);
      else root.removeAttribute("data-theme");
    };
  }, [theme]);

  return [theme, setTheme];
}

function ShowcaseBody() {
  const toast = useCcureToast();
  const [theme, setTheme] = useShowcaseTheme();
  const [modalOpen, setModalOpen] = useState(false);
  const [page, setPage] = useState(2);
  const [pageSize, setPageSize] = useState(25);
  const [sort, setSort] = useState({ key: "host", direction: "ascending" });
  const tabs = useCcureTabs("services");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);

  const emailError =
    submitted && !email ? "Enter your email address or username." : "";
  const passwordError =
    submitted && password.length > 0 && password.length < 8
      ? "Password must be at least 8 characters."
      : "";

  // Nothing is sent anywhere. This reproduces the *shape* of Login's form so
  // label association, error association and focus order can be tested; the
  // real Login.jsx is untouched and remains a Test 5 regression control.
  const onSubmit = (e) => {
    e.preventDefault();
    setSubmitted(true);
    if (!email) return;
    setBusy(true);
    setTimeout(() => {
      setBusy(false);
      toast.success("Form validated locally. No request was sent.");
    }, 900);
  };

  return (
    <CcureAppShell
      title="CCure design system"
      meta="Development build · not a product page"
      sections={SECTIONS}
      currentPath="/design-system"
      onNavigate={() => {}}
      identity="Operated by the Centre for Development of Advanced Computing"
      footerNote="CCure Audit PRO — internal security assessment platform"
      footerLinks={[
        { href: "#accessibility", label: "Accessibility statement" },
        { href: "#help", label: "Help" },
        { href: "#terms", label: "Terms of use" },
      ]}
      sidebarFooter={<span>Development build</span>}
      headerActions={
        <>
          <CcureButton
            size="sm"
            variant="secondary"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-pressed={theme === "dark"}
          >
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </CcureButton>
          <CcureButton size="sm" onClick={() => setModalOpen(true)}>
            Open dialog
          </CcureButton>
        </>
      }
    >
      <div style={{ display: "grid", gap: "2rem", maxWidth: "64rem" }}>
        <Section title="Alerts">
          <div style={{ display: "grid", gap: "0.75rem" }}>
            {/* live={false}: these are page furniture, not events. Announcing
                four of them on every load is exactly the misuse the prop
                exists to prevent. */}
            <CcureAlert variant="info" title="Informational" live={false}>
              Discovery completed in 2.2 seconds across 254 addresses.
            </CcureAlert>
            <CcureAlert variant="success" title="Success" live={false}>
              All 24 configuration checks passed on this host.
            </CcureAlert>
            <CcureAlert variant="warning" title="Warning" live={false}>
              The credential was refused. Findings for this host are unassessed,
              not clean.
            </CcureAlert>
            <CcureAlert
              variant="danger"
              title="Critical"
              live={false}
              onDismiss={() => toast.info("Alert dismissed.")}
            >
              3 findings are past their remediation deadline.
            </CcureAlert>
          </div>
        </Section>

        <Section title="Buttons">
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
            <CcureButton>Primary</CcureButton>
            <CcureButton variant="secondary">Secondary</CcureButton>
            <CcureButton variant="ghost">Ghost</CcureButton>
            <CcureButton variant="danger">Danger</CcureButton>
            <CcureButton disabled>Disabled</CcureButton>
            <CcureButton loading>Loading</CcureButton>
          </div>
          <div
            style={{
              display: "flex",
              gap: "0.75rem",
              alignItems: "center",
              marginTop: "0.75rem",
            }}
          >
            <CcureButton size="sm">Small</CcureButton>
            <CcureButton size="md">Medium</CcureButton>
            <CcureButton size="lg">Large</CcureButton>
          </div>
        </Section>

        <Section title="Sign in — form composition">
          <form
            onSubmit={onSubmit}
            noValidate
            style={{ display: "grid", gap: "1rem", maxWidth: "26rem" }}
          >
            <CcureInput
              label="Email or username"
              type="text"
              required
              value={email}
              autoComplete="username"
              onChange={(e) => setEmail(e.target.value)}
              hint="Use the address your account was created with."
              error={emailError}
            />
            <CcureInput
              label="Password"
              type="password"
              required
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
              error={passwordError}
            />
            <CcureSelect label="Organisation" defaultValue="default">
              <option value="default">org_default</option>
              <option value="ot">OT segment</option>
            </CcureSelect>
            <CcureButton type="submit" loading={busy} block>
              Sign in
            </CcureButton>
          </form>
        </Section>

        <Section title="Toasts">
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
            <CcureButton
              size="sm"
              variant="secondary"
              onClick={() => toast.info("Scan queued.")}
            >
              Info
            </CcureButton>
            <CcureButton
              size="sm"
              variant="secondary"
              onClick={() => toast.success("Report generated.")}
            >
              Success
            </CcureButton>
            <CcureButton
              size="sm"
              variant="secondary"
              onClick={() => toast.warning("Worker not responding.")}
            >
              Warning (assertive)
            </CcureButton>
            <CcureButton
              size="sm"
              variant="secondary"
              onClick={() =>
                toast.danger("Scan failed to start.", { duration: 0 })
              }
            >
              Danger (stays)
            </CcureButton>
          </div>
        </Section>

        <Section title="Table">
          <CcureTable
            caption="Open services on 10.180.6.14"
            captionVisible
            columns={TABLE_COLUMNS}
            rows={sortRows(TABLE_ROWS, sort)}
            rowKey={(r) => r.id}
            sort={sort}
            onSortChange={setSort}
            density="compact"
          />
        </Section>

        <Section title="Table - loading and empty">
          <div style={{ display: "grid", gap: "1rem" }}>
            <CcureTable
              caption="Loading example"
              captionVisible
              columns={TABLE_COLUMNS}
              rows={[]}
              loading
              loadingRows={3}
            />
            <CcureTable
              caption="Empty example"
              captionVisible
              columns={TABLE_COLUMNS}
              rows={[]}
              empty={
                <CcureEmptyState
                  title="No open services"
                  description="Discovery found this host but no listening TCP ports."
                />
              }
            />
          </div>
        </Section>

        <Section title="Tabs">
          <CcureTabs
            {...tabs.listProps}
            tabs={SHOWCASE_TABS}
            label="Asset sections"
          />
          {SHOWCASE_TABS.map((t) => (
            <CcureTabPanel key={t.id} {...tabs.panelProps(t.id)}>
              <p
                style={{
                  margin: "1rem 0 0",
                  color: "var(--ccure-text-secondary)",
                }}
              >
                Panel content for <strong>{t.label}</strong>. Arrow keys move
                between tabs; the whole tab list is a single tab stop.
              </p>
            </CcureTabPanel>
          ))}
        </Section>

        <Section title="Pagination">
          <CcurePagination
            page={page}
            pageSize={pageSize}
            total={213}
            itemNoun="findings"
            onPageChange={setPage}
            onPageSizeChange={(n) => {
              setPageSize(n);
              setPage(1);
            }}
          />
        </Section>

        <Section title="Breadcrumb">
          <CcureBreadcrumb
            items={[
              { label: "Assets", onClick: () => {} },
              { label: "10.180.6.14", onClick: () => {} },
              { label: "Services and Ports" },
            ]}
          />
        </Section>

        <Section title="Badges">
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            <CcureBadge>Neutral</CcureBadge>
            <CcureBadge variant="primary">Primary</CcureBadge>
            <CcureBadge variant="success" dot>
              Completed
            </CcureBadge>
            <CcureBadge variant="warning" dot>
              Degraded
            </CcureBadge>
            <CcureBadge variant="danger" dot>
              Failed
            </CcureBadge>
            <CcureBadge variant="info">Queued</CcureBadge>
            <CcureBadge variant="neutral" mono size="md">
              CVE-2024-21413
            </CcureBadge>
          </div>
        </Section>

        <Section title="Cards">
          <div
            style={{
              display: "grid",
              gap: "1rem",
              gridTemplateColumns: "repeat(auto-fit, minmax(16rem, 1fr))",
            }}
          >
            <CcureCard
              title="Credentialed coverage"
              subtitle="Last 30 days"
              headingLevel={3}
            >
              <CcureProgress value={62} label="Hosts authenticated" />
            </CcureCard>
            <CcureCard
              title="With actions"
              headingLevel={3}
              actions={
                <CcureButton size="sm" variant="secondary">
                  Export
                </CcureButton>
              }
              footer={<CcureButton size="sm">Open</CcureButton>}
            >
              A card renders its title as a real heading and names its own
              region.
            </CcureCard>
          </div>
        </Section>

        <Section title="Progress, loading and empty">
          <div style={{ display: "grid", gap: "1.25rem", maxWidth: "34rem" }}>
            <CcureProgress value={35} label="Phase 2 - port scan" />
            <CcureProgress
              value={100}
              variant="success"
              label="Phase 1 - discovery"
            />
            <CcureProgress value={null} label="Waiting for a worker" />
            <div style={{ display: "flex", gap: "2rem", alignItems: "center" }}>
              <CcureLoader label="Loading findings" />
              <CcureLoader inline label="Inline" />
            </div>
            <div>
              <CcureSkeleton width="60%" />
              <CcureSkeleton width="90%" />
              <CcureSkeleton width="40%" />
            </div>
            <CcureEmptyState
              title="No findings"
              description="This host passed every check in the selected policy."
              action={<CcureButton size="sm">Run a scan</CcureButton>}
            />
          </div>
        </Section>

        <Section title="Severity — the canonical band rendering">
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            {SEVERITY_BANDS.map((sev) => (
              <CcureSeverityBadge key={sev} severity={sev} />
            ))}
          </div>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "0.5rem",
              marginTop: "0.75rem",
            }}
          >
            <CcureSeverityBadge severity="critical" score={9.8} />
            <CcureSeverityBadge severity="high" score={7.5} />
            <CcureSeverityBadge severity="medium" score={5.4} />
            <CcureSeverityBadge severity="Critical" />
            <CcureSeverityBadge severity="banana" />
          </div>
          <p
            style={{
              margin: "0.75rem 0 0",
              fontSize: "var(--ccure-text-sm)",
              color: "var(--ccure-text-secondary)",
            }}
          >
            Both spellings the API returns are accepted. An unrecognised value
            renders as <strong>Unscored</strong>, never as Info — asserting a
            rating that was never published is the defect this replaces.
          </p>
        </Section>

        <Section title="Scan status">
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            {SCAN_STATES.map((st) => (
              <CcureScanStatus key={st} status={st} />
            ))}
          </div>
          <p
            style={{
              margin: "0.75rem 0 0",
              fontSize: "var(--ccure-text-sm)",
              color: "var(--ccure-text-secondary)",
            }}
          >
            The last chip is an unrecognised status. It reads{" "}
            <strong>Unknown</strong>; the page it replaces rendered it as
            <em> Running</em>, which is a false statement about a scan.
          </p>
        </Section>

        <Section title="Scan progress">
          <div style={{ display: "grid", gap: "1.25rem", maxWidth: "34rem" }}>
            <CcureScanProgress
              value={67}
              status="running"
              phase="Phase 2 — port scan"
              label="Known progress"
            />
            <CcureScanProgress
              value={null}
              status="running"
              phase="Waiting for the host worker"
              label="Unknown, still running"
            />
            <CcureScanProgress
              value={null}
              status="failed"
              phase="No percentage was ever reported"
              label="Unknown, stopped"
            />
            <CcureScanProgress value={97} status="complete" label="Completed" />
          </div>
          <p
            style={{
              margin: "0.75rem 0 0",
              fontSize: "var(--ccure-text-sm)",
              color: "var(--ccure-text-secondary)",
            }}
          >
            Neither unknown case prints a number, and neither sets{" "}
            <code>aria-valuenow</code>. A stopped scan does not animate.
          </p>
        </Section>

        <Section title="Typography">
          <p style={{ margin: 0, color: "var(--ccure-text)" }}>
            Body text in Noto Sans, self-hosted as WOFF2 and served from this
            origin. If this renders in a system fallback the font extraction
            failed or <code>font-src</code> blocked it.
          </p>
          <p
            style={{
              margin: "0.5rem 0 0",
              color: "var(--ccure-text-secondary)",
            }}
          >
            Secondary text tier.
          </p>
          <p
            style={{
              margin: "0.5rem 0 0",
              fontFamily: "var(--ccure-font-mono)",
            }}
          >
            10.180.6.14:5985 · CVE-2024-21413 · CCURE-CFG-2-3-1-1
          </p>
        </Section>
      </div>

      <CcureModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Confirm scan cancellation"
        subtitle="This stops the running scan and records a cancelled outcome."
        footer={
          <>
            <CcureButton variant="ghost" onClick={() => setModalOpen(false)}>
              Keep running
            </CcureButton>
            <CcureButton
              variant="danger"
              onClick={() => {
                setModalOpen(false);
                toast.warning("Scan cancelled.");
              }}
            >
              Cancel scan
            </CcureButton>
          </>
        }
      >
        <p style={{ marginTop: 0 }}>
          Tab is trapped inside this dialog, Escape closes it, and focus returns
          to the button that opened it.
        </p>
        <CcureInput
          label="Reason (optional)"
          placeholder="e.g. wrong target range"
        />
      </CcureModal>
    </CcureAppShell>
  );
}

/**
 * `?section=severity` renders only the sections whose title contains that
 * text. A development affordance for headless verification: the showcase is
 * taller than any single screenshot, so without it the lower sections cannot
 * be captured. Same category as `?theme=` — dev-only, like the route itself.
 */
function sectionFilter() {
  return (new URLSearchParams(window.location.search).get("section") || "")
    .trim()
    .toLowerCase();
}

function Section({ title, children }) {
  const filter = sectionFilter();
  if (filter && !title.toLowerCase().includes(filter)) return null;

  return (
    <section
      aria-labelledby={`ds-${title.toLowerCase().replace(/[^a-z]+/g, "-")}`}
      style={{
        background: "var(--ccure-surface)",
        border: "1px solid var(--ccure-border)",
        borderRadius: "var(--ccure-radius-lg)",
        padding: "1.25rem",
      }}
    >
      <h2
        id={`ds-${title.toLowerCase().replace(/[^a-z]+/g, "-")}`}
        style={{
          margin: "0 0 1rem",
          fontSize: "var(--ccure-text-lg)",
          fontWeight: "var(--ccure-weight-semibold)",
          color: "var(--ccure-text)",
        }}
      >
        {title}
      </h2>
      {children}
    </section>
  );
}

export default function DesignSystemShowcase() {
  return (
    <CcureToastProvider>
      <ShowcaseBody />
    </CcureToastProvider>
  );
}
