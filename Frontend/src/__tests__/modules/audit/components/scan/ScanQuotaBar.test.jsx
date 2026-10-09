/**
 * ScanQuotaBar — Checkpoint 3C batch 15.
 *
 * Written against the legacy widget BEFORE migration. Everything up to the
 * last block holds on both sides; the last block is the migration spec and
 * fails on the baseline.
 *
 * One consumer, NewScan, whose own test mocks this component out — so until
 * this file existed nothing exercised the poll at all. The poll is the part
 * worth protecting: `onQuotaChange` is an inline arrow in NewScan, and a
 * version that depended on it directly restarted the 30 s interval on every
 * parent render, turning a poll into a burst of requests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { readFileSync } from "node:fs";
import path from "node:path";

import ScanQuotaBar from "@audit/components/scan/ScanQuotaBar";
import { getScanQuota } from "@audit/api/scans";
import { SRC, AUDIT_SRC } from "../../../../testPaths";

vi.mock("@audit/api/scans", () => ({ getScanQuota: vi.fn() }));

const QUOTA = {
  plan: "pro",
  scans_used_24h: 3,
  scans_limit_24h: 10,
  concurrent_running: 1,
  concurrent_limit: 2,
  max_ips_per_scan: 1024,
  quota_exceeded: false,
  concurrent_exceeded: false,
};
const ok = (over = {}) => ({ data: { ...QUOTA, ...over } });

async function renderBar(props = {}) {
  let utils;
  await act(async () => {
    utils = render(<ScanQuotaBar {...props} />);
  });
  return utils;
}

const region = () => screen.queryByRole("region", { name: "Scan quota usage" });
const bars = () => [
  ...screen.queryAllByRole("progressbar"),
  ...screen.queryAllByRole("meter"),
];

beforeEach(() => {
  getScanQuota.mockReset();
});

/* ══════════════════════════════════════════════════════════════════════════
   Visibility
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanQuotaBar — visibility", () => {
  it("renders nothing until the quota arrives", () => {
    getScanQuota.mockReturnValue(new Promise(() => {}));
    const { container } = render(<ScanQuotaBar />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing, and reports nothing, when the quota cannot be read", async () => {
    getScanQuota.mockRejectedValue(new Error("503"));
    const onQuotaChange = vi.fn();
    const { container } = await renderBar({ onQuotaChange });
    expect(container).toBeEmptyDOMElement();
    expect(onQuotaChange).not.toHaveBeenCalled();
  });

  it("is a region named for what it shows", async () => {
    getScanQuota.mockResolvedValue(ok());
    await renderBar();
    expect(region()).toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Contents
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanQuotaBar — contents", () => {
  it.each([
    ["community", "Community"],
    ["pro", "Pro"],
    ["enterprise", "Enterprise"],
    ["no-such-plan", "Free"],
    [undefined, "Free"],
  ])("labels plan %s as %s", async (plan, label) => {
    getScanQuota.mockResolvedValue(ok({ plan }));
    await renderBar();
    expect(screen.getByText(label, { exact: true })).toBeInTheDocument();
  });

  it("states the per-scan IP ceiling and concurrent use", async () => {
    getScanQuota.mockResolvedValue(ok());
    await renderBar();
    expect(screen.getByText(/Max 1,024 IPs\/scan/)).toBeInTheDocument();
    expect(screen.getByText(/1\/2 running/)).toBeInTheDocument();
  });

  it("states daily and concurrent usage against their limits", async () => {
    getScanQuota.mockResolvedValue(ok());
    await renderBar();
    expect(screen.getByText("Scans today (24 h)")).toBeInTheDocument();
    expect(screen.getByText("3 / 10 used")).toBeInTheDocument();
    expect(screen.getByText("Concurrent scans")).toBeInTheDocument();
    expect(screen.getByText("1 / 2 active")).toBeInTheDocument();
    expect(bars()).toHaveLength(2);
  });

  it("shows an unlimited daily plan as unlimited, with no bar", async () => {
    getScanQuota.mockResolvedValue(ok({ scans_limit_24h: null }));
    await renderBar();
    expect(screen.getByText("3 (unlimited)")).toBeInTheDocument();
    expect(bars()).toHaveLength(1);
  });

  it("raises no alert while within limits", async () => {
    getScanQuota.mockResolvedValue(ok());
    await renderBar();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("alerts when the daily limit is reached", async () => {
    getScanQuota.mockResolvedValue(
      ok({ scans_used_24h: 10, quota_exceeded: true }),
    );
    await renderBar();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Daily scan limit reached (10/10). Please wait or upgrade your plan.",
    );
  });

  it("alerts when the concurrent limit is reached", async () => {
    getScanQuota.mockResolvedValue(
      ok({ concurrent_running: 2, concurrent_exceeded: true }),
    );
    await renderBar();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Concurrent scan limit reached (2/2). Wait for a running scan to finish.",
    );
  });

  it("reports exactly the two blocking flags to the page", async () => {
    getScanQuota.mockResolvedValue(
      ok({ quota_exceeded: true, concurrent_exceeded: false }),
    );
    const onQuotaChange = vi.fn();
    await renderBar({ onQuotaChange });
    expect(onQuotaChange).toHaveBeenCalledTimes(1);
    expect(onQuotaChange).toHaveBeenCalledWith({
      quota_exceeded: true,
      concurrent_exceeded: false,
    });
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Polling
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanQuotaBar — polling", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const tick = (ms) =>
    act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });

  it("reads the quota on mount and then every 30 seconds", async () => {
    getScanQuota.mockResolvedValue(ok());
    await renderBar();
    expect(getScanQuota).toHaveBeenCalledTimes(1);
    await tick(29_999);
    expect(getScanQuota).toHaveBeenCalledTimes(1);
    await tick(1);
    expect(getScanQuota).toHaveBeenCalledTimes(2);
    await tick(30_000);
    expect(getScanQuota).toHaveBeenCalledTimes(3);
  });

  it("keeps its own clock when the page re-renders with a new callback", async () => {
    getScanQuota.mockResolvedValue(ok());
    const first = vi.fn();
    const { rerender } = await renderBar({ onQuotaChange: first });

    let latest = first;
    for (let i = 0; i < 5; i += 1) {
      await tick(5_000);
      latest = vi.fn();
      rerender(<ScanQuotaBar onQuotaChange={latest} />);
    }
    // 25 s of re-renders issued no request of their own.
    expect(getScanQuota).toHaveBeenCalledTimes(1);

    await tick(5_000);
    expect(getScanQuota).toHaveBeenCalledTimes(2);
    // The poll result went to the callback current at the time, not the
    // one captured at mount.
    expect(first).toHaveBeenCalledTimes(1);
    expect(latest).toHaveBeenCalledTimes(1);
  });

  it("stops polling when unmounted", async () => {
    getScanQuota.mockResolvedValue(ok());
    const { unmount } = await renderBar();
    unmount();
    await tick(120_000);
    expect(getScanQuota).toHaveBeenCalledTimes(1);
  });

  it("reflects new numbers on the next poll", async () => {
    getScanQuota
      .mockResolvedValueOnce(ok())
      .mockResolvedValueOnce(ok({ scans_used_24h: 4 }));
    await renderBar();
    expect(screen.getByText("3 / 10 used")).toBeInTheDocument();
    await tick(30_000);
    expect(screen.getByText("4 / 10 used")).toBeInTheDocument();
  });

  it("hides a bar that was showing when a later poll fails", async () => {
    getScanQuota
      .mockResolvedValueOnce(ok())
      .mockRejectedValueOnce(new Error("network"));
    await renderBar();
    expect(region()).toBeInTheDocument();
    await tick(30_000);
    expect(region()).toBeNull();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Migration spec — fails on the baseline
   ══════════════════════════════════════════════════════════════════════════ */

describe("ScanQuotaBar — migration spec", () => {
  it("presents usage as named meters, not as progress", async () => {
    // Quota use is a measurement within a known range, not a task advancing
    // towards completion. The legacy bars were unnamed progressbars valued in
    // percent, so a screen reader heard "30, progress bar" with no subject.
    getScanQuota.mockResolvedValue(ok());
    await renderBar();
    expect(screen.queryAllByRole("progressbar")).toHaveLength(0);

    const daily = screen.getByRole("meter", { name: /Scans today/ });
    expect(daily).toHaveAttribute("aria-valuenow", "3");
    expect(daily).toHaveAttribute("aria-valuemin", "0");
    expect(daily).toHaveAttribute("aria-valuemax", "10");
    expect(daily).toHaveAttribute("aria-valuetext", "3 of 10 scans used");

    const concurrent = screen.getByRole("meter", { name: /Concurrent scans/ });
    expect(concurrent).toHaveAttribute("aria-valuenow", "1");
    expect(concurrent).toHaveAttribute("aria-valuemax", "2");
  });

  it("renders no meter against a limit it was not given", async () => {
    // The legacy bar drew 0% for a missing concurrency limit — a measurement
    // nobody took.
    getScanQuota.mockResolvedValue(ok({ concurrent_limit: null }));
    await renderBar();
    expect(screen.queryByRole("meter", { name: /Concurrent/ })).toBeNull();
    expect(
      screen.getByRole("meter", { name: /Scans today/ }),
    ).toBeInTheDocument();
  });

  it("keeps aria-valuenow inside the range when use exceeds the limit", async () => {
    getScanQuota.mockResolvedValue(
      ok({ scans_used_24h: 12, quota_exceeded: true }),
    );
    await renderBar();
    const daily = screen.getByRole("meter", { name: /Scans today/ });
    expect(daily).toHaveAttribute("aria-valuenow", "10");
    expect(daily).toHaveAttribute("aria-valuetext", "12 of 10 scans used");
  });

  it("says near-limit and limit-reached in words, not only in colour", async () => {
    getScanQuota.mockResolvedValue(
      ok({ scans_used_24h: 8, concurrent_running: 0 }),
    );
    await renderBar();
    expect(screen.getByText("Near limit")).toBeInTheDocument();
  });

  it("says limit reached in words at 100%", async () => {
    getScanQuota.mockResolvedValue(
      ok({ scans_used_24h: 10, concurrent_running: 0, quota_exceeded: true }),
    );
    await renderBar();
    expect(screen.getByText("Limit reached")).toBeInTheDocument();
  });

  it("carries no colour in inline styles — only the measured width", async () => {
    getScanQuota.mockResolvedValue(
      ok({ plan: "enterprise", scans_used_24h: 9, concurrent_exceeded: true }),
    );
    const { container } = await renderBar();
    for (const el of container.querySelectorAll("[style]")) {
      const props = [...Array(el.style.length).keys()].map((i) =>
        el.style.item(i),
      );
      expect(props, el.outerHTML).toEqual(["width"]);
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   Meter fill contrast — WCAG 1.4.11
   ══════════════════════════════════════════════════════════════════════════
   The fill is the graphic showing how much of the quota is used, so it must
   reach 3:1 against the track it sits on, in both themes. The tokens are read
   out of the stylesheet that ships, so a later edit to a fill is measured
   rather than assumed. Token parsing and resolution follow
   __tests__/design-system/contrast.test.js.

   The first version of scan-quota.css drew the 80–99% band in
   --ccure-warning-solid: #fa8c16 on #f5f5f5, 2.18:1 in the light theme. */

function tokenThemes() {
  const tokens = path.join(SRC, "design-system", "tokens");
  const declarations = (block) => {
    const out = {};
    for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+)/g)) {
      out[m[1]] = m[2].trim();
    }
    return out;
  };
  const ux4g = readFileSync(path.join(tokens, "ux4g.generated.css"), "utf8");
  const ccure = readFileSync(path.join(tokens, "ccure-tokens.css"), "utf8");
  let uLight = {};
  for (const m of ux4g.matchAll(/:root\{([\s\S]*?)\}/g)) {
    uLight = { ...uLight, ...declarations(m[1]) };
  }
  let uDark = {};
  for (const m of ux4g.matchAll(/:root\[data-theme=dark\]\{([\s\S]*?)\}/g)) {
    uDark = { ...uDark, ...declarations(m[1]) };
  }
  let cLight = {};
  for (const m of ccure.matchAll(/(?:^|\n):root\s*\{([\s\S]*?)\n\}/g)) {
    cLight = { ...cLight, ...declarations(m[1]) };
  }
  const darkBlock = ccure.match(
    /:root\[data-theme="dark"\]\s*\{([\s\S]*?)\n?\}/,
  );
  const cDark = darkBlock ? declarations(darkBlock[1]) : {};
  const light = { ...uLight, ...cLight };
  return { light, dark: { ...light, ...uDark, ...cDark } };
}

function resolveToken(name, theme, fallback, depth = 0) {
  if (depth > 12) return null;
  const raw = theme[name] ?? fallback[name];
  if (!raw) return null;
  const m = raw.match(/^var\(\s*(--[a-z0-9-]+)/);
  return m ? resolveToken(m[1], theme, fallback, depth + 1) : raw;
}

function contrastRatio(fg, bg) {
  const rgb = (value) => {
    const hex = value?.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
    if (!hex) return null;
    const h =
      hex[1].length === 3 ? [...hex[1]].map((c) => c + c).join("") : hex[1];
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  };
  const lum = ([r, g, b]) => {
    const f = (c) => {
      const s = c / 255;
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const a = rgb(fg);
  const b = rgb(bg);
  if (!a || !b) return null;
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe("ScanQuotaBar — layout against its host", () => {
  it("is exactly as wide as the NewScan card it sits above", () => {
    // Not a rem conversion. theme.css sets `html { font-size: 15px }`, so the
    // first version's 42.5rem rendered 637.5px above a 680px card — visibly
    // narrower and misaligned in the final rendered validation.
    const quotaCss = readFileSync(
      path.join(AUDIT_SRC, "styles", "scan-quota.css"),
      "utf8",
    );
    const newScanCss = readFileSync(
      path.join(AUDIT_SRC, "styles", "NewScan.css"),
      "utf8",
    );
    const card = newScanCss
      .match(/\.ns-card\s*\{[^}]*max-width:\s*([^;]+);/)?.[1]
      .trim();
    const quota = quotaCss
      .match(/\.sq\s*\{[^}]*max-width:\s*([^;]+);/)?.[1]
      .trim();
    expect(card, ".ns-card max-width not found").toBeTruthy();
    expect(quota).toBe(card);
  });
});

describe("ScanQuotaBar — meter fill contrast (WCAG 1.4.11)", () => {
  const css = readFileSync(
    path.join(AUDIT_SRC, "styles", "scan-quota.css"),
    "utf8",
  );
  const track = css.match(
    /\.sq__track\s*\{[^}]*background:\s*var\((--[a-z0-9-]+)\)/,
  )?.[1];
  const fills = [
    ...css.matchAll(
      /(?:\.sq__meter--([a-z]+)\s+)?\.sq__fill\s*\{[^}]*background:\s*var\((--[a-z0-9-]+)\)/g,
    ),
  ].map((m) => [m[1] || "success (default)", m[2]]);

  it("reads the track and every band's fill out of the stylesheet", () => {
    expect(track).toBeTruthy();
    expect(fills.map(([band]) => band).sort()).toEqual([
      "danger",
      "primary",
      "success (default)",
      "warning",
    ]);
  });

  for (const themeName of ["light", "dark"]) {
    it(`every fill reaches 3:1 against the track — ${themeName}`, () => {
      const themes = tokenThemes();
      const theme = themes[themeName];
      const bg = resolveToken(track, theme, themes.light);
      expect(bg, `${track} did not resolve to a colour`).toBeTruthy();
      for (const [band, token] of fills) {
        const fg = resolveToken(token, theme, themes.light);
        const ratio = contrastRatio(fg, bg);
        expect(ratio, `${band}: ${token} (${fg}) did not compute`).toBeTruthy();
        expect(
          Number(ratio.toFixed(2)),
          `${band} fill ${token} (${fg}) on ${track} (${bg}) = ${ratio.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(3);
      }
    });
  }
});
