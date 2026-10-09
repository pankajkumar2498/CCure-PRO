/**
 * How much of the collected software inventory the vulnerability matcher could
 * actually assess.
 *
 * `VulnMatcher.coverage()` reports two percentages deliberately, and the
 * backend's own rule is to keep reporting both: `coverage_pct` is over every
 * package collected, `coverage_pct_software` excludes toolchain components —
 * SDK headers, `vs_*` resource MSIs, IntelliSense metadata — which NVD
 * publishes no CPE for because none is independently vulnerable. On a real
 * Windows host 147 of 191 packages are such components, so the unfiltered
 * figure understates coverage as badly as counting them assessed would
 * overstate it.
 *
 * The labels here therefore explain what each number is *over*. A percentage
 * with no denominator is the thing that makes "10.5% coverage" read as a
 * broken scanner when it is the correct answer to a different question.
 *
 * Nothing is renamed and nothing is recomputed. Where the API gives a
 * percentage it is displayed; where it gives counts they are displayed beside
 * it, so the reader can see the fraction rather than trust the division.
 */

import { CcureAlert } from "../../../../design-system";

/** label, key, and what the number is measured over. */
const PERCENTAGES = [
  {
    key: "coverage_pct",
    label: "Coverage — all packages",
    hint: "Assessed as a share of every package collected, toolchain components included.",
  },
  {
    key: "coverage_pct_software",
    label: "Coverage — software only",
    hint: "Excludes toolchain components, which have no CPE because none is independently vulnerable.",
  },
  {
    key: "coverage_pct_assessed",
    label: "Coverage — assessable set",
    hint: "Assessed as a share of the packages that could be assessed at all.",
  },
];

const COUNTS = [
  {
    key: "packages_collected",
    label: "Packages collected",
    hint: "Everything the credentialed session enumerated on the host.",
  },
  {
    key: "packages_assessable",
    label: "Assessable",
    hint: "Packages a vulnerability source could be matched against.",
  },
  {
    key: "packages_assessable_software",
    label: "Assessable (software only)",
    hint: "The same, with toolchain components removed.",
  },
  {
    key: "packages_cpe_resolved",
    label: "CPE resolved",
    hint: "Packages resolved to a CPE identity in the catalogue.",
  },
  {
    key: "packages_assessed_total",
    label: "Assessed",
    hint: "Packages actually compared against vulnerability data.",
  },
  {
    key: "packages_toolchain_components",
    label: "Toolchain components",
    hint: "SDK headers, resource MSIs and IntelliSense metadata — excluded from the software figure.",
  },
];

function pct(value) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

export default function PackageCoverageSection({ coverage }) {
  // Absent is not zero. A scan that never enumerated software has no coverage
  // figure at all, and rendering 0% would assert that nothing matched.
  if (!coverage || Object.keys(coverage).length === 0) {
    return (
      <CcureAlert
        variant="info"
        live={false}
        title="Package coverage — not reported"
      >
        This scan did not report package-coverage figures. That is not a
        coverage of zero; it means the matcher did not record how much of the
        inventory it could assess.
      </CcureAlert>
    );
  }

  return (
    <div className="pc-root">
      <p className="pc-note">
        Coverage bounds every vulnerability conclusion drawn from the software
        inventory. A package the matcher could not assess cannot produce a
        finding, so a low figure means &quot;less was checked&quot;, not
        &quot;less was wrong&quot;.
      </p>

      <dl className="pc-metrics">
        {PERCENTAGES.map(({ key, label, hint }) => {
          const value = pct(coverage[key]);
          return (
            <div key={key} className="pc-metric pc-metric--pct">
              <dt className="pc-metric__label">{label}</dt>
              <dd className="pc-metric__value">
                {value === null ? "—" : `${value.toFixed(1)}%`}
              </dd>
              <p className="pc-metric__hint">{hint}</p>
            </div>
          );
        })}
      </dl>

      <dl className="pc-metrics pc-metrics--counts">
        {COUNTS.map(({ key, label, hint }) => (
          <div key={key} className="pc-metric">
            <dt className="pc-metric__label">{label}</dt>
            <dd className="pc-metric__value">
              {coverage[key] === null || coverage[key] === undefined
                ? "—"
                : Number(coverage[key]).toLocaleString()}
            </dd>
            <p className="pc-metric__hint">{hint}</p>
          </div>
        ))}
      </dl>

      <p className="pc-source">
        Advisory source:{" "}
        <strong>{coverage.advisory_source || "not recorded"}</strong>
      </p>
    </div>
  );
}
