/**
 * pages/scan/ConfigurationRuleValidator.jsx
 * ───────────────────────────────────────────────────────────────────────────
 * `POST /config-audit/validate` — is this rule definition executable, and
 * would *this build* be able to run it?
 *
 * It lives on its own page rather than on the Configuration Checks catalogue,
 * and that is deliberate. That page's contract is **read-only, no mutation
 * ever**, pinned by a test that drives every control on it and asserts no POST
 * was issued — the guard that stops a "run a scan" button being added during a
 * migration. `/validate` writes nothing and contacts no target, so it is not a
 * mutation in substance; but weakening a negative assertion that exists for
 * that reason is a worse trade than a second page. The catalogue links here.
 *
 * Three properties of the endpoint the form must not misrepresent:
 *
 * * **`valid: false` arrives as HTTP 200 and is an answer, not a failure.**
 *   The caller asked whether the rule is valid and the errors are the answer.
 *   Rendering it through the error path would tell an author their request was
 *   broken when it was their rule that was.
 *
 * * **A warning is not an error.** A rule whose `check_type` has no collector
 *   on the named platform is still `valid: true` — it is well-formed and will
 *   be executable when that phase lands. Authoring content ahead of a
 *   collector is legitimate, so the warning says what would happen (the check
 *   reports an error rather than a verdict) without refusing the rule.
 *
 * * **The vocabulary is fetched.** Check types, platforms, operators and
 *   absence policies all come from `/capabilities`. A form with its own copy
 *   offers an operator the engine removed and omits one it gained.
 *
 * `collect` is free-form JSON because it is: its shape is decided by the
 * check type, and the backend is the thing that knows. It is parsed here only
 * far enough to avoid sending something that cannot be JSON at all, and the
 * parse error is reported as a parse error rather than as a validation
 * verdict.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import {
  CcureAlert,
  CcureButton,
  CcureInput,
  CcureSelect,
} from "../../../../design-system";
import {
  configAuditErrorMessage,
  getConfigCapabilities,
  validateConfigRule,
} from "@audit/api/configAudit";
import "../../styles/configuration-checks.css";

const SEVERITIES = ["critical", "high", "medium", "low", "none", "unscored"];

/** A worked example, so the first thing a reader sees is a rule that passes. */
const EXAMPLE = {
  check_id: "example.win.uac.enabled",
  title: "User Account Control is enabled",
  check_type: "registry",
  platform: "windows",
  collect: JSON.stringify(
    {
      hive: "HKLM",
      key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      value: "EnableLUA",
    },
    null,
    2,
  ),
  operator: "equals",
  expected: "1",
  absent: "manual_review",
  severity: "high",
  domain: "host_configuration",
};

/**
 * `expected` is typed as `Any` by the API, so a number has to reach it as a
 * number: `equals 1` and `equals "1"` are different comparisons, and the
 * registry collector returns a string only on some paths. JSON is tried first
 * and the raw text is the fallback, which is what a regular expression or a
 * bare word needs.
 */
const parseExpected = (raw) => {
  const text = String(raw ?? "").trim();
  if (text === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

export default function ConfigurationRuleValidator() {
  const [caps, setCaps] = useState(null);
  const [capsError, setCapsError] = useState("");
  const [form, setForm] = useState(EXAMPLE);
  const [collectError, setCollectError] = useState("");
  const [result, setResult] = useState(null);
  const [failure, setFailure] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getConfigCapabilities()
      .then(setCaps)
      .catch((err) =>
        setCapsError(
          configAuditErrorMessage(
            err,
            "Could not read this build's check vocabulary.",
          ),
        ),
      );
  }, []);

  const set = useCallback(
    (key) => (event) => setForm((f) => ({ ...f, [key]: event.target.value })),
    [],
  );

  /* Named so the reader can see, before submitting, that the platform they
     chose has no collector for the check type they chose — which is the thing
     the backend answers with a warning. */
  const localGap = useMemo(() => {
    const supported = caps?.supported?.[form.platform];
    if (!Array.isArray(supported)) return null;
    return supported.includes(form.check_type) ? null : form.check_type;
  }, [caps, form.platform, form.check_type]);

  const submit = async () => {
    setCollectError("");
    setFailure("");
    setResult(null);

    let collect;
    try {
      collect = JSON.parse(form.collect || "{}");
    } catch (err) {
      // A parse failure here is not a verdict about the rule, and must not be
      // rendered as one.
      setCollectError(`collect is not valid JSON: ${err.message}`);
      return;
    }
    if (
      collect === null ||
      typeof collect !== "object" ||
      Array.isArray(collect)
    ) {
      setCollectError("collect must be a JSON object.");
      return;
    }

    setBusy(true);
    try {
      const data = await validateConfigRule({
        check_id: form.check_id,
        title: form.title,
        check_type: form.check_type,
        platforms: [form.platform],
        collect,
        operator: form.operator,
        expected: parseExpected(form.expected),
        absent: form.absent,
        severity: form.severity,
        domain: form.domain,
      });
      setResult(data);
    } catch (err) {
      // Reserved for a genuine transport or authorisation failure. A rule that
      // does not validate arrives as a 200 and is handled above.
      setFailure(
        configAuditErrorMessage(err, "The validator could not be reached."),
      );
    } finally {
      setBusy(false);
    }
  };

  const options = {
    check_type: caps?.check_types || [],
    platform: caps ? Object.keys(caps.supported || {}) : [],
    operator: caps?.operators || [],
    absent: caps?.absence_policies || [],
  };

  return (
    <AppLayout>
      <div className="page-inner cfg-page">
        <h1 className="page-title">Rule validator</h1>

        <p className="page-subtitle cfg-lede">
          Check that a configuration rule definition is well-formed and that
          this build can execute it, without contacting any host. Nothing is
          saved: rules are authored through the seeders, and this answers the
          question a seed file cannot — whether the check type you named has a
          collector here.{" "}
          <Link to="/configuration-checks">Back to the catalogue</Link>.
        </p>

        {capsError ? (
          <CcureAlert variant="danger" className="cfg-error">
            {capsError} The vocabulary below cannot be offered without it.
          </CcureAlert>
        ) : null}

        <div className="cfg-form">
          <CcureInput
            label="Check id"
            value={form.check_id}
            onChange={set("check_id")}
            maxLength={120}
          />
          <CcureInput
            label="Title"
            value={form.title}
            onChange={set("title")}
            maxLength={255}
          />
          <CcureSelect
            label="Check type"
            value={form.check_type}
            onChange={set("check_type")}
          >
            {options.check_type.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </CcureSelect>
          <CcureSelect
            label="Platform"
            value={form.platform}
            onChange={set("platform")}
          >
            {options.platform.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </CcureSelect>
          <CcureSelect
            label="Operator"
            value={form.operator}
            onChange={set("operator")}
          >
            {options.operator.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </CcureSelect>
          <CcureSelect
            label="If the item is absent"
            value={form.absent}
            onChange={set("absent")}
            hint="Absence has no default: it is a pass for one rule and a failure for another."
          >
            {options.absent.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </CcureSelect>
          <CcureSelect
            label="Severity"
            value={form.severity}
            onChange={set("severity")}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </CcureSelect>
          <CcureInput
            label="Domain"
            value={form.domain}
            onChange={set("domain")}
          />
          <CcureInput
            label="Expected"
            value={form.expected}
            onChange={set("expected")}
            hint='Read as JSON where it parses, so 1 is a number and "1" is a string; anything else is taken as text.'
          />
        </div>

        <label className="cfg-collect">
          <span className="cfg-collect__label">
            What to collect (JSON, shape decided by the check type)
          </span>
          <textarea
            className="cfg-collect__area"
            rows={8}
            spellCheck={false}
            value={form.collect}
            onChange={set("collect")}
          />
        </label>

        {collectError ? (
          <CcureAlert variant="danger">{collectError}</CcureAlert>
        ) : null}

        {localGap ? (
          <CcureAlert variant="warning">
            This build has no collector for <strong>{localGap}</strong> on{" "}
            <strong>{form.platform}</strong>. The rule can still be valid — the
            validator will say so — but a scan would report it as an error
            rather than as a verdict.
          </CcureAlert>
        ) : null}

        <div className="cfg-form__actions">
          <CcureButton variant="primary" disabled={busy} onClick={submit}>
            Validate
          </CcureButton>
        </div>

        {failure ? <CcureAlert variant="danger">{failure}</CcureAlert> : null}

        {result ? (
          <div className="cfg-result">
            <CcureAlert variant={result.valid ? "success" : "danger"}>
              {result.valid
                ? "This rule is well-formed and the engine can build it."
                : "This rule is not executable as written."}
            </CcureAlert>

            {result.errors?.length > 0 ? (
              <>
                <h2 className="cfg-result__h">Errors</h2>
                <ul className="cfg-result__list">
                  {result.errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              </>
            ) : null}

            {result.warnings?.length > 0 ? (
              <>
                <h2 className="cfg-result__h">Warnings</h2>
                {/* Deliberately below the verdict and not folded into it: a
                    warning leaves the rule valid, and treating it as a refusal
                    would block writing content ahead of its collector. */}
                <ul className="cfg-result__list">
                  {result.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </>
            ) : null}

            {result.check_definition ? (
              <>
                <h2 className="cfg-result__h">
                  The definition this rule would store
                </h2>
                <pre className="cfg-result__json">
                  {JSON.stringify(result.check_definition, null, 2)}
                </pre>
              </>
            ) : null}
          </div>
        ) : null}
      </div>
    </AppLayout>
  );
}
