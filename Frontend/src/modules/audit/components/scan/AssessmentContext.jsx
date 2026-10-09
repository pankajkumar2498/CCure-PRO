/**
 * What a discovery phase actually did, and what it actually saw.
 *
 * Three groups of fields the phase pages dropped, all of them present on every
 * payload they already fetched:
 *
 * * **Port states** — the per-port answer, which is not two-valued. A live
 *   payload carries `closed`, `open` and `open|filtered` together, and the
 *   pages rendered only the open list. `open|filtered` means the probe could
 *   not tell, and dropping it turns an undetermined port into an absent one:
 *   `UNKNOWN ≠ ZERO`.
 *
 * * **The TCP fingerprint** — the evidence an OS inference rests on. Shown so
 *   a reader can weigh the guess rather than take it.
 *
 * * **The scan parameters** — scanner, profile, port range, timing template,
 *   service detection. A reader cannot tell a clean host from an unscanned one
 *   without them, and they were on the summary all along.
 *
 * Nothing here is derived. A field the payload does not carry is stated as not
 * reported, never defaulted.
 */

import { CcureBadge } from "../../../../design-system";

/** Present, as opposed to falsy. `0` and `false` are readings. */
const has = (v) => v !== null && v !== undefined && v !== "";

const NOT_REPORTED = <span className="asc-muted">not reported</span>;

/**
 * A port state's tone. `open|filtered` is deliberately its own: the probe did
 * not establish which, and colouring it as either would assert what the
 * scanner declined to.
 */
const STATE_TONE = {
  open: "danger",
  closed: "neutral",
  filtered: "warning",
  "open|filtered": "warning",
  "closed|filtered": "warning",
  unfiltered: "info",
};

const Fact = ({ label, children }) => (
  <div className="asc-fact">
    <dt>{label}</dt>
    <dd>{has(children) ? children : NOT_REPORTED}</dd>
  </div>
);

/**
 * Every port the probe reached a state for, including the ones it could not
 * resolve.
 *
 * The key carries the transport where the scanner recorded one — a live
 * payload has `"5353/udp"` beside bare `"53"` — so it is split rather than
 * assumed, for the same reason the ports table no longer prints `/tcp`.
 */
export function PortStates({ portStates }) {
  if (!portStates || typeof portStates !== "object") return null;
  const rows = Object.entries(portStates);
  if (!rows.length) return null;

  const parse = (key) => {
    const [port, proto] = String(key).split("/");
    return { port, proto: proto ? proto.toLowerCase() : null };
  };

  return (
    <div className="asc-block">
      <h4 className="asc-h">Port states ({rows.length})</h4>
      <p className="asc-note">
        The state the probe reached for each port it tried.{" "}
        <strong>open|filtered</strong> means the probe could not tell which — it
        is not a closed port.
      </p>
      <ul className="asc-states">
        {rows.map(([key, state]) => {
          const { port, proto } = parse(key);
          return (
            <li key={key} className="asc-state">
              <code>
                {port}
                {proto ? `/${proto}` : ""}
              </code>
              <CcureBadge variant={STATE_TONE[state] || "neutral"}>
                {String(state)}
              </CcureBadge>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** The raw TCP/IP stack readings behind an OS inference. */
export function TcpFingerprint({ fingerprint }) {
  if (!fingerprint || typeof fingerprint !== "object") return null;
  const rows = Object.entries(fingerprint).filter(([, v]) => has(v));
  if (!rows.length) return null;
  return (
    <div className="asc-block">
      <h4 className="asc-h">TCP fingerprint</h4>
      <p className="asc-note">
        The stack readings an OS inference rests on. They are evidence, not a
        verdict.
      </p>
      <dl className="asc-facts">
        {rows.map(([key, value]) => (
          <Fact key={key} label={key.replace(/_/g, " ")}>
            {typeof value === "boolean" ? String(value) : value}
          </Fact>
        ))}
      </dl>
    </div>
  );
}

/**
 * The scan's own parameters, in the backend's words.
 *
 * Every label below is the field's own name and every value is printed as the
 * API sent it — these are long sentences on purpose ("Not scanned — host
 * discovery policy does not scan ports") and shortening them would change what
 * they claim.
 */
const SUMMARY_FIELDS = [
  ["scanner", "Scanner"],
  ["scan_type", "Scan type"],
  ["discovery_profile", "Discovery profile"],
  ["discovery_scan_method", "Discovery method"],
  ["os_detection", "OS detection"],
  ["service_detection", "Service detection"],
  ["timing_template", "Timing"],
  ["port_range", "Port range"],
  ["ports_probed_spec", "Ports probed"],
];

export function ScanContext({ summary, title = "What this scan did" }) {
  if (!summary || typeof summary !== "object") return null;
  const rows = SUMMARY_FIELDS.filter(([key]) => has(summary[key]));
  if (!rows.length) return null;
  return (
    <div className="asc-block">
      <h4 className="asc-h">{title}</h4>
      <dl className="asc-facts asc-facts--wide">
        {rows.map(([key, label]) => (
          <Fact key={key} label={label}>
            {/* Verbatim. These are the scanner's own sentences and a shorter
                label would claim more than the field does. */}
            <span className={key === "ports_probed_spec" ? "asc-spec" : ""}>
              {String(summary[key])}
            </span>
          </Fact>
        ))}
      </dl>
    </div>
  );
}

/**
 * Per-host measurements the discovery phases record and neither page showed.
 *
 * `response_time_ms` is a measurement and a small one is meaningful — the live
 * host answers in 0.19 ms — so it is never rounded into "0 ms", and an absent
 * one is stated rather than printed as zero.
 */
export function HostMeasurements({ host }) {
  if (!host) return null;
  const rows = [];
  if (has(host.host_risk_level)) {
    rows.push(
      <Fact key="risk" label="Host risk level">
        {/* The backend's own level. Not derived from any score shown here. */}
        {host.host_risk_level}
      </Fact>,
    );
  }
  if (typeof host.response_time_ms === "number") {
    rows.push(
      <Fact key="rtt" label="Response time">
        {`${host.response_time_ms.toFixed(2)} ms`}
      </Fact>,
    );
  } else if ("response_time_ms" in host) {
    rows.push(
      <Fact key="rtt" label="Response time">
        {null}
      </Fact>,
    );
  }
  if (has(host.scan_method)) {
    rows.push(
      <Fact key="method" label="Discovered by">
        {host.scan_method}
      </Fact>,
    );
  }
  if (has(host.scan_timestamp)) {
    rows.push(
      <Fact key="ts" label="Seen at">
        {new Date(host.scan_timestamp).toLocaleString()}
      </Fact>,
    );
  }
  if (!rows.length) return null;
  return (
    <div className="asc-block">
      <h4 className="asc-h">Measurements</h4>
      <dl className="asc-facts">{rows}</dl>
    </div>
  );
}

/**
 * What the scanner believes this host runs, and how strongly.
 *
 * The live payload distinguishes four things the pages collapsed into one:
 * `os_name` (identified), `os_guess` (inferred), `os_confidence` (the strength
 * of the guess) and `confidence` (the strength of the *discovery*). A host can
 * carry a guess and no identified OS — the live one does — and presenting the
 * guess as the OS is the inference this component exists to refuse.
 *
 * `os_confidence` arrives as a word on the discovery phases and as a number on
 * the credentialed report, so both are rendered as they came. A missing one is
 * never 0%.
 */
export function OsIdentification({ host }) {
  if (!host) return null;
  const identified = host.os_name || host.os;
  const guess = host.os_guess;
  const evidence = host.os_evidence;
  const full = host.os_fingerprint_full;

  if (
    !identified &&
    !guess &&
    !has(host.os_confidence) &&
    !has(host.confidence)
  )
    return null;

  return (
    <div className="asc-block">
      <h4 className="asc-h">Operating system</h4>
      <dl className="asc-facts">
        <Fact label="Identified">
          {identified ? (
            identified
          ) : (
            <span className="asc-muted">
              {/* Not the guess. An inference presented as an identification is
                  the whole defect. */}
              not identified
            </span>
          )}
        </Fact>
        <Fact label="Inferred">
          {guess ? (
            <>
              {guess}{" "}
              <CcureBadge
                variant="info"
                title="An inference, not a confirmed identification."
              >
                guess
              </CcureBadge>
            </>
          ) : null}
        </Fact>
        <Fact label="OS confidence">
          {has(host.os_confidence) ? String(host.os_confidence) : null}
        </Fact>
        <Fact label="Discovery confidence">
          {has(host.confidence) ? String(host.confidence) : null}
        </Fact>
        <Fact label="Device category">{host.device_category}</Fact>
        <Fact label="SNMP device type">{host.snmp_device_type}</Fact>
      </dl>

      {has(evidence) ? (
        <>
          <h5 className="asc-h asc-h--sub">Evidence</h5>
          <pre className="asc-raw">
            {typeof evidence === "string"
              ? evidence
              : JSON.stringify(evidence, null, 2)}
          </pre>
        </>
      ) : null}

      {full && typeof full === "object" && Object.keys(full).length > 0 ? (
        <>
          <h5 className="asc-h asc-h--sub">Full fingerprint</h5>
          <pre className="asc-raw">{JSON.stringify(full, null, 2)}</pre>
        </>
      ) : null}
    </div>
  );
}

/**
 * A port's transport, from the scanner rather than from a habit.
 *
 * The ports table used to render `${port.port}/tcp` as a template literal, so
 * a UDP service in `open_ports` printed as TCP. CLAUDE.md records the same
 * mistake one layer down — recording a UDP probe as TCP "claims an open TCP
 * port that is usually filtered, and that claim reaches the asset registry and
 * the reports" — and this was the display half of it.
 *
 * A port whose protocol the payload does not carry renders `?`, never `tcp`.
 * "We were not told" and "it is TCP" are different statements. A table that
 * knows its own transport may pass one as `fallbackProtocol`, and a row that
 * carries its own still wins.
 */
export const PROTOCOL_UNKNOWN = "?";

export const protocolOf = (row) => {
  const raw = row?.protocol;
  if (raw === null || raw === undefined || raw === "") return null;
  return String(raw).toLowerCase();
};

export const PortLabel = ({ row, fallbackProtocol = null }) => {
  const protocol = protocolOf(row) || fallbackProtocol;
  if (!protocol) {
    return (
      <span title="The scan did not report a transport for this port. It is not being assumed to be TCP.">
        {row.port}/{PROTOCOL_UNKNOWN}
      </span>
    );
  }
  return (
    <span>
      {row.port}/{protocol}
    </span>
  );
};
