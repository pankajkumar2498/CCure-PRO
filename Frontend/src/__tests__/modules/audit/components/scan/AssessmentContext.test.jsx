/**
 * P2 — assessment fidelity.
 *
 * The UI must represent what the scanner assessed, not what it would be
 * convenient to assume. Every fixture below is a live payload fragment.
 *
 *     UNKNOWN ≠ ZERO
 *     UNASSESSED ≠ PASS
 *     NOT CONFIGURED ≠ FALSE
 *     TCP ≠ UDP
 *     detected ≠ merely inferred
 *     absent field ≠ negative result
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import {
  HostMeasurements,
  OsIdentification,
  PortLabel,
  PortStates,
  ScanContext,
  TcpFingerprint,
} from "@audit/components/scan/AssessmentContext";

/* Live `phase2.data[0].port_states`. Note `5353/udp` carries its transport in
   the key while the others do not. */
const PORT_STATES = {
  53: "closed",
  67: "closed",
  123: "open|filtered",
  161: "closed",
  500: "open|filtered",
  1900: "open|filtered",
  "5353/udp": "open",
};

/* Live `phase1.summary`. */
const P1_SUMMARY = {
  scanner: "Built-in host discovery (AGGRESSIVE profile)",
  scan_type: "ADAPTIVE",
  discovery_profile: "AGGRESSIVE",
  discovery_scan_method: "ADAPTIVE",
  os_detection: "Passive inference from discovery responses",
  service_detection: "Not performed",
  timing_template: "AGGRESSIVE discovery profile",
  port_range: "Not scanned — host discovery policy does not scan ports",
};

describe("port states", () => {
  it("renders every state the probe reached, not only the open ones", () => {
    const { container } = render(<PortStates portStates={PORT_STATES} />);
    expect(screen.getByText(/Port states \(7\)/)).toBeInTheDocument();
    /* Counted on the badges themselves: the explanatory note beside the list
       names the states in prose too, and a document-wide text match would
       count that sentence as a reading. */
    const states = [...container.querySelectorAll(".asc-state .cc-badge")].map(
      (el) => el.textContent,
    );
    expect(states.filter((s) => s === "closed").length).toBe(3);
    expect(states.filter((s) => s === "open|filtered").length).toBe(3);
    expect(states.filter((s) => s === "open").length).toBe(1);
  });

  it("keeps open|filtered as its own state, not as closed", () => {
    // The probe could not tell which. Rendering it as closed asserts what the
    // scanner declined to.
    render(<PortStates portStates={PORT_STATES} />);
    const undetermined = screen.getAllByText("open|filtered");
    expect(undetermined.length).toBeGreaterThan(0);
    for (const el of undetermined) {
      expect(el.textContent).not.toBe("closed");
    }
    // And it is toned as undetermined rather than borrowing either verdict.
    expect(undetermined[0].className).not.toMatch(/--(success|danger)\b/);
  });

  it("keeps the transport the key carried and adds none where it did not", () => {
    render(<PortStates portStates={PORT_STATES} />);
    expect(screen.getByText("5353/udp")).toBeInTheDocument();
    // 53 has no transport in the payload, so none is printed.
    expect(screen.getByText("53")).toBeInTheDocument();
    expect(screen.queryByText("53/tcp")).toBeNull();
  });

  it("renders nothing rather than an empty shell when there are no states", () => {
    const { container } = render(<PortStates portStates={{}} />);
    expect(container).toBeEmptyDOMElement();
    const { container: c2 } = render(<PortStates portStates={undefined} />);
    expect(c2).toBeEmptyDOMElement();
  });
});

describe("OS identification", () => {
  /* The live host: a guess, a word for its confidence, and no identified OS. */
  const HOST = {
    os_name: null,
    os_guess: "Windows (NT/2000/XP/7/8/10/11)",
    os_confidence: "Medium",
    confidence: "High",
    device_category: "endpoint",
    os_evidence: null,
    os_fingerprint_full: {},
  };

  it("does not present a guess as an identification", () => {
    render(<OsIdentification host={HOST} />);
    expect(screen.getByText("not identified")).toBeInTheDocument();
    expect(screen.getByText(HOST.os_guess)).toBeInTheDocument();
    expect(screen.getByText("guess")).toBeInTheDocument();
  });

  it("shows the confidence as the word the scanner used", () => {
    render(<OsIdentification host={HOST} />);
    // A word, not a number — so it is never turned into a percentage.
    expect(screen.getByText("Medium")).toBeInTheDocument();
    expect(screen.queryByText("0%")).toBeNull();
  });

  it("keeps OS confidence and discovery confidence apart", () => {
    render(<OsIdentification host={HOST} />);
    expect(screen.getByText("OS confidence")).toBeInTheDocument();
    expect(screen.getByText("Discovery confidence")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("says a missing confidence is not reported, never 0", () => {
    render(<OsIdentification host={{ ...HOST, os_confidence: undefined }} />);
    expect(screen.getAllByText("not reported").length).toBeGreaterThan(0);
    expect(screen.queryByText("0")).toBeNull();
    expect(screen.queryByText("0%")).toBeNull();
  });

  it("shows an identified OS as identified", () => {
    render(
      <OsIdentification
        host={{ ...HOST, os_name: "Microsoft Windows 11 Pro" }}
      />,
    );
    expect(screen.getByText("Microsoft Windows 11 Pro")).toBeInTheDocument();
    expect(screen.queryByText("not identified")).toBeNull();
  });

  it("offers the evidence when the payload carries it", () => {
    render(
      <OsIdentification
        host={{
          ...HOST,
          os_evidence: "ttl=128 window=65535",
          os_fingerprint_full: { os: "Windows", accuracy: 92 },
        }}
      />,
    );
    expect(screen.getByText("Evidence")).toBeInTheDocument();
    expect(screen.getByText(/ttl=128/)).toBeInTheDocument();
    expect(screen.getByText("Full fingerprint")).toBeInTheDocument();
  });

  it("shows no evidence block when the payload has none", () => {
    // `os_evidence: null` and `os_fingerprint_full: {}` on the live host.
    render(<OsIdentification host={HOST} />);
    expect(screen.queryByText("Evidence")).toBeNull();
    expect(screen.queryByText("Full fingerprint")).toBeNull();
  });

  it("renders nothing for a host with no OS information at all", () => {
    const { container } = render(<OsIdentification host={{ ip: "1.2.3.4" }} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("host measurements", () => {
  it("renders the measured response time without rounding it away", () => {
    // The live host answers in 0.1857 ms. A naive round prints "0 ms".
    render(
      <HostMeasurements
        host={{ response_time_ms: 0.1857280731201172, host_risk_level: "Info" }}
      />,
    );
    expect(screen.getByText("0.19 ms")).toBeInTheDocument();
    expect(screen.queryByText("0 ms")).toBeNull();
  });

  it("renders the backend's own risk level rather than deriving one", () => {
    render(<HostMeasurements host={{ host_risk_level: "Critical" }} />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("says not reported for a null response time, never 0 ms", () => {
    render(<HostMeasurements host={{ response_time_ms: null }} />);
    expect(screen.getByText("not reported")).toBeInTheDocument();
    expect(screen.queryByText("0.00 ms")).toBeNull();
  });

  it("renders a genuine zero when the scan measured one", () => {
    render(<HostMeasurements host={{ response_time_ms: 0 }} />);
    expect(screen.getByText("0.00 ms")).toBeInTheDocument();
  });
});

describe("tcp fingerprint", () => {
  it("renders the stack readings the payload carried", () => {
    render(
      <TcpFingerprint
        fingerprint={{ ttl: 128, window: 65535, df_bit: true, sack_ok: true }}
      />,
    );
    expect(screen.getByText("128")).toBeInTheDocument();
    expect(screen.getByText("65535")).toBeInTheDocument();
    expect(screen.getAllByText("true").length).toBe(2);
  });

  it("renders nothing when the payload carried none", () => {
    const { container } = render(<TcpFingerprint fingerprint={{}} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("scan context", () => {
  it("renders the scan parameters verbatim", () => {
    render(<ScanContext summary={P1_SUMMARY} />);
    expect(
      screen.getByText("Built-in host discovery (AGGRESSIVE profile)"),
    ).toBeInTheDocument();
    // The sentence is the value. A shorter label would claim more than the
    // field does — here, that ports were scanned and none was open.
    expect(
      screen.getByText(
        "Not scanned — host discovery policy does not scan ports",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Not performed")).toBeInTheDocument();
  });

  it("omits a parameter the summary did not carry", () => {
    render(<ScanContext summary={{ scanner: "Nmap 7.95" }} />);
    expect(screen.getByText("Nmap 7.95")).toBeInTheDocument();
    expect(screen.queryByText("Ports probed")).toBeNull();
    expect(screen.queryByText("Timing")).toBeNull();
  });

  it("renders nothing for an empty summary", () => {
    const { container } = render(<ScanContext summary={{}} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("port transport — TCP is not UDP and neither is a default", () => {
  it("keeps a TCP port TCP", () => {
    render(<PortLabel row={{ port: 22, protocol: "tcp" }} />);
    expect(screen.getByText("22/tcp")).toBeInTheDocument();
  });

  it("keeps a UDP port UDP, and never prints it as TCP", () => {
    // The cell used to be the template literal `${port.port}/tcp`, so this
    // row printed "161/tcp" — a claim of an open TCP port that is usually
    // filtered, which reaches the asset registry and the reports.
    render(<PortLabel row={{ port: 161, protocol: "udp" }} />);
    expect(screen.getByText("161/udp")).toBeInTheDocument();
    expect(screen.queryByText("161/tcp")).toBeNull();
  });

  it("does not infer TCP when the payload reports no protocol", () => {
    render(<PortLabel row={{ port: 8080 }} />);
    expect(screen.getByText("8080/?")).toBeInTheDocument();
    expect(screen.queryByText("8080/tcp")).toBeNull();
  });

  it("does not infer TCP from an empty protocol either", () => {
    render(<PortLabel row={{ port: 8080, protocol: "" }} />);
    expect(screen.getByText("8080/?")).toBeInTheDocument();
  });

  it("says in words why the transport is unknown", () => {
    render(<PortLabel row={{ port: 8080 }} />);
    expect(screen.getByText("8080/?")).toHaveAttribute(
      "title",
      expect.stringMatching(/not being assumed to be TCP/i),
    );
  });

  it("uses a table's own transport only where the row carries none", () => {
    // The UDP table may say udp; a row that states its own still wins.
    render(<PortLabel row={{ port: 5353 }} fallbackProtocol="udp" />);
    expect(screen.getByText("5353/udp")).toBeInTheDocument();
  });

  it("believes the row over the table it sits in", () => {
    render(
      <PortLabel row={{ port: 53, protocol: "tcp" }} fallbackProtocol="udp" />,
    );
    expect(screen.getByText("53/tcp")).toBeInTheDocument();
  });

  it("normalises the case the scanner used without changing the value", () => {
    render(<PortLabel row={{ port: 161, protocol: "UDP" }} />);
    expect(screen.getByText("161/udp")).toBeInTheDocument();
  });
});
