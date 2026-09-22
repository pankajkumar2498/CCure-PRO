// @vitest-environment node
/**
 * What `exportScanDataset` actually puts on the wire.
 *
 * This runs in the node environment on purpose. The component test asserts
 * that `paramsSerializer: { indexes: null }` is passed, which is the right
 * check at that layer but proves nothing about the query string axios builds
 * from it. Here a real HTTP server receives a real axios request, so the
 * assertion is the URL itself.
 *
 * The stakes, measured against the live API on 22 Sep 2026 with a real scan:
 *
 *     /reports/export/{id}?fmt=json&dataset=findings&severity=critical
 *         -> 154 rows          (the filter applied)
 *     /reports/export/{id}?fmt=json&dataset=findings&severity[]=critical
 *         -> 1862 rows         (the filter silently ignored)
 *
 * FastAPI binds a `list[str]` Query from repeated bare names; the bracketed
 * form arrives as one parameter literally named `severity[]`, matches nothing
 * in the signature, and is dropped. The export then succeeds, downloads, and
 * contains everything — which is the worst failure shape available on this
 * path, because it looks exactly like a correct filtered export.
 *
 * Axios's *default* is the bracketed form, so this is not a hypothetical.
 */

import http from "node:http";
import { describe, it, expect, afterAll } from "vitest";
import axios from "axios";

const received = [];
const server = http.createServer((req, res) => {
  received.push(req.url);
  res.writeHead(200, { "content-type": "application/json" });
  res.end("{}");
});

const listening = new Promise((resolve) => server.listen(0, resolve));

afterAll(() => server.close());

async function capture(config) {
  await listening;
  const { port } = server.address();
  received.length = 0;
  await axios.get(`http://127.0.0.1:${port}/reports/export/scn_1`, config);
  return received[0];
}

describe("export query serialization", () => {
  it("emits repeated keys for a multi-value filter", async () => {
    const url = await capture({
      params: {
        fmt: "json",
        dataset: "findings",
        severity: ["critical", "high"],
      },
      paramsSerializer: { indexes: null },
    });

    expect(url).toContain("severity=critical");
    expect(url).toContain("severity=high");
    // The form the API ignores must not appear in any encoding.
    expect(url).not.toContain("severity%5B%5D");
    expect(url).not.toContain("severity[]");
  });

  it("axios's default would send the form the API ignores", async () => {
    /*
     * Not a test of axios so much as a record of why the option above is not
     * optional. If a future axios changes this default, this test fails and
     * the reason to keep the serializer is re-examined deliberately rather
     * than by someone deleting a line that looks redundant.
     */
    const url = await capture({
      params: { severity: ["critical", "high"] },
    });

    expect(url).toContain("severity%5B%5D=critical");
  });

  it("serialises a single-value filter as one repeated key too", async () => {
    const url = await capture({
      params: { severity: ["critical"] },
      paramsSerializer: { indexes: null },
    });

    expect(url).toContain("severity=critical");
    expect(url).not.toContain("severity%5B%5D");
  });
});
