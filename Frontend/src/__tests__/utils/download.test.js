/**
 * Saving an authenticated response as a file.
 *
 * The two behaviours worth pinning are the ones the eight hand-rolled copies
 * of this logic in the app get wrong or omit: honouring the server's filename,
 * and releasing the object URL.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  filenameFromDisposition,
  saveBlob,
  saveResponseAsFile,
} from "../../utils/download";

beforeEach(() => {
  global.URL.createObjectURL = vi.fn(() => "blob:mock");
  global.URL.revokeObjectURL = vi.fn();
});

describe("filenameFromDisposition", () => {
  it("reads the plain form the API sends", () => {
    expect(
      filenameFromDisposition(
        'attachment; filename="scan_84_scn_defa_c52_findings.xlsx"',
      ),
    ).toBe("scan_84_scn_defa_c52_findings.xlsx");
  });

  it("prefers the RFC 5987 form, which survives a non-ASCII name", () => {
    expect(
      filenameFromDisposition(
        "attachment; filename=\"fallback.csv\"; filename*=UTF-8''r%C3%A9sultats.csv",
      ),
    ).toBe("résultats.csv");
  });

  it("falls back rather than losing the download on a bad escape", () => {
    expect(
      filenameFromDisposition(
        "attachment; filename=\"good.csv\"; filename*=UTF-8''bad%ZZname.csv",
      ),
    ).toBe("good.csv");
  });

  it("returns null when the header is absent", () => {
    expect(filenameFromDisposition(undefined)).toBeNull();
    expect(filenameFromDisposition("")).toBeNull();
  });
});

describe("saveBlob", () => {
  it("revokes the object URL", () => {
    // A workbook is hundreds of kilobytes and a Blob URL pins its data until
    // revoked; leaking one per export is a real cost in a long session.
    saveBlob(new Blob(["x"]), "a.txt");
    expect(global.URL.revokeObjectURL).toHaveBeenCalledWith("blob:mock");
  });

  it("revokes even when the click throws", () => {
    const original = document.body.appendChild.bind(document.body);
    document.body.appendChild = () => {
      throw new Error("detached");
    };
    try {
      expect(() => saveBlob(new Blob(["x"]), "a.txt")).toThrow();
      expect(global.URL.revokeObjectURL).toHaveBeenCalled();
    } finally {
      document.body.appendChild = original;
    }
  });
});

describe("saveResponseAsFile", () => {
  it("uses the server's filename over the caller's guess", () => {
    const anchors = [];
    const create = document.createElement.bind(document);
    vi.spyOn(document, "createElement").mockImplementation((tag) => {
      const el = create(tag);
      if (tag === "a") anchors.push(el);
      return el;
    });

    saveResponseAsFile(
      {
        data: new Blob(["x"]),
        headers: {
          "content-type": "text/csv",
          "content-disposition": 'attachment; filename="server_named.csv"',
        },
      },
      "client_guess.csv",
    );

    expect(anchors[0].download).toBe("server_named.csv");
    document.createElement.mockRestore();
  });

  it("uses the fallback when the server sent no disposition", () => {
    // `fmt=json` returns a JSON body rather than a download, so there is no
    // Content-Disposition and the caller's name is all there is.
    const anchors = [];
    const create = document.createElement.bind(document);
    vi.spyOn(document, "createElement").mockImplementation((tag) => {
      const el = create(tag);
      if (tag === "a") anchors.push(el);
      return el;
    });

    saveResponseAsFile(
      {
        data: new Blob(["{}"]),
        headers: { "content-type": "application/json" },
      },
      "scan_84_findings.json",
    );

    expect(anchors[0].download).toBe("scan_84_findings.json");
    document.createElement.mockRestore();
  });
});
