/**
 * Turning an authenticated API response into a saved file.
 *
 * `/reports/download` and `/reports/export` are authenticated endpoints, so
 * the browser cannot be pointed at them with an `href` — a plain link carries
 * no Authorization header and lands on a 401 page. The response has to be
 * fetched, held as a Blob and handed to a synthetic anchor, which is what
 * every caller in this app already does, separately, in eight places.
 *
 * Two details here are the ones those copies get wrong or omit.
 *
 * **The server names the file.** `Content-Disposition` carries a name built
 * from the scan number and the dataset (`scan_84_scn_defa_c52_findings.xlsx`);
 * a client-invented name loses the scan it came from, which for an artefact
 * that ends up attached to an audit is the one thing it must keep. RFC 6266's
 * `filename*` form is preferred where present, because that is the one that
 * survives a non-ASCII name.
 *
 * **The object URL is always revoked.** A Blob URL pins its data in memory
 * until revoked, and a workbook is hundreds of kilobytes — leaking one per
 * export is a real cost in a long session. It is released in a `finally`, so a
 * failure between creating and clicking does not leak it either.
 */

/** RFC 6266: prefer `filename*`, fall back to `filename`, else null. */
export function filenameFromDisposition(disposition) {
  if (!disposition) return null;

  // filename*=UTF-8''name%20with%20spaces.xlsx
  const extended = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(disposition);
  if (extended && extended[2]) {
    try {
      return decodeURIComponent(extended[2].trim());
    } catch {
      // A malformed percent-escape is not a reason to lose the download; fall
      // through to the plain form.
    }
  }

  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(disposition);
  return plain && plain[1] ? plain[1].trim() : null;
}

/**
 * Save a Blob under `filename`.
 *
 * Exported separately so a caller that already holds bytes — a JSON body it
 * serialised itself — can use the same path as one that received a file.
 */
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename || "download";
    // Firefox requires the anchor to be in the document before a synthetic
    // click does anything.
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

/**
 * Save an axios response that carries a file.
 *
 * `fallbackName` is used only when the server sent no disposition — which is
 * the case for `fmt=json`, where the endpoint returns a JSON *body* rather
 * than a download. The response's own content type is preserved, so the saved
 * file opens in whatever the OS associates with it.
 */
export function saveResponseAsFile(response, fallbackName) {
  const disposition =
    response?.headers?.["content-disposition"] ??
    response?.headers?.get?.("content-disposition");
  const type =
    response?.headers?.["content-type"] ??
    response?.headers?.get?.("content-type") ??
    "application/octet-stream";

  const data = response?.data;
  const blob = data instanceof Blob ? data : new Blob([data], { type });

  saveBlob(blob, filenameFromDisposition(disposition) || fallbackName);
}
