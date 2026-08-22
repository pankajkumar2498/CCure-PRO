"""
core/upload_guard.py
─────────────────────────────────────────────────────────────────────────────
Shared primitives for the two endpoints in this product that accept a file:
`POST /compliance/controls/{id}/evidence` and `POST /assets/import-amt`.

They had different, and differently incomplete, versions of the same three
checks. The evidence endpoint read with a cap and the AMT endpoint did not; the
AMT endpoint had no type check at all; both built a `Content-Disposition` by
f-string. Keeping one copy is the point of this module — an upload check that
exists on one endpoint and not the other is the shape every finding in the
August 2026 upload audit took.

Four things worth knowing before changing anything here:

  * **The declared `Content-Type` is attacker-controlled.** It arrives in the
    multipart part header, written by whatever posted the form. `content_type`
    on a FastAPI `UploadFile` is that string and nothing more — it is not
    derived from the bytes. `sniff_content_type()` is what actually looks at
    the payload.

  * **There is deliberately no `python-magic` or `filetype` dependency.**
    libmagic is a system library the API image does not carry, and the
    whitelist here is ten formats with stable, well-published signatures. A
    sixty-line table that a reviewer can read start to finish is worth more
    than a supply-chain edge, and this deployment installs from a pinned
    requirements file behind a private CA.

  * **Text has no magic number**, which is the whole difficulty. `text/plain`
    and `text/csv` cannot be confirmed by a signature, so they are confirmed by
    *exclusion*: the payload must decode as UTF-8 and must not carry NUL or C0
    control bytes. A PE, an ELF and a Mach-O binary all fail that on the first
    NUL. Without this rule, declaring `text/plain` is an unconditional bypass
    of the entire whitelist.

  * **OOXML is a ZIP, and the whitelist excludes archives on purpose.** A bare
    ZIP renamed `.docx` would otherwise pass a signature check, because its
    signature *is* the ZIP signature. `_looks_like_ooxml()` requires
    `[Content_Types].xml` in the central directory, which a smuggled archive
    does not have. Only the directory is read; nothing is decompressed, so a
    zip bomb costs the central-directory parse and no more.
"""

from __future__ import annotations

import io
import logging
import os
import re
import socket
import unicodedata
import zipfile
from urllib.parse import quote

log = logging.getLogger("ccure.upload_guard")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Capped reads
# ─────────────────────────────────────────────────────────────────────────────
#
# The size of an upload is only knowable once the bytes are in hand. A declared
# `Content-Length` is a claim by the client, and nginx's `client_max_body_size`
# is a different layer's ceiling that this process must not depend on — it is
# 50 MB on the host listener, and an endpoint that reads unbounded inherits
# that as its own memory budget per concurrent request.
#
# Reading MAX + 1 and testing for overflow is the whole trick: it never
# allocates more than one byte beyond the limit, and it cannot be lied to.


# INSTREAM chunk size, and the ceiling on how much of a clamd reply is read
# before giving up. A verdict line is tens of bytes; 4 KB is generous.
_AV_CHUNK_BYTES = 65536
_AV_MAX_RESPONSE_BYTES = 4096


class UploadTooLarge(Exception):
    """Raised when a payload exceeds the caller's cap. Callers map this to 413."""

    def __init__(self, limit_bytes: int):
        self.limit_bytes = limit_bytes
        super().__init__(f"Upload exceeds {limit_bytes} bytes")


async def read_capped_async(upload_file, max_bytes: int) -> bytes:
    """Read at most `max_bytes` from an async UploadFile, or raise UploadTooLarge."""
    payload = await upload_file.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise UploadTooLarge(max_bytes)
    return payload


def read_capped(upload_file, max_bytes: int) -> bytes:
    """
    Read at most `max_bytes` from a sync endpoint's UploadFile.

    Takes the FastAPI `UploadFile`, not its `.file`, so both call sites pass the
    same object. Endpoints declared `def` rather than `async def` cannot await
    the async reader, and `import-amt` is one of those.
    """
    payload = upload_file.file.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise UploadTooLarge(max_bytes)
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# 2. Magic-byte detection
# ─────────────────────────────────────────────────────────────────────────────

# Signature → the MIME types that signature legitimately backs. One signature
# maps to several types because the container is shared: OLE2 carries both .doc
# and .xls, and ZIP carries both .docx and .xlsx. The declared type only has to
# be *among* the types the bytes can support, because nothing downstream
# distinguishes a Word OLE2 stream from an Excel one, and guessing between them
# would reject legitimate documents to no benefit.
_SIGNATURES: list[tuple[bytes, tuple[str, ...]]] = [
    (b"%PDF-", ("application/pdf",)),
    (b"\x89PNG\r\n\x1a\n", ("image/png",)),
    (b"\xff\xd8\xff", ("image/jpeg",)),
    (b"GIF87a", ("image/gif",)),
    (b"GIF89a", ("image/gif",)),
    # OLE2 compound file: legacy .doc and .xls.
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        ("application/msword", "application/vnd.ms-excel"),
    ),
    # ZIP local file header: OOXML .docx and .xlsx, subject to _looks_like_ooxml.
    (
        b"PK\x03\x04",
        (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
    ),
]

# Types that carry no signature and are confirmed by exclusion instead.
_TEXT_TYPES = frozenset({"text/plain", "text/csv", "application/json"})

# C0 controls that never appear in a document a human typed. Tab, LF and CR are
# excluded from the set because they obviously do appear.
_BINARY_CONTROL_BYTES = frozenset(
    set(range(0x09)) | set(range(0x0B, 0x0D)) | set(range(0x0E, 0x20)) | {0x7F}
)


class UploadTypeRejected(Exception):
    """Raised when the payload's real type contradicts the declared one."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def _looks_like_ooxml(payload: bytes) -> bool:
    """
    True when a ZIP payload is an Office Open XML document rather than a plain
    archive.

    Only the central directory is parsed. `[Content_Types].xml` is mandated by
    ECMA-376 at the package root, so its absence means the ZIP is something
    else wearing a .docx name — which is exactly the archive smuggling the
    evidence whitelist excludes archives to prevent.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            return "[Content_Types].xml" in zf.namelist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def looks_like_text(payload: bytes) -> bool:
    """
    True when the payload is plausibly a text document.

    Decodes strictly as UTF-8 and rejects NUL and other C0 control bytes. Every
    common executable format fails this immediately: a PE carries NUL padding
    within its first 64 bytes, ELF's magic is `\\x7fELF`, and Mach-O's is a
    non-UTF-8 four-byte magic.
    """
    if not payload:
        return False
    if any(b in _BINARY_CONTROL_BYTES for b in payload[:8192]):
        return False
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def sniff_content_type(payload: bytes) -> tuple[str, ...]:
    """
    Return the MIME types the payload's own bytes can support.

    An empty tuple means the content matched no known signature and is not
    plausible text — which is the answer for every executable, and the answer
    callers should refuse on.
    """
    for signature, types in _SIGNATURES:
        if payload.startswith(signature):
            if signature == b"PK\x03\x04" and not _looks_like_ooxml(payload):
                # A ZIP that is not an OOXML package. Fall through rather than
                # returning the OOXML types.
                break
            return types
    if looks_like_text(payload):
        return tuple(_TEXT_TYPES)
    return ()


def assert_content_matches(payload: bytes, declared_type: str) -> None:
    """
    Refuse a payload whose bytes contradict the type the client declared.

    Raises UploadTypeRejected with wording safe to return to the caller: it
    names the declared type, which the caller already knows, and never echoes
    file content back.
    """
    actual = sniff_content_type(payload)
    if not actual:
        raise UploadTypeRejected(
            f"The file content is not a valid '{declared_type}'. "
            "It appears to be binary data of an unsupported format."
        )
    if declared_type not in actual:
        raise UploadTypeRejected(
            f"The file content does not match the declared type "
            f"'{declared_type}'. Upload the file in the format it claims to be."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Content-Disposition
# ─────────────────────────────────────────────────────────────────────────────
#
# `f'attachment; filename="{name}"'` was the shape at every download site here.
# The name reaching it is user-supplied, and `os.path.basename()` — the only
# treatment it got — strips `/` and nothing else. On Linux, which the API runs
# on, `\` is not a path separator, so a Windows-style path survived intact; and
# a `"` in the name ends the quoted-string early, reshaping the header.
#
# RFC 6266 §4.1 is the fix: an ASCII-safe `filename=` for old agents and an
# RFC 5987 `filename*=` carrying the real name percent-encoded as UTF-8.

_UNSAFE_FILENAME_RE = re.compile(r'[\x00-\x1f\x7f"\\/:*?<>|]')


def sanitize_filename(name: str | None, fallback: str = "download") -> str:
    """
    Reduce a user-supplied filename to something safe to store and to display.

    Strips directory components under both separators, removes quotes, control
    characters and the Windows-reserved set, collapses whitespace, and refuses
    to return an empty or dot-only name. Truncates to 255 bytes, which is the
    ext4 and NTFS limit for a single component.

    This is a *display* name. Neither call site derives a storage path from it —
    evidence writes `{uuid}{whitelisted extension}` — and none should start.
    """
    raw = (name or "").replace("\\", "/")
    raw = os.path.basename(raw)
    # NFKC folds full-width and compatibility forms that render like separators.
    raw = unicodedata.normalize("NFKC", raw)
    cleaned = _UNSAFE_FILENAME_RE.sub("", raw)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().strip(".")
    if not cleaned:
        return fallback
    return cleaned.encode("utf-8")[:255].decode("utf-8", "ignore") or fallback


def content_disposition(filename: str | None, disposition: str = "attachment") -> str:
    """
    Build an RFC 6266 Content-Disposition value that a filename cannot break.

    Emits both forms. The plain `filename=` is the ASCII transliteration for
    agents that predate RFC 5987; `filename*=` carries the real UTF-8 name and
    wins in every current browser.
    """
    safe = sanitize_filename(filename)
    ascii_fallback = safe.encode("ascii", "ignore").decode("ascii").strip()
    # A wholly non-ASCII name transliterates to nothing, or to a bare ".pdf"
    # with no stem. Give it a stem rather than emitting a filename that is only
    # an extension; `filename*=` carries the real name for anything modern.
    if "." in ascii_fallback:
        stem, _, extension = ascii_fallback.rpartition(".")
        if not stem:
            ascii_fallback = f"download.{extension}" if extension else "download"
    elif not ascii_fallback:
        ascii_fallback = "download"
    # Belt and braces: the quoted-string form must not contain a quote even
    # after sanitisation, since this is the value that decides header framing.
    ascii_fallback = ascii_fallback.replace('"', "")
    encoded = quote(safe, safe="")
    return f"{disposition}; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Malware scanning
# ─────────────────────────────────────────────────────────────────────────────
#
# Evidence files are stored and handed back to other people in the tenant, so
# an audit workspace is a file-sharing surface whether or not it was designed
# as one. This talks clamd's INSTREAM protocol directly over a socket: clamd is
# a service, not a library, and the wire format is four bytes of length
# followed by the chunk, terminated by a zero-length chunk. Adding `pyclamd`
# for that would be a dependency for thirty lines.
#
# **Only an explicit "OK" is clean.** Every other outcome — a timeout, a closed
# connection, a truncated reply, an ERROR, a response this parser does not
# recognise — is `scanner_unavailable`, never `clean`. This is the single most
# important property of the function: a scanner failure that reports "clean" is
# worse than having no scanner at all, because it launders an unscanned file
# into an audit trail that says it was checked.
#
# **Deploying a scanner means requiring it.** `UPLOAD_AV_REQUIRED` defaults to
# *on whenever CLAMAV_HOST is set*. The email domain guard fails open for an
# unloadable blocklist, and that is right there — refusing every signup is a
# worse outage than the abuse. Malware inverts the trade: evidence upload is a
# low-frequency operation, so refusing it while the scanner is down costs an
# auditor a retry, whereas accepting an unscanned file costs the thing the
# scan exists for. Set UPLOAD_AV_REQUIRED=false to opt into fail-open
# deliberately, which is a reasonable staged-rollout setting while clamd is
# still being brought up.
#
# With no CLAMAV_HOST at all there is no scan and no error: the caller is told
# `not_configured` and can render that honestly.


class MalwareDetected(Exception):
    """Raised when the scanner names a signature. Callers map this to 400."""

    def __init__(self, signature: str):
        self.signature = signature
        super().__init__(f"Malware signature detected: {signature}")


class MalwareScanUnavailable(Exception):
    """
    Raised when a *required* scanner could not produce a verdict.

    Distinct from MalwareDetected on purpose: callers answer 400 for a
    detection and 503 for this, and the two must never be confusable.
    """


def _av_settings() -> tuple[str, int, float, bool]:
    host = os.getenv("CLAMAV_HOST", "").strip()
    port = int(os.getenv("CLAMAV_PORT", "3310"))
    timeout = float(os.getenv("CLAMAV_TIMEOUT", "30"))
    # Configuring a scanner is the act of requiring it. Opting out is explicit.
    raw_required = os.getenv("UPLOAD_AV_REQUIRED", "").strip().lower()
    required = bool(host) if raw_required == "" else raw_required == "true"
    return host, port, timeout, required


def _unavailable(context: str, reason: str, required: bool) -> str:
    """One exit for every way a scan can fail to produce a verdict."""
    if required:
        log.error("Malware scan failed for %s: %s. Upload refused.", context, reason)
        raise MalwareScanUnavailable(reason)
    log.warning(
        "Malware scan unavailable for %s: %s. Upload allowed because "
        "UPLOAD_AV_REQUIRED is false.",
        context,
        reason,
    )
    return "scanner_unavailable"


def scan_for_malware(payload: bytes, *, context: str = "upload") -> str:
    """
    Scan a payload with clamd if one is configured.

    Returns "clean", "not_configured", or "scanner_unavailable". Raises
    MalwareDetected when clamd names a signature, and MalwareScanUnavailable
    when a required scanner could not answer.

    The payload is already bounded by the caller's read cap before it reaches
    here — this function must never be handed an unbounded buffer.
    """
    host, port, timeout, required = _av_settings()
    if not host:
        return "not_configured"

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"zINSTREAM\x00")
            view = memoryview(payload)
            for offset in range(0, len(payload), _AV_CHUNK_BYTES):
                chunk = view[offset : offset + _AV_CHUNK_BYTES]
                sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
            sock.sendall((0).to_bytes(4, "big"))

            # clamd terminates its reply with NUL. Bounded so a scanner that
            # streams without terminating cannot hold the request open.
            response = b""
            truncated = False
            while b"\x00" not in response:
                if len(response) >= _AV_MAX_RESPONSE_BYTES:
                    truncated = True
                    break
                block = sock.recv(4096)
                if not block:
                    break  # closed before terminating — not a verdict
                response += block
    except (TimeoutError, OSError) as exc:
        return _unavailable(context, f"clamd at {host}:{port}: {exc}", required)

    if truncated:
        return _unavailable(context, "clamd reply exceeded the response cap", required)

    # The NUL is how a reply is known to be *complete*. Without it the bytes in
    # hand are a prefix of something, and a prefix that happens to end in "OK"
    # would otherwise be read as a clean verdict. Completeness is checked before
    # content for exactly that reason.
    if b"\x00" not in response:
        return _unavailable(
            context, "clamd reply was not terminated; the connection dropped", required
        )

    verdict = response.split(b"\x00")[0].decode("utf-8", "replace").strip()
    if not verdict:
        # Terminated, but empty. Previously this fell through to "clean", which
        # reported an unscanned file as scanned.
        return _unavailable(context, "clamd returned an empty verdict", required)

    if verdict.endswith("FOUND"):
        # "stream: Eicar-Test-Signature FOUND" → the middle field is the name.
        signature = verdict[len("stream:") : -len("FOUND")].strip() or "unknown"
        log.warning("Malware detected in %s: %s", context, signature)
        raise MalwareDetected(signature)

    if verdict.endswith("OK"):
        return "clean"

    # ERROR, or anything this parser does not recognise. Both are the same
    # thing for our purposes: no verdict was obtained. Never "clean".
    return _unavailable(context, f"clamd replied {verdict!r}", required)
