"""
tests/security/test_upload_validation.py
─────────────────────────────────────────────────────────────────────────────
Negative-path coverage for the two endpoints that accept a file:

    POST /assets/import-amt
    POST /compliance/controls/{control_id}/evidence

Both had working happy-path tests and no negative ones, which is how the
August 2026 upload audit found six defects in code that was passing its suite.
Every assertion below corresponds to a finding in that audit; the finding id is
named in the test's docstring so a failure here says which control regressed.

The unit tests for `core.upload_guard` come first because the endpoint tests
depend on them being right — a magic-byte table that silently matched nothing
would make every endpoint test pass for the wrong reason.

Note on rate limiting: `conftest.py` sets `app.state.limiter.enabled = False`
for the session, so the `@limiter.limit` decorators cannot be exercised through
the TestClient. `test_upload_endpoints_declare_rate_limits` asserts the
decorator is attached instead, which is the part that regresses.
"""

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func
from sqlalchemy.orm import Session

from core.upload_guard import (
    MalwareDetected,
    MalwareScanUnavailable,
    UploadTooLarge,
    UploadTypeRejected,
    assert_content_matches,
    content_disposition,
    looks_like_text,
    sanitize_filename,
    scan_for_malware,
    sniff_content_type,
)
from db.models.amt import AMTInventoryRecord
from db.models.compliance import ComplianceControl, ComplianceTenantFramework
from db.models.users import User

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures and payload builders
# ─────────────────────────────────────────────────────────────────────────────

PDF_BYTES = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF\n"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
# A DOS/PE header. The NUL padding is what `looks_like_text` catches, and the
# absence of any whitelisted signature is what `sniff_content_type` catches.
PE_BYTES = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 64
ELF_BYTES = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56


def _ooxml_bytes() -> bytes:
    """A minimal but genuine OOXML package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<document/>")
    return buf.getvalue()


def _bare_zip_bytes() -> bytes:
    """A plain archive, which the evidence whitelist excludes by design."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.exe", "MZ")
    return buf.getvalue()


@pytest.fixture(autouse=True)
def evidence_dir_is_disposable(tmp_path, monkeypatch):
    """
    Keep uploaded test evidence out of the working tree.

    `_evidence_root()` defaults to /app/data/compliance_evidence, and the API
    container bind-mounts ./Backend at /app — so without this, every evidence
    test drops a real file into Backend/data/compliance_evidence/ in the repo.
    The default is read from the environment on each call, so pointing the
    variable at tmp_path is enough.
    """
    monkeypatch.setenv("COMPLIANCE_EVIDENCE_DIR", str(tmp_path / "evidence"))


@pytest.fixture
def evidence_control(db_session: Session, test_user: User) -> ComplianceControl:
    """A control belonging to a framework this tenant has enabled."""
    ctrl = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_iso27001_2022")
        .first()
    )
    if ctrl is None:
        pytest.skip("ISO 27001 catalogue is not seeded in this database")

    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == ctrl.framework_id,
        )
        .first()
    )
    if inst is None:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_{ctrl.framework_id}",
            tenant_id=test_user.org_id,
            framework_id=ctrl.framework_id,
            is_enabled=True,
        )
        db_session.add(inst)
    else:
        inst.is_enabled = True
    db_session.commit()
    return ctrl


# ─────────────────────────────────────────────────────────────────────────────
# 1. core.upload_guard — magic-byte detection
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "payload,expected",
    [
        (PDF_BYTES, "application/pdf"),
        (PNG_BYTES, "image/png"),
        (b"\xff\xd8\xff\xe0" + b"\x00" * 16, "image/jpeg"),
        (b"GIF89a" + b"\x00" * 16, "image/gif"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16, "application/msword"),
        (b"host,ip\nweb01,10.0.0.1\n", "text/csv"),
    ],
)
def test_sniff_recognises_each_whitelisted_format(payload, expected):
    """Every accepted evidence type must be detectable from its own bytes."""
    assert expected in sniff_content_type(payload)


def test_sniff_recognises_genuine_ooxml():
    """A real .docx is a ZIP carrying [Content_Types].xml."""
    types = sniff_content_type(_ooxml_bytes())
    assert (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        in types
    )


@pytest.mark.parametrize(
    "payload", [PE_BYTES, ELF_BYTES, b"\xca\xfe\xba\xbe" + b"\x00" * 32]
)
def test_sniff_rejects_executables(payload):
    """E-2: an executable matches no whitelisted signature and is not text."""
    assert sniff_content_type(payload) == ()


def test_sniff_rejects_bare_archive_wearing_an_ooxml_signature():
    """
    E-2: the evidence whitelist excludes archives on purpose, but a ZIP's magic
    bytes *are* the OOXML magic bytes. Without the [Content_Types].xml check a
    plain archive renamed .docx passes a signature test.
    """
    assert sniff_content_type(_bare_zip_bytes()) == ()


def test_text_detection_rejects_binary_and_accepts_text():
    """
    E-2: text carries no magic number, so it is confirmed by exclusion. If this
    inverts, declaring `text/plain` becomes an unconditional whitelist bypass.
    """
    assert looks_like_text(b"policy document\nline two\ttabbed\r\n")
    assert not looks_like_text(PE_BYTES)
    assert not looks_like_text(b"\x00")
    assert not looks_like_text(b"")
    # Valid UTF-8 beyond ASCII must still read as text.
    assert looks_like_text("policy — ISO 27001 §5.1\n".encode())


def test_assert_content_matches_rejects_mismatch_and_accepts_agreement():
    """E-2: the declared type must be among the types the bytes can support."""
    assert_content_matches(PDF_BYTES, "application/pdf")  # no raise

    with pytest.raises(UploadTypeRejected):
        assert_content_matches(PE_BYTES, "application/pdf")
    with pytest.raises(UploadTypeRejected):
        assert_content_matches(PDF_BYTES, "image/png")
    # The exact bypass the finding described: an executable declared as text.
    with pytest.raises(UploadTypeRejected):
        assert_content_matches(PE_BYTES, "text/plain")


# ─────────────────────────────────────────────────────────────────────────────
# 2. core.upload_guard — filename and Content-Disposition
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        # The API runs on Linux, where os.path.basename does not treat `\` as a
        # separator. This is the case the old code let through intact.
        ("..\\..\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ('ev"il.pdf', "evil.pdf"),
        ("", "download"),
        ("...", "download"),
        (None, "download"),
    ],
)
def test_sanitize_filename(raw, expected):
    """E-3: reduce a user-supplied name to something safe to store and display."""
    assert sanitize_filename(raw) == expected


def test_content_disposition_cannot_be_broken_by_a_filename():
    """
    E-3: the header used to be an f-string around a user-supplied name. A quote
    ends the quoted-string early; CR/LF would reshape the response.
    """
    header = content_disposition('eq"uote\r\nX-Injected: yes.pdf')
    assert "\r" not in header and "\n" not in header
    # Exactly one quoted-string, so the quote count must stay even and small.
    assert header.count('"') == 2
    assert "X-Injected:" not in header.split(";")[1]
    assert header.startswith("attachment; filename=")


def test_content_disposition_carries_the_real_name_in_rfc5987_form():
    """E-3: non-ASCII names survive in `filename*=` rather than being lost."""
    header = content_disposition("政策文件.pdf")
    assert "filename*=UTF-8''" in header
    assert "%E6%94%BF" in header


# ─────────────────────────────────────────────────────────────────────────────
# 3. core.upload_guard — capped reads and AV posture
# ─────────────────────────────────────────────────────────────────────────────


def test_read_capped_raises_past_the_limit():
    """A-1: the cap must trip on the byte after the limit, not on a claim."""

    class _Fake:
        def __init__(self, data):
            self.file = io.BytesIO(data)

    from core.upload_guard import read_capped

    assert read_capped(_Fake(b"x" * 10), 10) == b"x" * 10
    with pytest.raises(UploadTooLarge):
        read_capped(_Fake(b"x" * 11), 10)


def test_malware_scan_is_off_unless_configured(monkeypatch):
    """
    E-4: no CLAMAV_HOST means no scan and no error. A scanner that is not
    deployed must not turn every evidence upload into a 500.
    """
    monkeypatch.delenv("CLAMAV_HOST", raising=False)
    assert scan_for_malware(b"anything") == "not_configured"


def test_malware_scan_fails_open_when_scanner_is_unreachable(monkeypatch):
    """
    E-4: an unreachable scanner is a coverage gap that gets logged, not an
    outage — the same call the email domain guard makes for a blocklist that
    did not load. UPLOAD_AV_REQUIRED=true is the fail-closed opt-in.
    """
    monkeypatch.setenv("CLAMAV_HOST", "127.0.0.1")
    monkeypatch.setenv("CLAMAV_PORT", "1")  # nothing listens here
    monkeypatch.setenv("CLAMAV_TIMEOUT", "1")
    monkeypatch.setenv("UPLOAD_AV_REQUIRED", "False")
    assert scan_for_malware(b"anything") == "scanner_unavailable"

    # Required: refused, and with the dedicated exception rather than the raw
    # socket error. The endpoint maps this to 503 — the file is not accused of
    # anything, so it must not share a status with a detection.
    monkeypatch.setenv("UPLOAD_AV_REQUIRED", "True")
    with pytest.raises(MalwareScanUnavailable):
        scan_for_malware(b"anything")


def test_malware_detected_is_its_own_exception():
    """A positive detection must never be confusable with an unavailable scanner."""
    assert not issubclass(MalwareDetected, OSError)
    assert not issubclass(MalwareDetected, MalwareScanUnavailable)
    assert not issubclass(MalwareScanUnavailable, MalwareDetected)


def test_configuring_a_scanner_makes_it_required_by_default(monkeypatch):
    """
    Deploying a scanner is the act of requiring it.

    Malware inverts the trade the email domain guard makes: evidence upload is
    low-frequency, so refusing it while the scanner is down costs a retry,
    whereas accepting an unscanned file costs the thing the scan exists for.
    Fail-open stays available, but has to be asked for.
    """
    from core.upload_guard import _av_settings

    monkeypatch.delenv("UPLOAD_AV_REQUIRED", raising=False)

    monkeypatch.delenv("CLAMAV_HOST", raising=False)
    assert _av_settings()[3] is False, "no scanner configured → nothing to require"

    monkeypatch.setenv("CLAMAV_HOST", "clamav")
    assert _av_settings()[3] is True, "a configured scanner is required by default"

    monkeypatch.setenv("UPLOAD_AV_REQUIRED", "false")
    assert _av_settings()[3] is False, "fail-open must remain an explicit opt-in"


@pytest.mark.parametrize(
    "reply",
    [
        b"",  # closed before replying
        b"stream: OK",  # no NUL terminator, connection just ended
        b"stream: Database error ERROR\x00",
        b"UNKNOWN COMMAND\x00",
        b"some unrecognised protocol noise\x00",
    ],
)
def test_only_an_explicit_ok_counts_as_clean(monkeypatch, reply):
    """
    The single most important property of the scanner.

    A scanner failure reported as `clean` is worse than having no scanner: it
    launders an unscanned file into an audit trail that says it was checked.
    Every non-OK outcome must be `scanner_unavailable`. An earlier version of
    this function returned "clean" for anything that was not FOUND or ERROR,
    which covered the first two cases above.
    """
    import socket as socket_mod

    import core.upload_guard as guard

    class _FakeSock:
        def __init__(self, *a, **kw):
            self._out = reply

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, _):
            pass

        def sendall(self, _):
            pass

        def recv(self, _n):
            out, self._out = self._out, b""
            return out

    monkeypatch.setattr(guard.socket, "create_connection", _FakeSock)
    monkeypatch.setenv("CLAMAV_HOST", "clamav")
    monkeypatch.setenv("UPLOAD_AV_REQUIRED", "false")
    assert guard.scan_for_malware(b"data") == "scanner_unavailable"

    # And when the scanner is required, the same outcomes refuse the upload.
    monkeypatch.setenv("UPLOAD_AV_REQUIRED", "true")
    with pytest.raises(MalwareScanUnavailable):
        guard.scan_for_malware(b"data")

    assert socket_mod is guard.socket  # guards against a stray import rename


def test_clean_and_found_are_still_recognised(monkeypatch):
    """The strict OK rule must not break the two verdicts that matter."""
    import core.upload_guard as guard

    class _FakeSock:
        def __init__(self, *a, **kw):
            self._out = self.reply

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, _):
            pass

        def sendall(self, _):
            pass

        def recv(self, _n):
            out, self._out = self._out, b""
            return out

    monkeypatch.setenv("CLAMAV_HOST", "clamav")
    monkeypatch.setenv("UPLOAD_AV_REQUIRED", "true")

    _FakeSock.reply = b"stream: OK\x00"
    monkeypatch.setattr(guard.socket, "create_connection", _FakeSock)
    assert guard.scan_for_malware(b"data") == "clean"

    _FakeSock.reply = b"stream: Eicar-Test-Signature FOUND\x00"
    with pytest.raises(MalwareDetected) as caught:
        guard.scan_for_malware(b"data")
    assert "Eicar-Test-Signature" in caught.value.signature


# ─────────────────────────────────────────────────────────────────────────────
# 4. POST /assets/import-amt
# ─────────────────────────────────────────────────────────────────────────────


def _amt_post(client, auth_headers, body, filename="assets.json"):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode("utf-8")
    return client.post(
        "/assets/import-amt",
        headers=auth_headers,
        files={"file": (filename, body, "application/json")},
    )


def test_amt_import_rejects_oversize_file(client: TestClient, auth_headers: dict):
    """A-1: `file.file.read()` was unbounded; nginx's 50 MB was the only ceiling."""
    from routers.assets import _MAX_AMT_BYTES

    oversize = b'{"data": [' + b" " * (_MAX_AMT_BYTES + 16) + b"]}"
    res = _amt_post(client, auth_headers, oversize)
    assert res.status_code == 413
    assert "limited to" in res.json()["detail"]


def test_amt_import_rejects_non_json_extension(client: TestClient, auth_headers: dict):
    """A-2: there was no server-side extension or type check at all."""
    res = _amt_post(client, auth_headers, {"data": []}, filename="inventory.exe")
    assert res.status_code == 400
    assert ".json" in res.json()["detail"]


def test_amt_import_rejects_binary_content(client: TestClient, auth_headers: dict):
    """A-2: a binary payload named .json produced a misleading JSON syntax error."""
    res = _amt_post(client, auth_headers, PE_BYTES)
    assert res.status_code == 400
    assert "not text" in res.json()["detail"].lower()


def test_amt_import_rejects_empty_file(client: TestClient, auth_headers: dict):
    res = _amt_post(client, auth_headers, b"")
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()


@pytest.mark.parametrize("data_value", [{"x": 1}, "some text", 42])
def test_amt_import_rejects_non_list_data_key(
    client: TestClient, auth_headers: dict, data_value
):
    """
    A-6: `{"data": {...}}` and `{"data": "text"}` both satisfied the structure
    check. Iterating either yielded dict keys or single characters, and the
    `.get()` that followed raised AttributeError outside any handler — a 500
    for what is simply the wrong file.
    """
    res = _amt_post(client, auth_headers, {"data": data_value})
    assert res.status_code == 400, f"expected 400, got {res.status_code}"
    assert "list" in res.json()["detail"].lower()


def test_amt_import_rejects_too_many_records(client: TestClient, auth_headers: dict):
    """A-4: nothing capped len(records) before building a single transaction."""
    from routers.assets import _MAX_AMT_RECORDS

    payload = {
        "data": [{"mac_address_1": "aa:bb:cc:dd:ee:ff"}] * (_MAX_AMT_RECORDS + 1)
    }
    res = _amt_post(client, auth_headers, payload)
    assert res.status_code == 400
    assert "limit" in res.json()["detail"].lower()


def test_amt_import_does_not_wipe_inventory_when_no_record_is_usable(
    client: TestClient, auth_headers: dict, db_session: Session, test_user: User
):
    """
    A-7 — the finding this file exists for.

    The delete ran before any record was validated, so a file that parsed as
    JSON but carried the wrong field names destroyed the organisation's entire
    AMT reference inventory and returned `{"success": true, "records_imported":
    0}`. The caller was told it worked.
    """
    seeded = _amt_post(
        client,
        auth_headers,
        {
            "data": [
                {"mac_address_1": "11:22:33:44:55:66", "asset_tag": "KEEP-1"},
                {"mac_address_1": "aa:bb:cc:dd:ee:ff", "asset_tag": "KEEP-2"},
            ]
        },
    )
    assert seeded.status_code == 200
    assert seeded.json()["records_imported"] == 2

    before = (
        db_session.query(AMTInventoryRecord)
        .filter(AMTInventoryRecord.org_id == test_user.org_id)
        .count()
    )
    assert before == 2

    # Valid JSON, plausible shape, wrong field names — an export from a
    # different tool, which is the realistic version of this mistake.
    res = _amt_post(
        client,
        auth_headers,
        {"data": [{"macAddress1": "11:22:33:44:55:66", "assetTag": "OOPS"}]},
    )

    assert res.status_code == 400, "an import with no usable record must be refused"
    assert "left untouched" in res.json()["detail"]

    db_session.expire_all()
    after = (
        db_session.query(AMTInventoryRecord)
        .filter(AMTInventoryRecord.org_id == test_user.org_id)
        .count()
    )
    assert after == before, "the existing inventory must survive a failed import"


def test_amt_import_replacement_is_atomic(
    client: TestClient,
    auth_headers: dict,
    db_session: Session,
    test_user: User,
    monkeypatch,
):
    """
    A-7, second half: validating before the delete is not sufficient on its own.

    If the delete commits and an insert then fails halfway, the inventory is
    still gone. The endpoint issues one `db.commit()` after both, so the DELETE
    and the INSERTs share a transaction — this proves it by making an insert
    blow up and asserting the pre-existing rows are still there.
    """
    seeded = _amt_post(
        client,
        auth_headers,
        {
            "data": [
                {"mac_address_1": "11:22:33:44:55:66", "asset_tag": "KEEP-1"},
                {"mac_address_1": "aa:bb:cc:dd:ee:ff", "asset_tag": "KEEP-2"},
            ]
        },
    )
    assert seeded.status_code == 200
    db_session.expire_all()
    before = {
        r.mac_address_1
        for r in db_session.query(AMTInventoryRecord).filter(
            AMTInventoryRecord.org_id == test_user.org_id
        )
    }
    assert len(before) == 2

    # Detonate between the DELETE and the COMMIT.
    import routers.assets as assets_router

    def _boom(*_a, **_kw):
        raise RuntimeError("simulated failure during insert")

    monkeypatch.setattr(assets_router, "_amt_text", _boom)

    with pytest.raises(RuntimeError):
        _amt_post(
            client,
            auth_headers,
            {"data": [{"mac_address_1": "de:ad:be:ef:00:99", "asset_tag": "NEW"}]},
        )

    db_session.rollback()
    after = {
        r.mac_address_1
        for r in db_session.query(AMTInventoryRecord).filter(
            AMTInventoryRecord.org_id == test_user.org_id
        )
    }
    assert after == before, "a failed import must not leave the inventory deleted"


def test_amt_import_bounds_individual_field_lengths(
    client: TestClient, auth_headers: dict, db_session: Session, test_user: User
):
    """
    The byte and record caps bound the file; neither bounds a single field.

    `asset_name` is String(255), so a megabyte-long value reached Postgres and
    returned a DataError — an unhandled 500 for what is simply a bad field.
    A structure where a scalar belongs must not crash either.
    """
    res = _amt_post(
        client,
        auth_headers,
        {
            "data": [
                {
                    "mac_address_1": "de:ad:be:ef:01:02",
                    "asset_name": "A" * 100_000,
                    "asset_tag": {"nested": "object"},
                    "location_id": "not-an-integer",
                }
            ]
        },
    )
    assert res.status_code == 200, res.text
    assert res.json()["records_imported"] == 1

    db_session.expire_all()
    rec = (
        db_session.query(AMTInventoryRecord)
        .filter(
            AMTInventoryRecord.org_id == test_user.org_id,
            AMTInventoryRecord.mac_address_1 == "DE:AD:BE:EF:01:02",
        )
        .first()
    )
    assert rec is not None
    assert len(rec.asset_name) == 255
    assert rec.asset_tag is None, "a dict where a string belongs becomes absent"
    assert rec.location_id is None, "an uncoercible integer becomes absent"


def test_amt_import_still_accepts_a_valid_file(
    client: TestClient, auth_headers: dict, db_session: Session, test_user: User
):
    """The happy path must survive all of the above."""
    res = _amt_post(
        client,
        auth_headers,
        {
            "data": [
                {
                    "mac_address_1": "de:ad:be:ef:00:01",
                    "asset_tag": "TAG-OK",
                    "asset_name": "Workstation-1",
                }
            ]
        },
    )
    assert res.status_code == 200
    assert res.json()["records_imported"] == 1

    db_session.expire_all()
    rec = (
        db_session.query(AMTInventoryRecord)
        .filter(
            AMTInventoryRecord.org_id == test_user.org_id,
            AMTInventoryRecord.mac_address_1 == "DE:AD:BE:EF:00:01",
        )
        .first()
    )
    assert rec is not None
    assert rec.asset_tag == "TAG-OK"


# ─────────────────────────────────────────────────────────────────────────────
# 5. POST /compliance/controls/{id}/evidence
# ─────────────────────────────────────────────────────────────────────────────


def _evidence_post(client, auth_headers, control_id, filename, payload, content_type):
    return client.post(
        f"/compliance/controls/{control_id}/evidence",
        headers=auth_headers,
        files={"file": (filename, payload, content_type)},
    )


def test_evidence_rejects_executable_declared_as_pdf(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    """
    E-2 — the finding this endpoint's changes exist for.

    `file.content_type` is written by whatever posted the form. Renaming
    malware.exe to malware.pdf makes the browser declare application/pdf, and
    the whitelist was satisfied by that string alone.
    """
    res = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "malware.pdf",
        PE_BYTES,
        "application/pdf",
    )
    assert res.status_code == 400
    assert "does not match" in res.json()["detail"] or "not a valid" in (
        res.json()["detail"]
    )


def test_evidence_rejects_executable_declared_as_text(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    """E-2: text has no signature, so it must be confirmed by exclusion."""
    res = _evidence_post(
        client, auth_headers, evidence_control.id, "notes.txt", PE_BYTES, "text/plain"
    )
    assert res.status_code == 400


def test_evidence_rejects_bare_archive_declared_as_docx(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    """
    E-2: archives are excluded from the whitelist so content cannot be smuggled
    past the type check — but a ZIP's magic bytes are also OOXML's magic bytes.
    """
    res = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "evidence.docx",
        _bare_zip_bytes(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert res.status_code == 400


def test_evidence_accepts_a_genuine_document_and_reports_scan_verdict(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    """The happy path, plus E-4's audit signal that a scan did or did not run."""
    res = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "policy.pdf",
        PDF_BYTES,
        "application/pdf",
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["content_type"] == "application/pdf"
    assert body["size_bytes"] == len(PDF_BYTES)
    # An auditor must be able to tell "scanned and clean" from "never scanned".
    assert body["malware_scan"] in {"clean", "not_configured", "scanner_unavailable"}


def test_evidence_accepts_genuine_ooxml(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    """The OOXML check must not reject real Office documents."""
    res = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "evidence.docx",
        _ooxml_bytes(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert res.status_code == 201, res.text


def test_evidence_download_header_is_not_breakable(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    """
    E-3: the filename reaches a response header. Upload one carrying a quote and
    a traversal prefix, then read the header back off the download.
    """
    up = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        '../../ev"il.pdf',
        PDF_BYTES,
        "application/pdf",
    )
    assert up.status_code == 201, up.text
    stored_name = up.json()["filename"]
    assert '"' not in stored_name
    assert "/" not in stored_name and "\\" not in stored_name

    down = client.get(
        f"/compliance/evidence/{up.json()['id']}/download", headers=auth_headers
    )
    assert down.status_code == 200
    disposition = down.headers["content-disposition"]
    assert disposition.count('"') == 2, disposition
    assert "\r" not in disposition and "\n" not in disposition
    assert down.headers["x-evidence-sha256"] == up.json()["sha256"]
    assert down.content == PDF_BYTES


def test_evidence_rejects_empty_file(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    res = _evidence_post(
        client, auth_headers, evidence_control.id, "empty.pdf", b"", "application/pdf"
    )
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()


def test_evidence_rejects_type_outside_the_whitelist(
    client: TestClient, auth_headers: dict, evidence_control: ComplianceControl
):
    """The pre-existing whitelist must keep working after the new checks."""
    res = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "archive.zip",
        _bare_zip_bytes(),
        "application/zip",
    )
    assert res.status_code == 400
    assert "not an accepted evidence type" in res.json()["detail"]


def test_evidence_enforces_tenant_storage_quota(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    monkeypatch,
):
    """
    E-6: the per-file cap bounds one request, not a loop of them. Without a
    tenant quota, `compliance:attest` is an unbounded write to the API host's
    disk.
    """
    import routers.compliance_attestation as compliance_router

    monkeypatch.setattr(
        compliance_router, "_MAX_EVIDENCE_BYTES_PER_TENANT", len(PDF_BYTES) + 1
    )

    first = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "one.pdf",
        PDF_BYTES,
        "application/pdf",
    )
    assert first.status_code == 201, first.text

    second = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "two.pdf",
        PDF_BYTES,
        "application/pdf",
    )
    assert second.status_code == 413
    assert "quota" in second.json()["detail"].lower()


def _stored_evidence_files(tmp_path) -> list:
    """Every file currently in the disposable evidence root."""
    root = tmp_path / "evidence"
    return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


@pytest.mark.parametrize(
    "filename,payload,declared,expected_status",
    [
        # Declared type outside the whitelist.
        ("archive.zip", _bare_zip_bytes(), "application/zip", 400),
        # Whitelisted type, contradicted by the bytes.
        ("malware.pdf", PE_BYTES, "application/pdf", 400),
        # Whitelisted type, empty payload.
        ("empty.pdf", b"", "application/pdf", 400),
    ],
)
def test_rejected_evidence_never_reaches_disk(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    tmp_path,
    filename,
    payload,
    declared,
    expected_status,
):
    """
    Scan-then-persist, never persist-then-scan.

    A refused upload must never be briefly present in storage — there must be no
    window in which a rejected file exists on disk for another process, a
    backup, or an indexer to pick up.
    """
    assert _stored_evidence_files(tmp_path) == []

    res = _evidence_post(
        client, auth_headers, evidence_control.id, filename, payload, declared
    )
    assert res.status_code == expected_status, res.text
    assert (
        _stored_evidence_files(tmp_path) == []
    ), "a rejected upload wrote bytes to the evidence store"


def test_malware_detection_refuses_before_writing_anything(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    tmp_path,
    monkeypatch,
):
    """A detection must refuse with nothing on disk and no metadata row."""
    import routers.compliance_attestation as compliance_router

    def _detect(*_a, **_kw):
        raise MalwareDetected("Eicar-Test-Signature")

    monkeypatch.setattr(compliance_router, "scan_for_malware", _detect)

    res = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "policy.pdf",
        PDF_BYTES,
        "application/pdf",
    )
    assert res.status_code == 400
    assert "Eicar-Test-Signature" in res.json()["detail"]
    assert _stored_evidence_files(tmp_path) == []


def test_unavailable_scanner_refuses_with_503_and_no_side_effects(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    db_session: Session,
    test_user: User,
    tmp_path,
    monkeypatch,
):
    """
    R-2: a required scanner that cannot answer refuses the upload — 503, not
    400, because the file is not accused of anything — and leaves neither an
    orphaned file nor committed metadata.
    """
    import routers.compliance_attestation as compliance_router
    from db.models.compliance import ComplianceEvidenceFile

    before = (
        db_session.query(ComplianceEvidenceFile)
        .filter(ComplianceEvidenceFile.tenant_id == test_user.org_id)
        .count()
    )

    def _unavailable(*_a, **_kw):
        raise MalwareScanUnavailable("clamd closed the connection without a reply")

    monkeypatch.setattr(compliance_router, "scan_for_malware", _unavailable)

    res = _evidence_post(
        client,
        auth_headers,
        evidence_control.id,
        "policy.pdf",
        PDF_BYTES,
        "application/pdf",
    )
    assert res.status_code == 503, res.text
    assert _stored_evidence_files(tmp_path) == []

    db_session.expire_all()
    after = (
        db_session.query(ComplianceEvidenceFile)
        .filter(ComplianceEvidenceFile.tenant_id == test_user.org_id)
        .count()
    )
    assert after == before, "a refused upload committed metadata"


def test_failed_commit_leaves_no_orphaned_file(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    db_session: Session,
    test_user: User,
    tmp_path,
    monkeypatch,
):
    """
    R-9. The one window that remained after scan-then-persist: the bytes are
    written before the metadata row is committed. A failure there leaves a file
    nothing points at — unreachable through the API, and invisible to the quota,
    which sums `size_bytes` over *rows*. So it consumes disk that nothing
    accounts for and nothing will reclaim.

    The end state must be all-or-nothing on three axes: the file, the row, and
    the quota accounting derived from the row.
    """
    import routers.compliance_attestation as compliance_router
    from db.models.compliance import ComplianceEvidenceFile

    def _tenant_usage() -> int:
        db_session.expire_all()
        return (
            db_session.query(
                func.coalesce(func.sum(ComplianceEvidenceFile.size_bytes), 0)
            )
            .filter(ComplianceEvidenceFile.tenant_id == test_user.org_id)
            .scalar()
            or 0
        )

    rows_before = (
        db_session.query(ComplianceEvidenceFile)
        .filter(ComplianceEvidenceFile.tenant_id == test_user.org_id)
        .count()
    )
    usage_before = _tenant_usage()
    assert _stored_evidence_files(tmp_path) == []

    # The injection point has to fail *after* the write. `ComplianceEvidenceFile`
    # is the obvious lever and the wrong one: the quota query above the write
    # also references it, so patching it detonates before a byte reaches disk
    # and the test passes without exercising the path it exists for.
    # `sanitize_filename` is evaluated inside the row constructor, which is the
    # first statement in the try block after the file is closed — so the failure
    # lands with the payload already on disk, which is the state under test.
    # Records what was on disk at the instant of failure. Without this the test
    # cannot tell "the file was written and then cleaned up" from "the file was
    # never written" — both end with an empty directory, and only the first is
    # the path R-9 is about.
    # The *content* is captured, not the Path: by the time the assertions below
    # run, the cleanup under test has already unlinked the file, so reading it
    # later raises FileNotFoundError rather than proving anything.
    written_at_failure_time: list = []

    def _explode(*_a, **_kw):
        written_at_failure_time.extend(
            (p.name, p.read_bytes()) for p in _stored_evidence_files(tmp_path)
        )
        raise RuntimeError("simulated database failure after the file was written")

    monkeypatch.setattr(compliance_router, "sanitize_filename", _explode)

    with pytest.raises(RuntimeError):
        _evidence_post(
            client,
            auth_headers,
            evidence_control.id,
            "policy.pdf",
            PDF_BYTES,
            "application/pdf",
        )

    # 0. The failure genuinely landed after the write. If this fails, the
    #    injection point moved above `open()` and the rest of this test proves
    #    nothing.
    assert len(written_at_failure_time) == 1, (
        "the injected failure did not land after the filesystem write; "
        f"files present at failure time: {written_at_failure_time}"
    )
    assert (
        written_at_failure_time[0][1] == PDF_BYTES
    ), "the payload was not fully written before the failure"

    # 1. No file left behind.
    assert (
        _stored_evidence_files(tmp_path) == []
    ), "a failed commit left an orphaned evidence file on disk"

    # 2. No row committed.
    db_session.rollback()
    rows_after = (
        db_session.query(ComplianceEvidenceFile)
        .filter(ComplianceEvidenceFile.tenant_id == test_user.org_id)
        .count()
    )
    assert rows_after == rows_before, "a failed upload committed a metadata row"

    # 3. Quota accounting unchanged — the figure the next upload is checked
    #    against must not have moved.
    assert _tenant_usage() == usage_before, "a failed upload moved the quota total"


def test_evidence_quota_check_is_serialised_per_tenant(db_session: Session):
    """
    E-6, concurrency half.

    SUM → compare → write is a read-modify-write across three statements. Two
    concurrent uploads each read the same total, each conclude they fit, and
    the quota is exceeded by whatever the second one carried. The fix is a
    transaction-scoped advisory lock; this asserts it is actually taken, since
    a helper that quietly no-ops is how a concurrency guard stops guarding.
    """
    import routers.compliance_attestation as compliance_router

    if db_session.bind is None or db_session.bind.dialect.name != "postgresql":
        pytest.skip("advisory locks are Postgres-only; SQLite serialises writers")

    from sqlalchemy import text

    compliance_router._lock_tenant_evidence_quota(db_session, "org_quota_probe")

    held = db_session.execute(
        text(
            "SELECT count(*) FROM pg_locks "
            "WHERE locktype = 'advisory' AND pid = pg_backend_pid()"
        )
    ).scalar()
    assert held >= 1, "no advisory lock was taken; the quota check is racy"

    # Transaction-scoped, so a rollback must release it — no unlock path to miss.
    db_session.rollback()
    still_held = db_session.execute(
        text(
            "SELECT count(*) FROM pg_locks "
            "WHERE locktype = 'advisory' AND pid = pg_backend_pid()"
        )
    ).scalar()
    assert still_held == 0, "advisory lock outlived its transaction"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Rate limiting
# ─────────────────────────────────────────────────────────────────────────────


def test_upload_endpoints_declare_rate_limits():
    """
    A-5 / E-6: both upload endpoints must carry a limit.

    conftest disables the limiter for the session, so this asserts registration
    rather than exercising a 429. slowapi does not mark the decorated function —
    it records the limit centrally in `Limiter._route_limits`, keyed by the
    endpoint's module-qualified name — so that registry is the thing to read.
    `/scan/host-discovery` is included as a control: if the lookup shape ever
    changes, that assertion fails too and says so, rather than this test
    quietly passing on all three.
    """
    import routers.assets
    import routers.compliance
    import routers.phase_scans  # noqa: F401
    from scan_helpers import limiter

    registry = limiter._route_limits
    for key in (
        "routers.assets.import_amt_inventory",
        "routers.compliance.upload_control_evidence",
        "routers.phase_scans.scan_host_discovery",
    ):
        assert registry.get(key), f"{key} carries no @limiter.limit decorator"
