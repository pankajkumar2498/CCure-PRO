# Web Application Gap-Closure — Phase 4: Authorization / Access-Control Testing

Controlled, evidence-based testing for IDOR, horizontal and vertical privilege
escalation, and unauthorized resource access. Builds on Phase 3's multi-session
authentication; integrated into the existing pipeline, not a parallel scanner.

## Multi-user model — sessions never mixed

Each configured identity (User A, User B, an optional administrator) is
authenticated into its **own isolated httpx client** via the Phase 3 session
manager, plus an anonymous client with no session. A test compares what these
separate identities see for the _same_ resource. Peer credentials are carried
under `auth.access_control.users[].auth`, AES-256-GCM encrypted at rest exactly
like the main login (recursively, including their own CSRF/multi-step configs)
and redacted for logs.

## Evidence, not coincidence

A finding is **never** raised for the reasons the specification rejects — an
HTTP 200, an identifier that changed, public content, or a generic endpoint.
Every horizontal (IDOR) finding clears four gates:

1. **Owner baseline** — the owner sees substantive content for its identifier.
2. **Resource-specific** — a bogus identifier returns _different_ content, so
   the endpoint is not a generic page that ignores the id.
3. **Protected** — an anonymous request is denied, so it is not simply public.
4. **Bypass** — another authenticated identity receives content ≥ 90% identical
   to the owner's baseline, i.e. it read a resource it does not own.

Vertical escalation compares a declared admin path: admin sees it, anon is
denied, and a lower-privilege identity nonetheless receives admin content.
A declared admin path served to an anonymous client is broken access control.

## Read-only and safe

GET/read-only verification only; nothing is deleted, modified, purchased or
transferred. State-changing methods are gated behind `allow_write_testing`
(default off) and not exercised by default. Same-origin, bounded candidate
count, rate-limited, cancellable.

## Finding evidence

Each finding records source (attacker) identity, owner identity, endpoint, HTTP
method, the identifier, the response-comparison (owner/anon/attacker statuses
and the attacker↔owner similarity percentage), the authorization context and
the technique. Session tokens and passwords never appear in findings.

Finding types: `idor` (CWE-639, high), `privilege_escalation` (CWE-269,
critical), `broken_access_control` (CWE-284, high) — all OWASP A01. No CVE
invented.

## Tests

`tests/web/test_access_control_engine.py` — 10 tests against a stateful
multi-user app (alice/bob/admin, vulnerable and correctly-protected endpoints,
a generic endpoint and a public endpoint): horizontal IDOR detected, secure
resource not flagged, generic endpoint not flagged, public resource not
flagged, changed-id-alone not a finding, vertical escalation detected, secure
admin not flagged, sessions isolated, cancellation, credential non-exposure.
Both vulnerable and secure behaviour verified.

## End-to-end (multi-user target)

Against a deployed multi-user banking-style target (alice owns account 1001,
bob owns 1002, admin is privileged; each with a real form login), driving the
full orchestrator path — encrypt config → decrypt → authenticate each identity
into an isolated session → run the engine:

- Peer credentials stored **encrypted at rest** (`enc:v1:…`).
- Three identities authenticated into **isolated sessions** — distinct cookies
  (`s-alice`, `s-bob`, `s-admin`), never mixed.
- **Horizontal IDOR (CWE-639, high):** bob read alice's `/account?id=1001`
  (owner content, protected from anon, resource-specific).
- **Vertical privilege escalation (CWE-269, critical) ×2:** alice and bob both
  reached `/admin` functionality (admin baseline, anon denied).
- **Secure endpoints produced nothing:** `/safe_account?id=1001` (ownership
  enforced → bob 403) and `/safe_admin` (role enforced → 403) — no false
  positives.
- **No credential leak:** no session token or password in any finding.

The same evidence-based gates hold against the live app that the unit tests
pin: the generic and public endpoints, and the correctly-protected resources,
raise nothing.

## Application types still unsupported / out of scope this phase

- State-changing authorization tests (unauthorized PUT/DELETE/PATCH execution)
  are gated behind `allow_write_testing` and not exercised by default, to honour
  the no-destructive-actions rule; enabling them is an operator decision for a
  test environment.
- Multi-step _object_ workflows (create → obtain a fresh id → access it as
  another user) beyond identifiers already present in the discovered surface.
- Authorization expressed only through request bodies / JSON object graphs that
  the identifier extractor does not surface (path + query identifiers are
  covered).

## Regression

web + reports + security: **476 passed, 0 failed** (10 new access-control
tests). Phases 1–3, SQLi, crawling, reporting, progress and terminal-state all
still pass.
