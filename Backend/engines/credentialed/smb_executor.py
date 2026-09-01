"""
Windows authenticated collection over SMB, Remote Registry and WMI/DCOM.

The second Windows transport, added because the first one is not always there.
**WinRM is off by default on Windows client SKUs**, so on a workstation estate
this product reached fewer hosts out of the box than the tools it is measured
against — whose primary Windows transport has always been SMB plus Remote
Registry plus WMI. That was a recorded coverage gap, not a defect in WinRM, and
this closes it without touching WinRM.

**This is a transport, not a collector.** ``WindowsCollector`` is unchanged
apart from one seam: it already asked for data by *name* — ``_run("os_info")``,
``_run_json("services")`` — and this executor answers those names natively
instead of by running PowerShell. Every parser, every finding, every check and
every report path downstream is the same one WinRM drives.

    Credential → resolver → SMB / RemoteRegistry / WMI → WindowsCollector
        → existing checks → findings

**It deliberately cannot execute commands.** ``run()`` refuses rather than
approximating a shell. Remote command execution over SMB means creating a
service or a scheduled task on the target — which is what psexec does, changes a
host this product is only meant to read, and is precisely the elevation
mechanism the Windows path is forbidden to invent. So anything genuinely
command-shaped reports UNAVAILABLE, the engine renders that as ERROR, and no
check ever returns a verdict this transport did not establish. A narrower honest
transport beats a broader dishonest one.

Three things measured against a real Windows 11 Pro host before this was
written, each of which shapes the code:

- **Remote Registry answers, but not immediately.** The service is
  trigger-started on client SKUs, so the first ``\\winreg`` bind can fail with
  ``STATUS_PIPE_NOT_AVAILABLE`` while the service is still coming up and succeed
  seconds later. The bind is retried rather than reported as "not supported".
  **The service is never started by this code** — it is stopped by default, this
  product's own ``ccure.win.remote_registry.not_running`` check treats a running
  one as a finding, and starting it would both modify the host and contradict
  the advice the same scan gives.
- **SCMR is the reliable service source.** ``\\svcctl`` enumerated 848 services
  where WMI's ``Win32_Service`` returned 360; the two disagree because WMI omits
  driver services. Services come from WMI, which carries the start mode and
  binary path the checks read, and SCMR is the fallback when DCOM is blocked.
- **DCOM needs more than port 445.** WMI negotiates a dynamic high port after
  the 135 endpoint mapper, so a firewall that permits SMB alone gets SMB and
  Remote Registry and no WMI. Each subsystem is therefore opened lazily and
  independently: losing one does not lose the others.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from typing import Any, Callable, Dict, List, Optional

from engines.credentialed.ssh_scanner import CommandResult

log = logging.getLogger(__name__)

try:  # pragma: no cover - import guard
    from impacket.dcerpc.v5 import rrp, scmr, transport
    from impacket.dcerpc.v5.dcom import wmi as impacket_wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.smbconnection import SMBConnection

    IMPACKET_AVAILABLE = True
except ImportError:  # pragma: no cover - import guard
    IMPACKET_AVAILABLE = False
    SMBConnection = DCOMConnection = None  # type: ignore
    rrp = scmr = transport = impacket_wmi = None  # type: ignore
    NULL = None  # type: ignore

IMPACKET_INSTALL_HINT = (
    "impacket is not installed, so SMB/WMI Windows collection is unavailable. "
    "Run: pip install impacket==0.12.0"
)

DEFAULT_SMB_PORT = 445
#: NetBIOS session service. Still found on old estates; impacket speaks it.
LEGACY_SMB_PORT = 139


class SMBError(RuntimeError):
    """Base for every SMB-path failure this module distinguishes."""


class SMBConnectionError(SMBError):
    """Nothing answered — host down, 445 filtered, or SMB disabled."""


class SMBAuthenticationError(SMBError):
    """The credential was rejected."""


class SMBPermissionError(SMBError):
    """Authenticated, but not permitted to do what was asked."""


class SMBConfigurationError(SMBError):
    """SMB answered but is configured in a way that prevents the scan."""


#: Substrings of impacket's error text that identify a rejected credential.
#: Matched explicitly for the reason the WinRM executor matches its own: the
#: literal strings contain none of "401", "unauthorized" or "authentication",
#: so a generic classifier calls a refused password a connection error and the
#: operator goes looking at the firewall.
_AUTH_MARKERS = (
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_WRONG_PASSWORD",
    "STATUS_NO_SUCH_USER",
    "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
)

_PERMISSION_MARKERS = (
    "STATUS_ACCESS_DENIED",
    "rpc_s_access_denied",
    "WBEM_E_ACCESS_DENIED",
    "0x80041003",
)

_UNAVAILABLE_MARKERS = (
    "STATUS_PIPE_NOT_AVAILABLE",
    "STATUS_OBJECT_NAME_NOT_FOUND",
    "SERVICE_NOT_ACTIVE",
)


def classify_smb_error(exc: Exception) -> SMBError:
    """
    Turn an impacket exception into one a person can act on.

    Four types, and they must stay four: a refused password, an unprivileged
    account, nothing listening, and a subsystem that is switched off need four
    different actions. Collapsing them is how a stopped Remote Registry service
    becomes "host unreachable".
    """
    text = str(exc)
    if any(marker in text for marker in _AUTH_MARKERS):
        return SMBAuthenticationError(f"SMB credential rejected: {text}")
    if any(marker in text for marker in _PERMISSION_MARKERS):
        return SMBPermissionError(f"SMB access denied: {text}")
    if any(marker in text for marker in _UNAVAILABLE_MARKERS):
        return SMBConfigurationError(f"SMB subsystem unavailable: {text}")
    lowered = text.lower()
    if any(
        marker in lowered
        for marker in ("timed out", "timeout", "refused", "unreachable", "no route")
    ):
        return SMBConnectionError(f"Cannot reach SMB: {text}")
    return SMBConnectionError(f"SMB error: {text}")


#: The documented all-zero LM half of a Pass-the-Hash pair. Modern Windows does
#: not accept LM authentication at all, and computing a real LM hash would mean
#: holding the plaintext password that Pass-the-Hash exists to avoid storing.
_EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

_NT_HASH = re.compile(r"^[0-9a-fA-F]{32}$")


def _normalise_nt_hash(raw: Optional[str]) -> Optional[str]:
    """
    Accept an NT hash, in either of the two forms operators paste.

    ``LM:NT`` is how every dumping tool prints a pair, so an operator who copies
    one gets it whole; only the NT half is used. A value that is not 32 hex
    characters is refused rather than sent — an unparsed hash would be presented
    as though it were one and produce a failed logon against a real account,
    which is a lockout risk created by a typo.

    The value is never logged, and the exception deliberately does not quote it.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if ":" in text:
        text = text.rsplit(":", 1)[-1].strip()
    if not _NT_HASH.match(text):
        raise SMBConfigurationError(
            "the NT hash is not 32 hexadecimal characters. Expected an NT hash "
            "or an LM:NT pair as dumping tools print it."
        )
    return text.lower()


def _s(value: Any) -> str:
    """impacket returns null-terminated strings; trim and normalise."""
    if value is None:
        return ""
    text = str(value)
    return text.split("\x00", 1)[0].strip()


class SMBExecutor:
    """
    An SMB/WMI/Remote-Registry session shaped like the other executors.

    Always use as a context manager so every subsystem is released::

        with SMBExecutor("10.0.0.5", "CORP\\\\svc_scan", password=pw) as smb:
            result = smb.run_named("os_info")
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: Optional[str] = None,
        *,
        port: Optional[int] = None,
        domain: Optional[str] = None,
        timeout: int = 30,
        nt_hash: Optional[str] = None,
        **_ignored: Any,
    ):
        if not IMPACKET_AVAILABLE:
            raise SMBConfigurationError(IMPACKET_INSTALL_HINT)

        self.ip = ip
        # NTLM wants the domain as its own field, so a ``DOMAIN\\user`` principal
        # is split back apart here. ``principal()`` on the credential composes
        # it for the transports that want it joined; this one does not.
        user = username or ""
        resolved_domain = domain or ""
        if "\\" in user:
            resolved_domain, _, user = user.partition("\\")
        self.username = user
        self.domain = resolved_domain or ""
        self._password = password
        #: NT hash for Pass-the-Hash. Held beside the password and wiped with
        #: it. When set it is the *only* material presented: see ``_new_smb``.
        self._nt_hash = _normalise_nt_hash(nt_hash)
        self.port = int(port or DEFAULT_SMB_PORT)
        self.timeout = int(timeout)

        # Per-thread connections. ``WindowsCollector.collect_all`` runs its
        # sections in a ThreadPoolExecutor, and neither an impacket
        # ``SMBConnection`` nor a bound DCE/RPC handle is thread-safe: sharing
        # one corrupts the session and the target resets the connection
        # (WinError 10054) part-way through the run. Measured against a real
        # host — a shared registry handle lost the software inventory, the OS
        # revision and the share list, while the WMI sections that happened to
        # finish first succeeded. This is the same trap the WinRM executor
        # documents for pywinrm sessions, one protocol over.
        self._local = threading.local()
        #: The connection opened by ``connect()``, owned by the calling thread
        #: and closed by ``disconnect()``. Worker threads open their own.
        self._threads: List[Any] = []
        self._closed = False
        self._lock = threading.Lock()
        #: Subsystems that were tried and are not available on this host, so a
        #: second caller does not pay the timeout again. Keyed by name, valued
        #: with the reason, which travels into the coverage record.
        self.unavailable: Dict[str, str] = {}
        #: Whether Remote Registry was running before this transport used it.
        #: ``None`` until the first registry access establishes it. See
        #: ``_open_registry`` for why the order of those two events matters.
        self.remote_registry_was_running: Optional[bool] = None

    # ── Context manager ──────────────────────────────────────────────────────

    def __enter__(self) -> "SMBExecutor":
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ── BaseExecutor ─────────────────────────────────────────────────────────

    def _new_smb(self) -> Any:
        """One freshly authenticated SMB session, for the calling thread."""
        try:
            smb = SMBConnection(
                self.ip, self.ip, sess_port=self.port, timeout=self.timeout
            )
            if self._nt_hash:
                # Pass-the-Hash. The password is sent as an empty string
                # deliberately: impacket authenticates with the hash when one is
                # supplied, and passing both would let it fall back to the
                # password if the hash were rejected — which turns one failed
                # logon into two and hides which material the target refused.
                #
                # The LM half is the documented all-zero placeholder. Modern
                # Windows does not accept LM at all, and computing a real one
                # would mean holding the plaintext this method exists to avoid.
                smb.login(
                    self.username,
                    "",
                    self.domain,
                    lmhash=_EMPTY_LM_HASH,
                    nthash=self._nt_hash,
                )
            else:
                smb.login(self.username, self._password or "", self.domain)
            return smb
        except Exception as exc:  # noqa: BLE001 — classified, not swallowed
            raise classify_smb_error(exc) from exc

    def connect(self) -> None:
        """
        Open the SMB session. Raises on connection or authentication failure.

        Only SMB is opened here. Remote Registry and WMI are opened on first use
        because either may be blocked while SMB works perfectly, and a host that
        can still be inventoried through the two that answered should not be
        abandoned because the third did not.
        """
        smb = self._new_smb()

        # A guest session authenticates and can read almost nothing. Reporting
        # it as success would hand the collectors an empty host and the report
        # would show a clean machine that was never actually inspected.
        try:
            if smb.isGuestSession():
                smb.close()
                raise SMBAuthenticationError(
                    "SMB mapped this credential to the guest account, which "
                    "cannot read the host's configuration. Check the username, "
                    "the domain, and that the account is permitted to log on."
                )
        except SMBAuthenticationError:
            raise
        except Exception:  # noqa: BLE001 — older servers may not answer this
            pass

        self._local.smb = smb
        with self._lock:
            self._threads.append(smb)
        log.info(
            "SMB connected to %s:%s as %s%s",
            self.ip,
            self.port,
            f"{self.domain}\\" if self.domain else "",
            self.username,
        )

    def disconnect(self) -> None:
        """Release every thread's subsystems and wipe the credential."""
        self._closed = True
        for attr, closer in (
            ("registry", lambda h: h.disconnect()),
            ("dcom", lambda h: h.disconnect()),
        ):
            handle = getattr(self._local, attr, None)
            if handle is not None:
                try:
                    closer(handle)
                except Exception:  # noqa: BLE001 — teardown is best effort
                    log.debug("SMB executor: releasing %s raised", attr, exc_info=True)
                setattr(self._local, attr, None)
        with self._lock:
            sessions, self._threads = list(self._threads), []
        for smb in sessions:
            try:
                smb.close()
            except Exception:  # noqa: BLE001 — teardown is best effort
                log.debug("SMB executor: closing a session raised", exc_info=True)
        self._local = threading.local()
        self._password = None
        self._nt_hash = None

    def run(self, command: str, timeout: Optional[int] = None) -> CommandResult:
        """
        Refused, deliberately, and this is a design decision rather than a gap.

        Executing a command over SMB means creating a service or a scheduled
        task on the target. That writes to a host this product is only meant to
        read, and it is the elevation mechanism the Windows path is explicitly
        forbidden to invent. Returning a *failed* result rather than raising
        keeps the contract with ``BaseExecutor``: a caller that needs a shell
        gets UNAVAILABLE, which the configuration engine renders as ERROR — a
        recorded gap — and never as a passing check.
        """
        return CommandResult(
            stderr=(
                "The SMB transport does not execute commands. Remote execution "
                "over SMB requires creating a service or scheduled task on the "
                "target, which this product does not do. Use the WinRM "
                "transport for command-based checks."
            ),
            exit_code=-1,
            success=False,
        )

    @property
    def executes_commands(self) -> bool:
        """
        False. Read by the collectors so a command-shaped check can report that
        this transport cannot perform it, instead of reading a refusal as an
        empty reading from the host.
        """
        return False

    # ── Subsystems, opened lazily ────────────────────────────────────────────

    def _require_smb(self) -> Any:
        """
        This thread's SMB session, opening one if it is the first to ask.

        A worker thread gets its own authenticated session rather than borrowing
        the one ``connect()`` opened. That is one logon per collecting thread —
        the price of a transport whose handles cannot be shared — and it is
        bounded by the collector's own thread pool, not by the number of
        sections.
        """
        if self._closed:
            raise SMBConnectionError("the SMB session has been closed")
        smb = getattr(self._local, "smb", None)
        if smb is None:
            smb = self._new_smb()
            self._local.smb = smb
            with self._lock:
                self._threads.append(smb)
        return smb

    def _open_registry(self) -> Any:
        """
        Bind the Remote Registry pipe, retrying a not-yet-available pipe.

        ``RemoteRegistry`` is trigger-started on client Windows, so the first
        bind can lose a race with the service's own startup and return
        ``STATUS_PIPE_NOT_AVAILABLE`` while a bind two seconds later succeeds.
        Measured on a real host. **The service is never started by this code.**
        """
        existing = getattr(self._local, "registry", None)
        if existing is not None:
            return existing
        if "registry" in self.unavailable:
            raise SMBConfigurationError(self.unavailable["registry"])

        # Record whether Remote Registry was already running *before* this
        # transport touches it, and do it once per session.
        #
        # This matters because binding ``\winreg`` trigger-starts the service on
        # a host where it is set to start on demand — and this product's own
        # ``ccure.win.remote_registry.not_running`` check treats a running
        # Remote Registry as a finding. Without this the scanner could start the
        # service, then report the host for having it running: a finding the
        # scan itself created. Measuring first is what keeps that answerable.
        if self.remote_registry_was_running is None:
            try:
                state = next(
                    (
                        entry["State"]
                        for entry in self.service_states()
                        if entry["Name"].lower() == "remoteregistry"
                    ),
                    None,
                )
                self.remote_registry_was_running = (
                    None if state is None else state == "Running"
                )
            except Exception:  # noqa: BLE001 — unknown stays unknown
                log.debug("could not read RemoteRegistry state first", exc_info=True)

        last: Optional[Exception] = None
        for _attempt in range(3):
            try:
                rpc = transport.SMBTransport(
                    self.ip, self.port, r"\winreg", smb_connection=self._require_smb()
                )
                dce = rpc.get_dce_rpc()
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)
                self._local.registry = dce
                return dce
            except Exception as exc:  # noqa: BLE001 — retried, then classified
                last = exc
                import time

                time.sleep(1.5)

        reason = (
            "the Remote Registry service is not answering on this host "
            f"({type(last).__name__}). It is stopped by default on Windows "
            "client editions; this scanner does not start it."
        )
        self.unavailable["registry"] = reason
        raise SMBConfigurationError(reason)

    def _open_wmi(self) -> Any:
        """
        Open a WMI session over DCOM against ``root/cimv2``.

        DCOM negotiates a dynamic high port after contacting the endpoint mapper
        on 135, so this fails on a host that permits 445 alone — which is a
        common firewall shape and not an error worth failing the scan over.
        """
        existing = getattr(self._local, "wmi", None)
        if existing is not None:
            return existing
        if "wmi" in self.unavailable:
            raise SMBConfigurationError(self.unavailable["wmi"])

        try:
            dcom = DCOMConnection(
                self.ip,
                self.username,
                self._password or "",
                self.domain,
                "",
                "",
                None,
                oxidResolver=True,
            )
            iface = dcom.CoCreateInstanceEx(
                impacket_wmi.CLSID_WbemLevel1Login, impacket_wmi.IID_IWbemLevel1Login
            )
            login = impacket_wmi.IWbemLevel1Login(iface)
            services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
            self._local.dcom = dcom
            self._local.wmi = services
            return services
        except Exception as exc:  # noqa: BLE001 — recorded, not fatal
            reason = (
                f"WMI over DCOM is not available on this host ({type(exc).__name__}: "
                f"{str(exc)[:160]}). DCOM negotiates a dynamic port after the "
                "endpoint mapper on 135, so a firewall permitting only 445 "
                "blocks it while SMB continues to work."
            )
            self.unavailable["wmi"] = reason
            raise classify_smb_error(exc) from exc

    # ── Native primitives ────────────────────────────────────────────────────

    def wmi_query(self, query: str, limit: int = 5000) -> List[Dict[str, Any]]:
        """
        Run one WQL query and return plain dictionaries.

        ``limit`` is a real bound, not a formality: ``Win32_Process`` returned
        507 rows on an idle workstation and an unbounded enumeration on a busy
        server is both slow and pointless for an inventory.
        """
        services = self._open_wmi()
        if True:
            enumerator = services.ExecQuery(query)
            rows: List[Dict[str, Any]] = []
            try:
                while len(rows) < limit:
                    try:
                        record = enumerator.Next(0xFFFFFFFF, 1)[0]
                    except Exception:  # noqa: BLE001 — normal end of enumeration
                        break
                    raw = record.getProperties()
                    rows.append(
                        {name: entry.get("value") for name, entry in raw.items()}
                    )
            finally:
                try:
                    enumerator.RemRelease()
                except Exception:  # noqa: BLE001 — best effort
                    pass
        return rows

    def read_registry_value(self, hive: str, path: str, name: str) -> Optional[str]:
        """
        Read one registry value. ``None`` means the key or value is absent.

        Absent is returned rather than raised because it is a *reading*: a
        security setting missing from the registry is at its platform default,
        which is a different fact from a registry this scanner could not read.
        The second raises.
        """
        dce = self._open_registry()
        opener = {
            "HKLM": rrp.hOpenLocalMachine,
            "HKEY_LOCAL_MACHINE": rrp.hOpenLocalMachine,
            "HKU": rrp.hOpenUsers,
            "HKEY_USERS": rrp.hOpenUsers,
            "HKCU": rrp.hOpenCurrentUser,
            "HKEY_CURRENT_USER": rrp.hOpenCurrentUser,
        }.get(hive.upper().rstrip(":"))
        if opener is None:
            raise SMBConfigurationError(f"unsupported registry hive {hive!r}")

        root = opener(dce)["phKey"]
        try:
            key = rrp.hBaseRegOpenKey(dce, root, path)["phkResult"]
        except Exception:  # noqa: BLE001 — a missing key is a reading
            return None
        if True:
            try:
                _type, value = rrp.hBaseRegQueryValue(dce, key, name)
                return _s(value)
            except Exception:  # noqa: BLE001 — a missing value is a reading
                return None

    def enumerate_registry_subkeys(self, hive: str, path: str) -> List[str]:
        """Every immediate subkey name, for walking the uninstall hives."""
        dce = self._open_registry()
        opener = rrp.hOpenLocalMachine if hive.upper().startswith("HKLM") else None
        if opener is None:
            raise SMBConfigurationError(f"unsupported registry hive {hive!r}")

        names: List[str] = []
        if True:
            root = opener(dce)["phKey"]
            try:
                key = rrp.hBaseRegOpenKey(dce, root, path)["phkResult"]
            except Exception:  # noqa: BLE001 — absent hive is an empty list
                return []
            index = 0
            while True:
                try:
                    entry = rrp.hBaseRegEnumKey(dce, key, index)
                except Exception:  # noqa: BLE001 — end of enumeration
                    break
                names.append(_s(entry["lpNameOut"]))
                index += 1
        return names

    def list_shares(self) -> List[Dict[str, Any]]:
        """Shares the authenticated session can see."""
        smb = self._require_smb()
        try:
            shares = []
            for entry in smb.listShares():
                # impacket yields ``SHARE_INFO_1`` structures, not dicts: they
                # support ``[]`` but have no ``.get``, and the remark field is
                # absent on some servers rather than empty.
                try:
                    remark = _s(entry["shi1_remark"])
                except Exception:  # noqa: BLE001 — an absent remark is not a fault
                    remark = ""
                shares.append(
                    {"Name": _s(entry["shi1_netname"]), "Description": remark}
                )
            return shares
        except Exception as exc:  # noqa: BLE001
            raise classify_smb_error(exc) from exc

    def server_info(self) -> Dict[str, Any]:
        """What the SMB handshake itself established, before any query."""
        smb = self._require_smb()
        return {
            "server_os": _s(smb.getServerOS()),
            "dns_hostname": _s(smb.getServerDNSHostName()),
            "netbios_name": _s(smb.getServerName()),
            "domain": _s(smb.getServerDomain()),
            "signing_required": bool(smb.isSigningRequired()),
        }

    def query_service(self, name: str) -> Optional[Dict[str, Any]]:
        """
        One service's state and start mode, or ``None`` if it is not installed.

        ``None`` is the answer for "not installed" and an exception is the
        answer for "could not be read". Collapsing those two is how a rule
        saying "the Telnet service must not be running" comes to pass on a host
        nobody could query — the check would read absence as compliance.

        The service name is a rule parameter, so it is bound into the WQL string
        with quotes doubled rather than interpolated raw. Rules are
        administrator-editable; this is an injection boundary inside the
        product, not defensive style.
        """
        safe = str(name).replace("\\", "\\\\").replace('"', '\\"')
        try:
            rows = self.wmi_query(
                "SELECT Name, State, StartMode, PathName, StartName "
                f'FROM Win32_Service WHERE Name = "{safe}"',
                limit=2,
            )
        except SMBError as exc:
            # DCOM unreachable, which is the common shape of a firewall that
            # permits 445 alone — WMI negotiates a dynamic high port after the
            # endpoint mapper on 135. SCMR runs over the SMB session that is
            # already open, so the check still gets a real answer.
            #
            # ``_services`` has had this fallback since the transport was
            # written and this method did not, so on exactly the host the
            # fallback exists for, every service *check* reported ERROR while
            # the service *inventory* succeeded.
            log.debug("WMI service query failed, falling back to SCMR: %s", exc)
            rows = []

        if not rows:
            # Also reached when WMI answers and knows nothing of the name: it
            # omits driver services entirely, so SCMR is consulted before
            # concluding the service is absent.
            for entry in self.service_states():
                if entry["Name"].lower() == str(name).lower():
                    return {
                        "status": entry["State"],
                        # SCMR carries the running state but not the start mode;
                        # empty means "not available from this source", and the
                        # collector renders that as unavailable rather than as a
                        # start mode of "".
                        "start_mode": "",
                        "source": "scmr",
                    }
            return None
        row = rows[0]
        return {
            "status": _s(row.get("State")),
            "start_mode": _s(row.get("StartMode")),
            "path": _s(row.get("PathName")),
            "account": _s(row.get("StartName")),
            "source": "wmi",
        }

    def service_states(self) -> List[Dict[str, Any]]:
        """
        Every service, from the Service Control Manager over ``\\svcctl``.

        The fallback when DCOM is blocked. SCMR sees more than WMI does — 848
        against 360 on the validation host, the difference being driver
        services — but carries less about each one, so WMI leads where it works.
        """
        dce = None
        try:
            rpc = transport.SMBTransport(
                self.ip, self.port, r"\svcctl", smb_connection=self._require_smb()
            )
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            manager = scmr.hROpenSCManagerW(dce)["lpScHandle"]
            states = {1: "Stopped", 2: "StartPending", 3: "StopPending", 4: "Running"}
            return [
                {
                    "Name": _s(entry["lpServiceName"]),
                    "DisplayName": _s(entry["lpDisplayName"]),
                    "State": states.get(
                        entry["ServiceStatus"]["dwCurrentState"], "Unknown"
                    ),
                }
                for entry in scmr.hREnumServicesStatusW(dce, manager)
            ]
        except Exception as exc:  # noqa: BLE001
            raise classify_smb_error(exc) from exc
        finally:
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:  # noqa: BLE001
                    pass

    # ── Named collection — the WindowsCollector seam ─────────────────────────

    def run_named(
        self, key: str, timeout: Optional[int] = None
    ) -> Optional[CommandResult]:
        """
        Answer one of ``WindowsCollector``'s command keys natively.

        Returns ``None`` for a key this transport cannot serve, which tells the
        collector to fall back to running the PowerShell — and on this executor
        that refuses, so the section is recorded as unread rather than as empty.
        The distinction matters: an empty package list and an unreadable one
        look identical in a report that does not keep them apart.

        The JSON returned is shaped exactly as the PowerShell command's output,
        so every parser in ``WindowsCollector`` is untouched. That is what makes
        this a transport rather than a second collector.
        """
        handler = _NATIVE_HANDLERS.get(key)
        if handler is None:
            return None
        try:
            payload = handler(self)
        except SMBError as exc:
            log.debug("SMB native collection of '%s' failed: %s", key, exc)
            return CommandResult(stderr=str(exc), exit_code=1, success=False)
        except Exception as exc:  # noqa: BLE001 — never fails the whole audit
            log.debug("SMB native collection of '%s' raised", key, exc_info=True)
            return CommandResult(stderr=str(exc), exit_code=1, success=False)
        if payload is None:
            return None
        return CommandResult(
            stdout=json.dumps(payload, default=str), exit_code=0, success=True
        )

    @staticmethod
    def test_connectivity(
        ip: str, port: int = DEFAULT_SMB_PORT, timeout: int = 5
    ) -> bool:
        """
        Is anything listening? A TCP probe only — deliberately not an
        authentication attempt, so the resolver can use it before a credential
        has been chosen without generating a failed-logon event.
        """
        import socket

        try:
            with socket.create_connection((ip, int(port)), timeout=timeout):
                return True
        except OSError:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Native handlers, one per WindowsCollector command key.
#
# Each returns the *same shape* the PowerShell command produces, because the
# collector's parsers are the contract. Where a shape cannot be reproduced
# faithfully the handler is simply absent, and the key falls through.
# ─────────────────────────────────────────────────────────────────────────────


def _one(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    return rows[0] if rows else {}


def _os_info(x: SMBExecutor) -> Dict[str, Any]:
    row = _one(
        x.wmi_query(
            "SELECT Caption, Version, BuildNumber, OSArchitecture "
            "FROM Win32_OperatingSystem"
        )
    )
    return {
        "Caption": row.get("Caption") or "",
        "Version": row.get("Version") or "",
        "BuildNumber": row.get("BuildNumber") or "",
        "OSArchitecture": row.get("OSArchitecture") or "",
    }


def _os_revision(x: SMBExecutor) -> Dict[str, Any]:
    """
    The update revision, which decides every Windows patch finding.

    ``Win32_OperatingSystem.Version`` stops at the build and omits the UBR, so
    without this every host looks like the day-zero release of its Windows
    version and every patch since launch reads as missing.
    """
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    return {
        "CurrentBuild": x.read_registry_value("HKLM", path, "CurrentBuild") or "",
        "UBR": x.read_registry_value("HKLM", path, "UBR") or "",
        "DisplayVersion": x.read_registry_value("HKLM", path, "DisplayVersion") or "",
        "ProductName": x.read_registry_value("HKLM", path, "ProductName") or "",
    }


def _computer_system(x: SMBExecutor) -> Dict[str, Any]:
    row = _one(
        x.wmi_query(
            "SELECT Name, DNSHostName, Domain, PartOfDomain, Manufacturer, Model "
            "FROM Win32_ComputerSystem"
        )
    )
    if not row:
        info = x.server_info()
        return {
            "Name": info["netbios_name"],
            "DNSHostName": info["dns_hostname"],
            "Domain": info["domain"],
        }
    return row


def _bios(x: SMBExecutor) -> Dict[str, Any]:
    return _one(x.wmi_query("SELECT SerialNumber, SMBIOSBIOSVersion FROM Win32_BIOS"))


def _cpu(x: SMBExecutor) -> Dict[str, Any]:
    return _one(
        x.wmi_query(
            "SELECT Name, NumberOfCores, NumberOfLogicalProcessors "
            "FROM Win32_Processor"
        )
    )


def _memory(x: SMBExecutor) -> Dict[str, Any]:
    return _one(
        x.wmi_query(
            "SELECT TotalVisibleMemorySize, FreePhysicalMemory "
            "FROM Win32_OperatingSystem"
        )
    )


def _disk(x: SMBExecutor) -> List[Dict[str, Any]]:
    """Shaped as ``Get-PSDrive`` returns it: Name, Used, Free."""
    out = []
    for row in x.wmi_query(
        "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3"
    ):
        size = int(row.get("Size") or 0)
        free = int(row.get("FreeSpace") or 0)
        out.append(
            {
                "Name": _s(row.get("DeviceID")).rstrip(":"),
                "Used": size - free,
                "Free": free,
            }
        )
    return out


_UNINSTALL_X64 = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
_UNINSTALL_X86 = r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"


def _installed_software(x: SMBExecutor, base: str) -> List[Dict[str, Any]]:
    """
    Walk an uninstall hive. This is the package inventory every Windows CVE
    finding is matched from, so it is the single most valuable thing Remote
    Registry provides — WMI's ``Win32_Product`` is not an alternative: it
    triggers an MSI reconfiguration of every installed product, which is a
    write to the host and notoriously slow.
    """
    packages: List[Dict[str, Any]] = []
    for subkey in x.enumerate_registry_subkeys("HKLM", base):
        if not subkey:
            continue
        path = f"{base}\\{subkey}"
        name = x.read_registry_value("HKLM", path, "DisplayName")
        if not name:
            continue
        packages.append(
            {
                "DisplayName": name,
                "DisplayVersion": x.read_registry_value("HKLM", path, "DisplayVersion")
                or "",
                "Publisher": x.read_registry_value("HKLM", path, "Publisher") or "",
            }
        )
    return packages


def _services(x: SMBExecutor) -> List[Dict[str, Any]]:
    """
    Running services, shaped as the PowerShell command returns them.

    WMI leads because it carries ``StartMode`` and ``PathName``, which the
    unquoted-service-path and binary-ACL checks read. SCMR is the fallback when
    DCOM is blocked; it sees more services but knows less about each.
    """
    try:
        rows = x.wmi_query(
            "SELECT Name, DisplayName, State, StartMode, PathName, StartName "
            "FROM Win32_Service"
        )
        return [
            {
                "Name": row.get("Name") or "",
                "DisplayName": row.get("DisplayName") or "",
                "Status": row.get("State") or "",
                "StartType": row.get("StartMode") or "",
                "PathName": row.get("PathName") or "",
                "StartName": row.get("StartName") or "",
            }
            for row in rows
            if str(row.get("State") or "").lower() == "running"
        ]
    except SMBError:
        return [
            {
                "Name": row["Name"],
                "DisplayName": row["DisplayName"],
                "Status": "Running",
            }
            for row in x.service_states()
            if row["State"] == "Running"
        ]


def _local_users(x: SMBExecutor) -> List[Dict[str, Any]]:
    return [
        {
            "Name": row.get("Name") or "",
            "Enabled": not bool(row.get("Disabled")),
            "LastLogon": "",
            "PasswordRequired": bool(row.get("PasswordRequired")),
            "PasswordExpires": not bool(row.get("PasswordExpires") is False),
            "SID": _s(row.get("SID")),
        }
        for row in x.wmi_query(
            "SELECT Name, Disabled, PasswordRequired, PasswordExpires, SID, LocalAccount "
            "FROM Win32_UserAccount WHERE LocalAccount = TRUE"
        )
    ]


def _local_admins(x: SMBExecutor) -> List[Dict[str, Any]]:
    """
    Members of the local Administrators group.

    Selected by the group's **SID**, not its name: S-1-5-32-544 is stable and
    the name is not — a non-English install has no group called
    "Administrators", and matching the name there silently returns nobody.
    """
    rows = x.wmi_query("SELECT Name, SID FROM Win32_Group WHERE LocalAccount = TRUE")
    group = next(
        (r for r in rows if _s(r.get("SID")).endswith("-544")),
        None,
    )
    if not group:
        return []
    name = _s(group.get("Name"))
    members = x.wmi_query(
        "SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent = "
        f'"Win32_Group.Domain=\\"{_s(x.server_info()["netbios_name"])}\\",Name=\\"{name}\\""'
    )
    out = []
    for row in members:
        part = _s(row.get("PartComponent"))
        match = re.search(r'Name="([^"]+)"', part)
        if match:
            out.append({"Name": match.group(1)})
    return out


def _hotfixes(x: SMBExecutor) -> List[Dict[str, Any]]:
    return [
        {
            "HotFixID": row.get("HotFixID") or "",
            "Description": row.get("Description") or "",
            "InstalledOn": _s(row.get("InstalledOn")),
        }
        for row in x.wmi_query(
            "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering"
        )
    ]


def _shares(x: SMBExecutor) -> List[Dict[str, Any]]:
    return x.list_shares()


def _network_iface(x: SMBExecutor) -> List[Dict[str, Any]]:
    return [
        {
            "Description": row.get("Description") or "",
            "IPAddress": list(row.get("IPAddress") or []),
            "MACAddress": _s(row.get("MACAddress")),
            "DefaultIPGateway": list(row.get("DefaultIPGateway") or []),
            "IPSubnet": list(row.get("IPSubnet") or []),
        }
        for row in x.wmi_query(
            "SELECT Description, IPAddress, MACAddress, DefaultIPGateway, IPSubnet "
            "FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"
        )
    ]


def _as_int(raw: Optional[str]) -> Optional[int]:
    """
    A registry DWORD as the number PowerShell would have produced.

    ``read_registry_value`` returns text, because the configuration-audit
    collector compares against the string the WinRM path yields. The posture
    handlers below need the *number*: the collector tests
    ``smb1_raw.get("SMB1", 0) == 1``, and ``"1" == 1`` is False — so a host with
    SMBv1 genuinely enabled read as SMBv1 disabled. A false PASS on a real
    security control, caused entirely by a type.
    """
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _registry_flag(path: str, value: str, key: str):
    """Build a handler that reads one registry value into a named field."""

    def handler(x: SMBExecutor) -> Dict[str, Any]:
        raw = x.read_registry_value("HKLM", path, value)
        return {key: None if raw is None else raw}

    return handler


def _smbv1_status(x: SMBExecutor) -> Dict[str, Any]:
    raw = x.read_registry_value(
        "HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"
    )
    # ``FeatureEnabled`` stays None: it comes from Get-WindowsOptionalFeature,
    # which this transport cannot run. The collector ORs the two, so None
    # contributes nothing rather than asserting the feature is absent.
    return {"SMB1": _as_int(raw), "FeatureEnabled": None}


def _rdp_nla_status(x: SMBExecutor) -> Dict[str, Any]:
    raw = x.read_registry_value(
        "HKLM",
        r"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication",
    )
    return {"UserAuthentication": _as_int(raw)}


def _rdp_status(x: SMBExecutor) -> Dict[str, Any]:
    raw = x.read_registry_value(
        "HKLM",
        r"System\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
    )
    return {"fDenyTSConnections": _as_int(raw)}


#: Command key → native handler. A key absent from this map falls through to the
#: PowerShell path, which this executor refuses — so the section is recorded as
#: unread rather than as empty. That is deliberate: an inventory that could not
#: be read and one that is genuinely empty must not look the same.
_NATIVE_HANDLERS: Dict[str, Callable[[SMBExecutor], Any]] = {
    "os_info": _os_info,
    "os_revision": _os_revision,
    "computer_system": _computer_system,
    "bios": _bios,
    "cpu": _cpu,
    "memory": _memory,
    "disk": _disk,
    "software_x64": lambda x: _installed_software(x, _UNINSTALL_X64),
    "software_x86": lambda x: _installed_software(x, _UNINSTALL_X86),
    "services": _services,
    "local_users": _local_users,
    "local_admins": _local_admins,
    "hotfixes": _hotfixes,
    "shares": _shares,
    "network_iface": _network_iface,
    "smbv1_status": _smbv1_status,
    "rdp_nla_status": _rdp_nla_status,
    "rdp_status": _rdp_status,
}

#: Keys this transport cannot serve, with the reason. Reported in coverage so a
#: reader knows what an SMB-transport audit did not look at, rather than being
#: left to infer it from a shorter report.
UNSERVED_KEYS: Dict[str, str] = {
    "open_ports": "needs netstat; no SMB/WMI equivalent",
    "scheduled_tasks": "needs the task scheduler RPC interface, not implemented",
    "failed_logins": "needs the Security event log, not implemented",
    "password_policy": "needs `net accounts`; SAMR equivalent not implemented",
    "audit_policy": "needs `auditpol`, a command-only interface",
    "firewall": "needs the firewall policy COM interface, not implemented",
    "network_config": "needs Get-NetIPConfiguration, a command-only interface",
    "telnet_status": "needs Get-WindowsOptionalFeature, a command-only interface",
    "netbios_status": "needs Get-CimInstance over a command shell",
    "tls_status": "reads several SCHANNEL keys; not implemented",
    "uptime": "derived from WMI LastBootUpTime; not implemented",
    "hostname": "available from the SMB handshake; served by computer_system",
    "privilege_context": "needs a token query in a command shell",
}
