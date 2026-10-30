# Engineering record: Middleware configuration, container and Kubernetes assessment

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 2799–3066, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 2799-3066 -->
## Middleware configuration assessment (`core/config_audit/structured.py`)

Authenticated assessment of nginx, Apache httpd, Tomcat and the Docker daemon's
own configuration. Phase 8 of the gap-closure programme, closing GAP-09;
tracker in [`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine, no new scan kind, no new route.** These are Phase 3
`ConfigCheck` records at `platform = linux|windows`, so they run inside the
credentialed host audit alongside the OS hardening rules — a web server's
configuration is part of the host's posture, not a separate scan. 40 checks.

- **`config_file` could not have been extended to cover this, and that is the
  phase's main engineering.** It reads one directive out of a flat
  `key<separator>value` file. All four products keep their settings inside a
  structure, and there was no XML or JSON reading anywhere in
  `core/config_audit/`. The failure a flat reader produces is not "misses the
  setting" — `AllowOverride None` under `<Directory />` and under a document
  root are different statements, and a reader that cannot say which it found
  returns whichever it saw last, confidently.

- **One check type, `structured_config`, with `format` as a parameter.** From
  the engine's point of view nginx, Apache, XML and JSON are one shape: name a
  file and an address, get COLLECTED / ABSENT / UNAVAILABLE. Four check types
  would have been four CHECK-constraint values on a table holding customer
  rules for a distinction the engine cannot act on. Migration `a9b0c1d2e3f4`.

- **Scope is matched exactly, never by suffix.** `scope: None` means any depth,
  `[]` means top level only, `["http","server"]` means that exact path. An
  "ends with" rule would let a directive in `http > server > location` satisfy
  a rule about `http > server`, and telling those apart is the entire reason to
  parse structure.

- **A missing configuration file is UNSUPPORTED, not ABSENT.** A Linux host
  that does not run Apache is not _failing_ Apache's rules. Get this wrong and
  every host in the estate acquires findings about software it does not have,
  which is how a configuration report gets ignored wholesale.

  **The Docker daemon is the deliberate exception** (`missing_file: absent`).
  Most installations have no `daemon.json` at all, and that means every setting
  is at its built-in default — a real state. Those defaults are a mixture, so
  each rule declares what its own absence means: no `hosts` entry is secure
  (PASS), no `icc` entry means inter-container traffic is on (MANUAL_REVIEW,
  because failing it would fire on every Docker host there is).

- **An unresolved include poisons an absence.** nginx and Apache both ship the
  interesting settings in _included_ files, so a directive missing from the
  named file may be somewhere the collector did not look. Incomplete expansion
  makes an absent reading UNAVAILABLE; only a _found_ value is trusted.
  Expansion is one level deep, which covers every default layout these products
  ship.

- **Include globs never reach a shell.** They come out of the _target's own
  configuration_, so they are attacker-influenced in a way rule parameters are
  not. Directories are listed and matched with `fnmatch` in Python; a glob
  handed to a shell for expansion would be command execution on the target
  during an audit.

- **Any DOCTYPE is refused before the XML parser sees it.** ElementTree _does_
  expand internal entities — measured, not assumed — and the XML here comes off
  a host being audited, so an entity bomb in a `server.xml` is a
  denial-of-service route into the scanner. No configuration file assessed here
  carries a DTD, so the ban costs nothing.

### Five things real containers settled, each of which had shipped looking right

- **Included files lost their enclosing scope.** nginx ships `server` blocks in
  `conf.d/*.conf`, included from inside `http`; parsed alone they scope as
  `server`, so every rule about `http > server` found nothing and reported it
  as not configured. `rescope()` grafts a child onto the branch its `include`
  sat on.
- **Apache resolves a relative `Include` against `ServerRoot`**, not the config
  file's directory. Assuming the latter left the include unexpanded, which
  downgraded _every_ absent directive in the file to "could not assess". The
  collector reads `ServerRoot` out of the configuration itself.
- **A default XML namespace made every Tomcat selection return nothing.**
  Tomcat 10 declares `xmlns` on `tomcat-users.xml`, so a plain `.//user`
  matches nothing — the parse succeeds, the selection is empty, the collector
  reports ABSENT and the rule's `AbsencePolicy.PASS` **declares the server
  clean**. Namespaces are stripped on parse; pinning rules to the URI would
  break on the next version, which is the same failure with a longer fuse.
- **`not_contains` on a list is membership, not substring.** `["apache-coyote"]`
  against `['Apache-Coyote/1.1']` found no equal element and passed — a server
  advertising itself, reported clean. Use the scalar path and a regex.
- **`User` is not a top-level Apache directive.** The stock layout puts it
  inside `<IfModule unixd_module>`; a rule pinned to the top level reports
  ABSENT on an entirely normal server.

### Content

**No CIS or STIG content, and none may be added from memory** — same position
as Phases 4 and 7. These are CCURE-authored rules written from vendor
documentation, and every directive was read off a live container before its
rule was written.

**Nothing here duplicates GAP-06.** Missing security headers, dangerous HTTP
methods, directory listing, banner version disclosure, cookie flags and TLS
endpoint assessment are observed over the wire and validated there.
`test_no_rule_duplicates_a_check_gap06_already_makes` enforces the boundary in
code. GAP-06 answers "what does this server _show_ an anonymous client";
GAP-09 answers "what does its configuration _say_".

**A directive missing from a config file means the compiled-in default**, and
those differ between builds and distributions — so those rules are
MANUAL_REVIEW, following the Phase 3 `sshd_config` precedent. Each one must
name the vendor default in its description, which a test enforces, so the
reviewer settles it in one step instead of going to look it up.

### Test targets

Disposable containers, destroyed after use:

```powershell
docker run -d --name ccure-nginx-target   nginx:1.27-alpine
docker run -d --name ccure-httpd-target   httpd:2.4
docker run -d --name ccure-tomcat-target  tomcat:10.1-jdk17
docker run -d --name ccure-dockerd-target --privileged docker:27-dind
```

Measured weak → hardened: nginx **11 → 0**, Apache **8 → 0**, Tomcat
**10 → 0**, Docker **10 → 0**. A run returning zero against a _weakened_
target is a regression, not a clean server.

Two things worth knowing about the stock images:

- **Tomcat's official image is already hardened on two checks.** `webapps/` is
  empty (the bundled applications live in `webapps.dist/`) and
  `tomcat-users.xml` defines no users, so proving those checks _fire_ needs the
  applications copied back deliberately.
- **`shutdown="SHUTDOWN"` on `<Server>` is a real finding on a stock Tomcat.**
  It is what the image ships and what Tomcat's own documentation tells you to
  change; anyone who can reach port 8005 and send that word stops the server.

### Coverage

`scripts/measure_middleware_coverage.py`, denominator frozen at 36 areas before
implementation and including **twelve areas this build does not implement** —
six of them IIS, which needs a Windows Server target that is not available
here. **~3% → 66.7%** (24/36), implemented _and_ tested. Product breadth is
reported separately and never folded in.

## Container and Kubernetes assessment (`core/config_audit/containers.py`)

Authenticated assessment of what a container runtime is _running_ and what a
Kubernetes cluster _allows_. Phase 9 of the gap-closure programme, closing
GAP-17; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine, no new scan kind, no new route.** 24 checks at
`platform = linux`, running inside the credentialed host audit — a container
runtime is assessed over the _host's_ session.

- **The Docker daemon configuration belongs to GAP-09, not here.**
  `daemon.json`, the TCP socket, `icc`, `userns-remap`, insecure registries and
  the log driver are ten checks built and validated in Phase 8. GAP-17 is about
  what the daemon is _running_. Two tests enforce the boundary in code, because
  counting them twice would have inflated this phase by a quarter.

- **`container` is its own check type, for the Phase 5 reason.**
  `structured_config` reads a document and addresses a value; this enumerates
  live state and filters it. The rule names a probe, the command is fixed in
  code, and the filtering happens **in Python** — putting a pipeline of
  `docker inspect` text-munging into administrator-editable rule data is what
  Phase 5 refused for service-ACL enumeration. Migration `b0c1d2e3f4a5`.

- **The reserved `container` platform is deliberately unused.** These rules
  target `linux`. That reservation describes a container as a target in its own
  right, which is a different idea.

- **Two exit statuses where one would have done, and this is the phase's main
  design decision.** `97` = the tool is not installed → UNSUPPORTED →
  NOT_APPLICABLE. `96` = installed but not answering → UNAVAILABLE → ERROR.

  This differs deliberately from Phases 3 and 5, where exit 97 is an _error_.
  Every Linux host has SUID binaries, so failing to list them is a gap; **most
  hosts run no Kubernetes**, so not finding it is an answer. Treating it as an
  error would hand every host in an estate eight findings-shaped errors about
  software it does not have.

  The second status is what keeps that safe: the probes require `docker info`
  and `kubectl version` to _succeed_, not merely that a binary exists, because
  `docker ps` against an unreachable daemon returns an empty container list
  byte-identical to a clean host.

- **`structured_config` gained `yaml` and `toml` rather than a new collector.**
  kubelet configuration is YAML, containerd's is TOML, and all three mapping
  formats parse to the same Python shapes — so `navigate()` is one
  implementation, not three. `tomllib` is stdlib from 3.11; **PyYAML is
  declared explicitly** in `requirements.txt` even though it arrives
  transitively via bandit and pre-commit, which are _development_ tooling. That
  is the dnspython trap: the import is reached at scan time.

- **Only `yaml.safe_load` is ever called.** The full loader constructs
  arbitrary Python objects from tags such as `!!python/object/apply`, which is
  remote code execution in the scanner reading a file off a host it audits —
  the same threat the XML DOCTYPE ban addresses, one format over.

- **A dotted pointer cannot address containerd's keys.**
  `[plugins."io.containerd.grpc.v1.cri"]` parses to a key literally _named_
  `io.containerd.grpc.v1.cri`; splitting on dots yields five segments matching
  nothing, and "matches nothing" is ABSENT, which for these rules means "at the
  product default". `navigate()` therefore accepts a **list** of segments, and
  the collector must pass it through without `str()` — see below.

### Three things real targets settled

- **`str(pointer)` silently defeated list pointers.** `_from_mapping` called
  `str()` on the address, turning `["plugins", "io.containerd…"]` into its repr,
  which then split on dots into nothing. containerd reported **clean however it
  was configured**. Found only because a deliberately weakened `config.toml`
  failed to produce the finding it should have.
- **`cluster-admin` was reported on every cluster.** The wildcard-role probe
  excluded roles named `system:*`, but `cluster-admin` is not one and is _the_
  role that legitimately holds `*` on `*`. The filter is now the
  `kubernetes.io/bootstrapping: rbac-defaults` label, which 65 of the 69
  ClusterRoles on a stock k3s carry.
- **Kubernetes' own components are legitimately privileged.** kube-proxy runs
  privileged and CNI pods share the host network, so the workload probes skip
  `kube-system`, `kube-public` and `kube-node-lease`. Without that, every
  cluster produces a page of findings.

### Content

**No CIS Benchmark content** — same licensing position as Phases 4, 7 and 8.
These are CCURE-authored rules written from vendor documentation, and every
probe was run against a live Docker host and a live k3s cluster before its rule
was written.

**Image scanning, registry scanning and managed-cloud Kubernetes are out of the
denominator entirely**, not merely unimplemented. They are a different product
shape needing a Trivy/Grype-class toolchain and cloud credentials.

### Test targets

Disposable containers, destroyed after use:

```powershell
docker run -d --name ccure-ctr-target --privileged docker:27-dind
docker run -d --name ccure-k3s-target --privileged -e K3S_KUBECONFIG_MODE=644 `
  rancher/k3s:v1.31.4-k3s1 server --disable=traefik --disable=metrics-server
```

Measured weak → hardened: Docker **9 → 0**, Kubernetes **7 → 0**, kubelet
**4 → 0**, containerd **1 → 0**. The hardened Docker run keeps one deliberately
well-configured container running (`--user 1000 --read-only --security-opt
no-new-privileges --cap-drop ALL`), so a clean result proves the probes stay
silent on a real container rather than on an empty host.

Three things worth knowing:

- **k3s bundles `kubectl` at `/bin/kubectl`.** `k3s kubectl` is not a valid
  invocation _inside_ the image; the guard tries `kubectl` first for that
  reason.
- **k3s does not use a kubelet configuration file** — it passes flags. The
  kubelet rules therefore report NOT_APPLICABLE against it and were validated
  against a kubeadm-shaped `config.yaml` written to the kubeadm path. That
  proves the rule, path, parser and verdict; it does not prove a kubeadm
  kubelet reads the file as assumed.
- **k3s's containerd config lives at
  `/var/lib/rancher/k3s/agent/etc/containerd/config.toml`**, not `/etc`.

### Coverage

`scripts/measure_container_coverage.py`, denominator frozen at 42 areas before
implementation and including **eighteen areas this build does not implement** —
five of them the Kubernetes control plane, which needs a kubeadm-style static
manifest that k3s does not have. **~4% → 57.1%** (24/42), implemented _and_
tested. Runtime breadth is reported separately and never folded in.

<!-- /verbatim -->
