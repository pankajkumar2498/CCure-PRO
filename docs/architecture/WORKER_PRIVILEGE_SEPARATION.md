# Worker privilege separation — current mapping and proposed split (S3)

|               |                                                                                                                                                                   |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Date**      | 16 Oct 2026                                                                                                                                                       |
| **Status**    | **Proposal, awaiting approval. Nothing in the deployment has changed.** The release compose files, the running containers and `docker-compose.yml` are untouched. |
| **Finding**   | S3 in [`MODULE_INDEPENDENCE_ANALYSIS.md`](MODULE_INDEPENDENCE_ANALYSIS.md) §14                                                                                    |
| **Pinned by** | `Backend/tests/repo/test_worker_queue_mapping.py` — every task's queue and every worker's queues, as they are today                                               |

## 1. The finding

The `worker` service consumes three queues with one set of privileges:

```
command: celery … worker --queues=scanner,default,compliance
user: root · network_mode: host · cap_add: NET_ADMIN, NET_RAW
```

Raw sockets and the host's own network interface are what network discovery needs: ARP is
layer 2 and does not cross the bridge's NAT, and nmap's file capabilities need `NET_ADMIN` in
the container's bounding set (the compose file explains both). The `default` and `compliance`
queues need neither. Because they share the container, platform mail, account purges,
outbound email-risk lookups, audit-log retention, compliance evaluation and compliance
remediation all run as root on the host network with raw sockets. The container also holds
the SMTP credentials, which no scanning task uses.

## 2. Current mapping (measured from source, 16 Oct 2026)

Queues come from each task's decorator. There are no `task_routes`, no `apply_async(queue=…)`
and no `send_task` anywhere in the application, so a task's queue is fixed by its definition.

| Queue        | Consumer (compose) | Tasks                                                                                                                                                                                                                                                                                                                              | Needs raw sockets / host network                                                                                                                                                               |
| ------------ | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scanner`    | `worker`           | `run_host_discovery`, `run_asset_discovery`, `run_vulnerability_audit`, `run_topology_mapping`, `run_traditional_scan`, `run_credentialed_scan`, `sync_host_discovery_task`, `sync_asset_discovery_task`, `sync_vulnerability_audit_task`, `run_due_scan_schedules`, `reconcile_amt_inventory_task`                                | **Yes** for discovery and port scanning (Scapy ARP/ICMP, nmap SYN and OS detection). The credentialed scan, schedule dispatch and AMT reconciliation do not, and stay here (no move proposed). |
| `default`    | `worker`           | 5 mail tasks; `enrich_email_risk`, `retro_scan_email_risk`, `sync_disposable_domains`; `purge_stale_unapproved_accounts`, `purge_stale_unverified_accounts`, `purge_expired_refresh_sessions`; `purge_expired_audit_logs`; `expire_risk_acceptances`; `update_mac_vendor_registry`; `reap_stalled_scans`, `reap_stalled_web_scans` | **No.** Database work plus outbound SMTP, DNS/RDAP and HTTPS.                                                                                                                                  |
| `compliance` | `worker`           | `compliance.run_scan`, `run_scheduled_scans`, `run_remediation`, `run_reverify`, `prune_remediation_logs`                                                                                                                                                                                                                          | **No.** Database work; remediation opens an SSH session and re-verification TCP probes, both ordinary outbound TCP.                                                                            |
| `web_*` (4)  | `web-worker`       | `ccure.web.run_recon`, `run_crawl`, `run_detect`, `run_audit`                                                                                                                                                                                                                                                                      | No — already a separate, unprivileged, bridge-networked worker that sends active traffic to targets.                                                                                           |

Beat publishes 11 schedules; every one names a task above.

## 3. Proposed split

Add one service and narrow one. Same image, same task names, same queues, same beat.

| Service            | Queues                  | User    | Network                      | Capabilities           | Secrets it needs                                                                        |
| ------------------ | ----------------------- | ------- | ---------------------------- | ---------------------- | --------------------------------------------------------------------------------------- |
| `worker`           | `scanner`               | root    | host                         | `NET_ADMIN`, `NET_RAW` | database, vuln-intel database, `COMPLIANCE_ENCRYPTION_KEY` (credentialed scans decrypt) |
| `ops-worker` (new) | `default`, `compliance` | `ccure` | compose bridge (like `beat`) | none                   | database, vuln-intel database, `COMPLIANCE_ENCRYPTION_KEY` (remediation decrypts), SMTP |

What moves out of the privileged container: the SMTP credentials and every non-scanning task.
`web-worker` already shows the shape works: a bridge-networked container reaching targets
through NAT, under the VM's own address, the same source address a target sees today.

The `ops-worker` definition copies `beat`'s environment (compose DNS names `db` and `redis`,
not loopback) and adds the SMTP variables and `FRONTEND_URL` the mail templates need. It mounts
the one path a moved task reads: `./backups:/backups:ro`. Audit-log retention checks for a
recent dump there before it deletes anything (`AUDIT_RETENTION_BACKUP_DIR`, `/backups` in the
container). No compliance task reads the evidence directory.

## 4. Preconditions to verify before the split

1. **`CELERY_TASK_ALWAYS_EAGER` is false on the live `worker`.** Its compose default is
   `${CELERY_TASK_ALWAYS_EAGER:-True}`. If the deployed value were true, a task the scanner
   worker dispatches would run inline in the privileged container whatever its queue, and the
   split would separate nothing. CLAUDE.md records that this machine sets it false. This
   analysis did not read `.env` to confirm it, because the file holds secrets; the operator
   checks it.
2. **Every target reachable from the host is reachable from the bridge.** The web worker
   proves this for the targets it has scanned. Compliance remediation and re-verification need
   it for SSH and TCP probes.
3. **`ops-worker` concurrency.** The `compliance` and `default` queues currently share
   `SCANNER_WORKER_CONCURRENCY` (20). A smaller value (4, like `web-worker`) is proposed.

## 5. Validation plan (isolated, before any release)

On a throwaway compose project with its own PostgreSQL and Redis, never the live stack:

1. Start `worker` (scanner) and `ops-worker` (default, compliance) from the release image.
2. `celery inspect active_queues`: each queue has exactly one consumer, as in §3.
3. `celery inspect registered`: the task set is unchanged (36 tasks).
4. Dispatch one task per queue by name and confirm which worker executed it.
5. `test_worker_queue_mapping.py` is updated in the same change and passes.
6. Beat's schedule is unchanged (11 entries).

## 6. Release and rollback

The VM runs from release directories (`backups/release-*/compose.sh`, CLAUDE.md
"Deployment: Linux VM"), not from this repository's `docker-compose.yml`. The split is a
release:

- update `docker-compose.yml` and the release's compose;
- recreate `worker` and start `ops-worker`, both idle;
- confirm with `celery inspect active_queues`.

**Rollback** is the previous release's compose, where `worker` consumes all three queues again.
No database change is involved.

## 7. Decision requested

D-4 in the analysis: approve the split as described, or amend it. Until then this document is
the record, and the characterisation test keeps the current routing from changing by accident.
