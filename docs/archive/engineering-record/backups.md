# Engineering record: Backups on the VM

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 1361–1419, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 1361-1419 -->
### Backups on the VM

`scripts/backup_db.sh` and `scripts/install_backup_schedule.sh` are the Linux
twins of the `.ps1` files. The schedule is a **user crontab** — no sudo and no
stored password, because the dump runs the container's own `pg_dump` as the
bootstrap superuser over the Unix socket, where the image's `pg_hba.conf` is
`trust`. The host's `pg_dump` is 16 and refuses an 18 server, and an archive
written by 18 is unreadable by an older `pg_restore`; **every dump,
verification and restore goes through `docker exec ccure-db`.**

    crontab -l                                   # two entries marked `# ccure-db-backup`
    tail backups/backup.log                      # every run logs here
    scripts/backup_db.sh --skip-reference-data   # ad hoc, before risky work

Two tiers, and the second is not optional:

- **Operational dump every 6 h** (`_ops`, 3 s, ~10 MB) — excludes the CVE and
  compliance catalogues.
- **Full dump daily at 02:30** (`_full`, 18 s, ~100 MB) — everything.

**An ops dump cannot be restored on its own.** `asset_vulnerabilities.vuln_id`
is a foreign key into `vulnerability_definitions`, which the ops dump
excludes: the constraint fails at the end of `pg_restore`, and `--clean` into
the live database would first **drop the 370k-row catalogue** the dump does
not carry. Measured 17 Sep 2026 by restoring into a scratch database. Every
6-hourly dump the Windows task had produced since August had this property,
and it went unnoticed because none was ever restored. The full dump is both
the self-contained recovery point and where an ops dump borrows its catalogue.

Both tiers are pushed to the Windows workstation
(`pankaj@10.180.6.30:D:/ccure-backups` — the workstation moved from `.14`; key `~/.ssh/ccure_backup_ed25519`,
expired there after 30 days). A failed push is exit 2 with the local dump
intact — look for `ERROR: remote copy` in the log. The dump itself is written
to a `.part` and renamed only after the matching `pg_restore -l` has listed
its table data, so a half-written file never carries a name the prune or the
push would trust.

**Restoring** — both proven against a scratch database on 17 Sep 2026, 44 s
each, every row count matching. Restore into a fresh database and rename, or
stop the API first; never over `ccure_db` while it is serving.

    docker exec ccure-db psql -U postgres -c 'CREATE DATABASE ccure_db_restored OWNER ccure_user'

    # A. full dump — self-contained
    docker exec -i ccure-db pg_restore -U postgres -d ccure_db_restored --exit-on-error \
        < backups/ccure_db_<stamp>_full.dump

    # B. ops dump — three sections, catalogue borrowed from the newest full dump
    docker exec -i ccure-db pg_restore -U postgres -d ccure_db_restored --exit-on-error \
        --section=pre-data --section=data < backups/ccure_db_<stamp>_ops.dump
    docker exec -i ccure-db pg_restore -U postgres -d ccure_db_restored --exit-on-error --data-only \
        -t vulnerability_definitions -t compliance_controls -t compliance_rules \
        -t compliance_rule_controls -t compliance_policy_rules < backups/ccure_db_<stamp>_full.dump
    docker exec -i ccure-db pg_restore -U postgres -d ccure_db_restored --exit-on-error \
        --section=post-data < backups/ccure_db_<stamp>_ops.dump

`archive_mode` is still `off`, so recovery granularity is "since the last
dump": up to six hours of operational data.

<!-- /verbatim -->
