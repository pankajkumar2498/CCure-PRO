"""Scoped development artifacts and broker messages; no global deletion."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifacts(reports_root, evidence_root, manifest, *, disposable):
    result = []
    for kind, value in (("reports", reports_root), ("evidence", evidence_root)):
        root = Path(value).absolute()
        if root.is_symlink() or root.resolve() != root:
            raise ValueError("artifact roots must be real absolute directories")
        if disposable and not root.is_relative_to(Path("/tmp")):
            raise ValueError("disposable rehearsals require artifact copies under /tmp")
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or path.resolve() != path.absolute():
                raise ValueError("an artifact path contains a symlink")
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if kind == "evidence":
                owned = len(relative.parts) > 1 and bool(
                    re.fullmatch(r"org_[A-Za-z0-9_.-]+", relative.parts[0])
                )
            else:
                owned = (
                    path.name.startswith(tuple(manifest["artifact_report_prefixes"]))
                    and path.suffix in manifest["artifact_report_extensions"]
                )
            if (
                kind == "reports"
                and len(relative.parts) == 3
                and relative.parts[0] == "web_evidence"
            ):
                scan_dir = relative.parts[1]
                owned = (
                    path.name.startswith("xss_")
                    and path.suffix == ".png"
                    and (
                        bool(re.fullmatch(r"wsc_[a-z0-9_]+", scan_dir))
                        or scan_dir
                        in manifest.get("artifact_web_evidence_legacy_directories", ())
                    )
                )
            if owned:
                result.append(
                    {
                        "kind": kind,
                        "root": str(root),
                        "relative": str(relative),
                        "size": path.stat().st_size,
                        "sha256": file_hash(path),
                    }
                )
    return result


def quarantine(files, destination):
    root = Path(destination).absolute()
    if root.resolve() != root or root.is_symlink():
        raise ValueError("artifact recovery path must not contain symlinks")
    if root.exists() and any(root.iterdir()):
        raise ValueError("artifact recovery directory must be empty")
    moved = []
    try:
        for item in files:
            relative = Path(item["relative"])
            if (
                item["kind"] not in {"reports", "evidence"}
                or relative.is_absolute()
                or ".." in relative.parts
            ):
                raise ValueError("artifact recovery path escapes its root")
            source = Path(item["root"]) / item["relative"]
            if (
                source.resolve() != source.absolute()
                or not source.is_file()
                or file_hash(source) != item["sha256"]
            ):
                raise ValueError("artifact changed since the reviewed plan")
            target = root / item["kind"] / item["relative"]
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
            moved.append((source, target))
        return moved
    except Exception:
        restore(moved)
        raise


def restore(moved):
    for source, target in reversed(moved):
        source.parent.mkdir(parents=True, exist_ok=True)
        os.replace(target, source)


def message_owner(raw, owners):
    """Only remove a JSON task whose arguments name a reset owner or scan."""
    try:
        message = json.loads(raw)
        # Unacked entries wrap the message with exchange and routing key.
        if isinstance(message, list):
            message = message[0]
        body = message.get("body")
        if isinstance(body, str):
            body = json.loads(base64.b64decode(body))

        def values(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for child in value.values():
                    yield from values(child)
            elif isinstance(value, list):
                for child in value:
                    yield from values(child)

        if set(values(body)) & set(owners):
            return message.get("headers", {}).get("id") or "owned"
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        pass
    return None


def broker_plan(redis, manifest, owners, task_ids):
    queued, unacked = [], []
    tasks = set(task_ids)
    for queue in manifest["broker_queues"]:
        for key in sorted(redis.scan_iter(match=queue + "*")):
            name = key.decode() if isinstance(key, bytes) else key
            if name != queue and not name.startswith(queue + "\x06\x16"):
                continue
            if redis.type(key) not in (b"list", "list"):
                continue
            for raw in redis.lrange(key, 0, -1):
                task = message_owner(raw, owners)
                if task:
                    queued.append(
                        {
                            "queue": name,
                            "message": raw.decode() if isinstance(raw, bytes) else raw,
                        }
                    )
                    tasks.add(task)
    for tag, raw in redis.hgetall("unacked").items():
        task = message_owner(raw, owners)
        if task:
            unacked.append(
                {
                    "tag": tag.decode() if isinstance(tag, bytes) else tag,
                    "message": raw.decode() if isinstance(raw, bytes) else raw,
                }
            )
            tasks.add(task)
    keys = []
    # Completed task results can outlive their scan's current_task_id. Only
    # an exact owner/scan identifier in structured result data proves ownership.
    for key in redis.scan_iter(match="celery-task-meta-*"):
        if redis.type(key) not in (b"string", "string"):
            continue
        try:
            result = json.loads(redis.get(key)).get("result")
            owned_result = message_owner(json.dumps({"body": result}), owners)
        except (ValueError, TypeError, AttributeError):
            owned_result = None
        if owned_result:
            keys.append(key.decode() if isinstance(key, bytes) else key)
    for task in sorted(tasks - {"owned"}):
        key = "celery-task-meta-" + task
        if redis.exists(key):
            keys.append(key)
    # Scan progress is PostgreSQL-backed; scan_progress:* is a pub/sub
    # channel, not an owned Redis key. Do not guess key prefixes.
    return {"queued": queued, "unacked": unacked, "keys": sorted(set(keys))}


def clean_broker(redis, plan):
    """Remove exact reviewed messages and keys, retaining unrelated entries."""
    with redis.pipeline(transaction=True) as pipe:
        for item in plan["queued"]:
            pipe.lrem(item["queue"], 1, item["message"])
        for item in plan["unacked"]:
            pipe.hdel("unacked", item["tag"])
            pipe.zrem("unacked_index", item["tag"])
        if plan["keys"]:
            pipe.delete(*plan["keys"])
        pipe.execute()
