"""
Phase 10.1 — dump the live application's route table with its authentication
class, response kind and registered rate limit, as JSON on stdout.

Run inside the api container (read-only; imports the app, touches nothing):

    docker exec -i -w /app ccure-api python - < scripts/gateway/characterization/route_table.py
"""
import inspect
import json
import logging
import sys

logging.disable(logging.CRITICAL)
sys.path.insert(0, "/app")

from fastapi.routing import APIRoute, APIWebSocketRoute  # noqa: E402
from main import app  # noqa: E402
from scan_helpers import limiter  # noqa: E402

FLEXIBLE = "get_current_user_flexible"
BEARER = ("get_current_user", "get_current_auth_context")
SERVICE = ("require_service_scope", "service_principal_for")


def dep_names(dependant):
    out = set()
    for d in dependant.dependencies:
        out.add(getattr(d.call, "__qualname__", getattr(d.call, "__name__", repr(d.call))))
        out |= dep_names(d)
    return out


def limits_for(endpoint):
    key = f"{endpoint.__module__}.{endpoint.__name__}"
    return [str(lim.limit) for lim in limiter._route_limits.get(key, [])]


rows = []
for r in app.routes:
    if isinstance(r, APIRoute):
        deps = dep_names(r.dependant)
        if any(FLEXIBLE in d for d in deps):
            auth = "ticket_or_bearer"
        elif any(any(s in d for s in SERVICE) for d in deps):
            auth = "service"
        elif any(any(b in d for b in BEARER) for d in deps):
            auth = "bearer"
        else:
            auth = "public"
        try:
            src = inspect.getsource(r.endpoint)
        except (OSError, TypeError):
            src = ""
        if "text/event-stream" in src:
            kind = "sse"
        elif "FileResponse" in src:
            kind = "file"
        elif "StreamingResponse" in src:
            kind = "stream"
        else:
            kind = "json"
        guards = sorted({d.split(".")[0] for d in deps if d.startswith(("require_", "current_user"))})
        for m in sorted(r.methods - {"HEAD"}):
            rows.append({"method": m, "path": r.path, "auth": auth, "response_kind": kind,
                         "guards": guards, "limits": limits_for(r.endpoint),
                         "endpoint": f"{r.endpoint.__module__}.{r.endpoint.__name__}"})
    elif isinstance(r, APIWebSocketRoute):
        rows.append({"method": "WS", "path": r.path, "auth": "ws_ticket", "response_kind": "websocket",
                     "guards": [], "limits": [],
                     "endpoint": f"{r.endpoint.__module__}.{r.endpoint.__name__}"})
print(json.dumps(rows))
