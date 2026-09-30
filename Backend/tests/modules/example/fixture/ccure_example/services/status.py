"""A service the route calls — the layering a real module uses."""


def module_status() -> dict:
    return {"module": "example", "status": "ok"}
