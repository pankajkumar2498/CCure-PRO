"""A route, mounted by the platform under the module's prefix (/example)."""

from fastapi import APIRouter

from ccure_example.services.status import module_status

router = APIRouter(tags=["example (test-only proof module)"])


@router.get("/ping")
def ping() -> dict:
    return module_status()
