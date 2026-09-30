"""
GET /platform/modules — the products CCure Home shows (Phase 12.1).

Everything in the response comes from the module registry: names, descriptions,
entry addresses and availability, and the vocabulary of availability states, so
the frontend holds no product list and no list of states of its own
(CLAUDE.md, "a vocabulary is fetched, not copied").

Every signed-in user receives the same four products. Nothing is filtered by
user or organisation, and a product is never left out because it is not built
yet (owner decision D12-4). The response names no backend route, table or task.

Record: docs/architecture/PHASE12_FRONTEND_SHELL.md.
"""

from __future__ import annotations

from ccure_platform.api import CurrentUser, current_user
from ccure_platform.modules import TILE_STATES, products
from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/platform", tags=["Platform"])


class PlatformProduct(BaseModel):
    key: str
    title: str
    #: ``core_module`` (hosted by the core service) or ``service`` (a separate
    #: service the platform lists, such as CCure IR).
    kind: str
    description: str
    entry_path: str
    tile_state: str


class PlatformProductList(BaseModel):
    #: The availability states a product can be in, so a client renders a state
    #: it does not recognise as unknown rather than guessing.
    tile_states: list[str]
    modules: list[PlatformProduct]


@router.get("/modules", response_model=PlatformProductList)
def list_platform_modules(
    _user: CurrentUser = Depends(current_user),
) -> PlatformProductList:
    """
    List the CCure products for the signed-in user's home page.

    Returns every product — CCure Policy Pro, CCure Audit, CCure Rank and
    CCure IR — in display order, each with its name, a description of what it is
    responsible for, the frontend address its card opens, and its availability
    (`tile_state`). `tile_states` lists every availability state. The list is the
    same for every signed-in user.
    """
    return PlatformProductList(
        tile_states=list(TILE_STATES),
        modules=[
            PlatformProduct(
                key=p.key,
                title=p.title,
                kind=p.kind,
                description=p.description,
                entry_path=p.entry_path,
                tile_state=p.tile_state,
            )
            for p in products()
        ],
    )
