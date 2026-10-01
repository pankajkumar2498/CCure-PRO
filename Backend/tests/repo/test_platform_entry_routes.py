"""
Phase 12.2 — the registry's availability agrees with the frontend's routes.

A product the registry calls ``available`` must have a page at its
``entry_path`` in this build, or CCure Home would offer "Open dashboard" onto a
page that does not exist (docs/architecture/PHASE12_FRONTEND_SHELL.md §3.5). The
other direction matters too: a product called ``not_yet_available`` must *not*
have a static route there, because a static route outranks the registry-driven
module page, so a team's half-built page would be reachable while every card and
the endpoint still said the product was not available.

The frontend is not mounted into the API container, so these skip there and run
on a full checkout (CI), like the gateway checks beside them.
"""

from __future__ import annotations

import re

import pytest

from ccure_platform.modules import products
from testpaths import REPO_ROOT

APP_JSX = REPO_ROOT / "Frontend" / "src" / "App.jsx"
_PATH_ATTR = re.compile(r'\bpath="([^"]+)"')


@pytest.fixture(scope="module")
def route_paths() -> set[str]:
    if not APP_JSX.is_file():
        pytest.skip(f"Frontend/src/App.jsx is not reachable from {REPO_ROOT}")
    return set(_PATH_ATTR.findall(APP_JSX.read_text(encoding="utf-8")))


def test_the_route_table_was_read(route_paths):
    # A regex that silently matched nothing would pass every check below.
    assert {"/", "/login", "/scan", "/assets"} <= route_paths


@pytest.mark.parametrize(
    "product",
    [p for p in products() if p.tile_state == "available"],
    ids=lambda p: p.key,
)
def test_an_available_product_has_a_page_at_its_entry_path(route_paths, product):
    assert product.entry_path in route_paths


@pytest.mark.parametrize(
    "product",
    [p for p in products() if p.tile_state != "available"],
    ids=lambda p: p.key,
)
def test_a_product_not_yet_available_has_no_static_page(route_paths, product):
    assert product.entry_path not in route_paths


def test_the_module_entry_route_and_the_dashboard_redirect_exist(route_paths):
    assert "/:entry" in route_paths
    assert "/dashboard" in route_paths
    assert "/audit-dashboard" in route_paths
