"""
Preference namespacing (backend alignment, follow-up 4).

The platform owns the platform's preferences; Audit owns ``default_scan_type``
and registers its block (``ccure_audit/preferences.py``). These pin that the
platform no longer knows the field, and that every form the API and the stored
document have ever had still works:

* a stored flat ``default_scan_type`` is read as Audit's value, never rewritten
  by a read or by an unrelated update;
* the response still carries the flat key beside the new ``products`` block;
* a ``PUT`` with the flat key (an old client) or with ``products.audit`` (the
  new frontend) is validated by Audit's model and stored in the namespace, the
  flat key it replaces leaving the document in the same write;
* an invalid value is a 422 carrying Audit's own message; an unknown product
  namespace is a 422.

The route functions are called directly with a real session — see the note in
CLAUDE.md on why these tests do not go through ``TestClient`` with a login.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import ccure_audit.preferences  # noqa: F401  (the registration main.py performs)
from ccure_platform import preferences as prefs
from ccure_platform.identity import profile


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "PUT",
            "path": "/user/preferences",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
        }
    )


def _get(user):
    return profile.get_preferences(current_user=user).model_dump()


def _put(db, user, **body):
    req = profile.PreferencesRequest(**body)
    return profile.update_preferences(
        req=req, request=_request(), db=db, current_user=user
    ).model_dump()


def _set(db, user, value):
    user.preferences = value
    db.commit()
    db.refresh(user)


# ── the platform no longer knows the field ───────────────────────────────────


def test_the_platform_schema_does_not_name_the_audit_preference():
    assert "default_scan_type" not in profile.PreferencesRequest.model_fields
    assert "default_scan_type" not in profile.UserPreferencesResponse.model_fields
    assert "default_scan_type" not in prefs.PLATFORM_KEYS


def test_audit_registered_its_block():
    assert "audit" in prefs.registered_namespaces()


# ── reading ──────────────────────────────────────────────────────────────────


def test_a_new_account_gets_the_defaults_in_both_forms(db_session, test_user):
    _set(db_session, test_user, {})
    got = _get(test_user)
    assert got["default_scan_type"] == "asset"
    assert got["products"] == {"audit": {"default_scan_type": "asset"}}
    assert got["theme"] == "light" and got["default_rows_per_page"] == 10


def test_a_stored_flat_value_is_read_as_audits_and_not_rewritten(db_session, test_user):
    stored = {"theme": "dark", "default_scan_type": "credentialed"}
    _set(db_session, test_user, dict(stored))
    got = _get(test_user)
    assert got["default_scan_type"] == "credentialed"
    assert got["products"]["audit"]["default_scan_type"] == "credentialed"
    assert got["theme"] == "dark"
    assert test_user.preferences == stored  # reading changed nothing


def test_the_namespaced_value_wins_over_a_stale_flat_one(db_session, test_user):
    _set(
        db_session,
        test_user,
        {
            "default_scan_type": "asset",
            "products": {"audit": {"default_scan_type": "host-discovery"}},
        },
    )
    got = _get(test_user)
    assert got["default_scan_type"] == "host-discovery"


def test_stored_junk_does_not_leak_into_the_response(db_session, test_user):
    _set(db_session, test_user, {"unrelated": "x", "products": {"nobody": {"a": 1}}})
    got = _get(test_user)
    assert "unrelated" not in got and "nobody" not in got["products"]


# ── writing ──────────────────────────────────────────────────────────────────


def test_an_old_client_sending_the_flat_key_still_works(db_session, test_user):
    _set(db_session, test_user, {"theme": "light", "default_scan_type": "asset"})
    got = _put(db_session, test_user, default_scan_type="vulnerability_audit")
    assert got["default_scan_type"] == "vulnerability_audit"
    assert got["products"]["audit"]["default_scan_type"] == "vulnerability_audit"
    # the value moved into the namespace; the flat key it replaced is gone
    assert "default_scan_type" not in test_user.preferences
    assert test_user.preferences["products"]["audit"] == {
        "default_scan_type": "vulnerability_audit"
    }
    assert test_user.preferences["theme"] == "light"  # nothing else lost


def test_the_new_frontend_sending_the_namespaced_block(db_session, test_user):
    _set(db_session, test_user, {"default_scan_type": "asset"})
    got = _put(
        db_session,
        test_user,
        products={"audit": {"default_scan_type": "credentialed"}},
    )
    assert got["default_scan_type"] == "credentialed"
    assert test_user.preferences["products"]["audit"]["default_scan_type"] == (
        "credentialed"
    )
    assert "default_scan_type" not in test_user.preferences


def test_the_drawer_sending_both_forms_back_lets_the_namespace_win(
    db_session, test_user
):
    _set(db_session, test_user, {"default_scan_type": "asset"})
    got = _put(
        db_session,
        test_user,
        default_scan_type="asset",  # the stale flat value the drawer got
        products={"audit": {"default_scan_type": "host-discovery"}},
    )
    assert got["default_scan_type"] == "host-discovery"


def test_an_unrelated_update_leaves_the_legacy_key_alone(db_session, test_user):
    """No migration happens as a side effect of changing the theme."""
    _set(db_session, test_user, {"default_scan_type": "credentialed"})
    _put(db_session, test_user, theme="dark")
    assert test_user.preferences["default_scan_type"] == "credentialed"
    assert "products" not in test_user.preferences
    assert test_user.preferences["theme"] == "dark"


def test_resending_the_stored_value_changes_nothing(db_session, test_user):
    _set(db_session, test_user, {"default_scan_type": "credentialed"})
    _put(db_session, test_user, default_scan_type="credentialed")
    assert test_user.preferences == {"default_scan_type": "credentialed"}


# ── validation ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        {"default_scan_type": "nonsense"},
        {"products": {"audit": {"default_scan_type": "nonsense"}}},
    ],
)
def test_an_invalid_value_is_a_422_with_audits_own_message(db_session, test_user, body):
    _set(db_session, test_user, {})
    with pytest.raises(HTTPException) as exc:
        _put(db_session, test_user, **body)
    assert exc.value.status_code == 422
    assert "Scan type must be one of" in exc.value.detail[0]["msg"]
    assert test_user.preferences == {}


def test_an_unknown_product_namespace_is_a_422(db_session, test_user):
    _set(db_session, test_user, {})
    with pytest.raises(HTTPException) as exc:
        _put(db_session, test_user, products={"nobody": {"x": 1}})
    assert exc.value.status_code == 422


def test_the_value_set_audit_accepted_is_unchanged():
    from ccure_audit.preferences import SCAN_TYPES

    assert set(SCAN_TYPES) == {
        "host-discovery",
        "asset",
        "vulnerability_audit",
        "advanced",
        "credentialed",
    }


# ── the registration contract ────────────────────────────────────────────────


def test_registration_rules():
    from pydantic import BaseModel

    class Other(BaseModel):
        theme: str = "x"
        thing: str = "y"

    with pytest.raises(ValueError):  # a platform key cannot be a product's flat key
        prefs.register_product_preferences("other", Other, legacy_flat_keys=("theme",))
    with pytest.raises(ValueError):  # not a field of the model
        prefs.register_product_preferences("other", Other, legacy_flat_keys=("nope",))

    class Audit2(BaseModel):
        default_scan_type: str = "asset"

    with pytest.raises(ValueError):  # that flat key is Audit's
        prefs.register_product_preferences(
            "other", Audit2, legacy_flat_keys=("default_scan_type",)
        )

    class NoDefault(BaseModel):
        required: str

    with pytest.raises(Exception):  # every field needs a default
        prefs.register_product_preferences("nodefault", NoDefault)
    assert "other" not in prefs.registered_namespaces()
    assert "nodefault" not in prefs.registered_namespaces()


def test_registering_the_same_block_twice_is_a_no_op():
    from ccure_audit.preferences import AuditPreferences

    prefs.register_product_preferences(
        "audit", AuditPreferences, legacy_flat_keys=("default_scan_type",)
    )
