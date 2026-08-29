"""
tests/security/test_config_audit_api.py
─────────────────────────────────────────────────────────────────────────────
The configuration audit's read surface: authorisation, the catalogue, and the
capability report.

``/config-audit/capabilities`` is the one worth explaining. ``check_type``
admits ``api`` and ``database_query``, and ``target_platform`` admits
``database`` and ``container``, ahead of the phases that implement them — so a
rule can be authored today that nothing in this build can execute. The engine
reports that as an error rather than skipping it, which is correct but only
visible after a scan has run. This endpoint answers it beforehand, and it is
read from the live collector registry so it cannot drift from what the product
can actually do.
"""


def _get(client, path, headers, **params):
    return client.get(path, headers=headers, params=params or None)


class TestAuthorisation:
    def test_the_catalogue_requires_authentication(self, client):
        for path in (
            "/config-audit/checks",
            "/config-audit/capabilities",
            "/config-audit/checks/ccure.win.uac.enabled",
        ):
            assert client.get(path).status_code in (401, 403), path

    def test_validate_requires_authentication(self, client):
        assert client.post("/config-audit/validate", json={}).status_code in (401, 403)

    def test_an_authenticated_user_with_scans_read_may_list(self, client, auth_headers):
        assert _get(client, "/config-audit/checks", auth_headers).status_code == 200


class TestTheCheckCatalogue:
    def test_it_lists_the_builtin_checks(self, client, auth_headers):
        from core.config_audit.builtin import BUILTIN_CHECKS

        body = _get(client, "/config-audit/checks", auth_headers).json()
        assert len(body) == len(BUILTIN_CHECKS)

    def test_platform_filtering_uses_the_checks_own_targeting(
        self, client, auth_headers
    ):
        windows = _get(
            client, "/config-audit/checks", auth_headers, platform="windows"
        ).json()
        linux = _get(
            client, "/config-audit/checks", auth_headers, platform="linux"
        ).json()
        assert windows and linux
        assert all("windows" in c["platforms"] for c in windows)
        assert not {c["check_id"] for c in windows} & {c["check_id"] for c in linux}

    def test_check_type_and_domain_filters(self, client, auth_headers):
        registry = _get(
            client, "/config-audit/checks", auth_headers, check_type="registry"
        ).json()
        assert registry
        assert all(c["check_type"] == "registry" for c in registry)

    def test_each_entry_carries_what_a_reviewer_needs(self, client, auth_headers):
        body = _get(client, "/config-audit/checks", auth_headers).json()
        entry = next(c for c in body if c["check_id"] == "ccure.win.uac.enabled")
        assert entry["expected"]
        assert entry["remediation"]
        assert entry["rationale"]
        # The field a reviewer most often needs to understand a manual_review.
        assert entry["absent_policy"] == "manual_review"

    def test_one_check_can_be_fetched_by_id(self, client, auth_headers):
        response = _get(
            client, "/config-audit/checks/ccure.linux.shadow.permissions", auth_headers
        )
        assert response.status_code == 200
        assert response.json()["severity"] == "critical"

    def test_an_unknown_check_is_404(self, client, auth_headers):
        assert (
            _get(client, "/config-audit/checks/nope", auth_headers).status_code == 404
        )


class TestTheCapabilityReport:
    def test_it_names_the_check_types_that_have_a_collector(self, client, auth_headers):
        body = _get(client, "/config-audit/capabilities", auth_headers).json()
        assert "registry" in body["supported"]["windows"]
        assert "registry" not in body["supported"]["linux"]
        assert {"file", "service", "package", "port"} <= set(body["supported"]["linux"])

    def test_it_names_declared_types_that_nothing_implements_yet(
        self, client, auth_headers
    ):
        """
        ``api`` is reserved for a later phase so it needs no CHECK migration on
        a table holding customer rules. Saying so here is what stops a rule
        author discovering it after a scan.

        ``database_query`` was on this list until Phase 7 (GAP-10) gave it a
        collector. That it dropped off is the point of reading the live
        registry: the endpoint reports what this build can do, not what a
        hand-maintained list says it can.
        """
        body = _get(client, "/config-audit/capabilities", auth_headers).json()
        assert set(body["declared_without_collector"]) == {"api"}
        assert "database_query" in body["supported"]["database"]

    def test_it_is_read_from_the_live_registry(self, client, auth_headers):
        from core.config_audit import collector_registry

        body = _get(client, "/config-audit/capabilities", auth_headers).json()
        assert body["supported"]["windows"] == collector_registry.supported_check_types(
            "windows"
        )

    def test_it_publishes_the_operator_and_absence_vocabularies(
        self, client, auth_headers
    ):
        body = _get(client, "/config-audit/capabilities", auth_headers).json()
        assert "between" in body["operators"]
        assert set(body["absence_policies"]) == {
            "pass",
            "fail",
            "not_applicable",
            "manual_review",
        }


class TestRuleValidation:
    def _validate(self, client, headers, **overrides):
        body = {
            "check_id": "test.rule",
            "title": "A rule",
            "check_type": "registry",
            "platforms": ["windows"],
            "collect": {"path": "HKLM\\SOFTWARE\\X", "value": "V"},
            "operator": "equals",
            "expected": 1,
            "absent": "manual_review",
        }
        body.update(overrides)
        return client.post("/config-audit/validate", headers=headers, json=body)

    def test_a_well_formed_rule_validates_and_returns_its_stored_shape(
        self, client, auth_headers
    ):
        body = self._validate(client, auth_headers).json()
        assert body["valid"] is True
        assert body["errors"] == []
        assert body["check_definition"]["config_check"] is True
        assert body["check_definition"]["absent"] == "manual_review"

    def test_an_invalid_rule_answers_200_with_the_reasons(self, client, auth_headers):
        """
        The caller asked whether the rule is valid. The errors are the answer
        to that question, not a fault in the request.
        """
        response = self._validate(client, auth_headers, operator="grater_than")
        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is False
        assert any("operator" in e for e in body["errors"])
        assert body["check_definition"] is None

    def test_a_missing_absence_policy_is_an_error(self, client, auth_headers):
        body = self._validate(client, auth_headers, absent="").json()
        assert body["valid"] is False

    def test_an_uncompilable_pattern_is_reported(self, client, auth_headers):
        body = self._validate(
            client, auth_headers, operator="matches", expected="(unclosed"
        ).json()
        assert body["valid"] is False
        assert any("regular expression" in e for e in body["errors"])

    def test_a_rule_for_an_unimplemented_platform_warns_but_stays_valid(
        self, client, auth_headers
    ):
        """
        Authoring content ahead of its collector is legitimate — a later phase
        will need it. Reporting it as invalid would block that; reporting
        nothing would let it ship silently unexecutable.

        Uses ``api`` on ``container``, because Phase 7 implemented
        ``database_query`` on ``database`` and this test needs a pair that
        genuinely has no collector. Swapping the pair rather than deleting the
        test keeps the warning path covered.
        """
        body = self._validate(
            client,
            auth_headers,
            check_type="api",
            platforms=["container"],
            collect={"endpoint": "/version"},
        ).json()
        assert body["valid"] is True
        assert body["warnings"]
        assert "no collector" in body["warnings"][0]

    def test_a_database_rule_no_longer_warns_now_that_it_can_run(
        self, client, auth_headers
    ):
        """
        The other side of the test above. A ``database_query`` rule was warned
        about as unexecutable until Phase 7; continuing to warn would tell a
        rule author their working rule cannot run.
        """
        body = self._validate(
            client,
            auth_headers,
            check_type="database_query",
            platforms=["database"],
            collect={"sql": "SHOW ssl", "engine": "postgresql"},
        ).json()
        assert body["valid"] is True
        assert not [w for w in body["warnings"] if "no collector" in w]

    def test_validation_contacts_no_target(self, client, auth_headers, monkeypatch):
        """
        The endpoint takes a rule, not a host. Nothing in it may open a
        session, and a regex it is handed is compiled but never matched.
        """
        from core.config_audit.collectors import base

        def explode(*_args, **_kwargs):
            raise AssertionError("validation must not run a command")

        monkeypatch.setattr(base.ShellRunner, "run", explode)
        assert self._validate(client, auth_headers).json()["valid"] is True


class TestTheRoutesAreRegisteredCorrectly:
    def test_every_limited_route_declares_a_response_parameter(self):
        """
        The limiter is built ``headers_enabled=True``, so slowapi writes
        X-RateLimit-* after the handler returns and finds the response only if
        the handler returned one or declared ``response: Response``. A handler
        that does neither hands slowapi ``None`` and raises inside the endpoint
        call — a 500 on every request to that route, invisible in the suite
        because ``conftest`` disables the limiter.
        """
        import inspect

        from routers import config_audit as module
        from scan_helpers import limiter

        registered = {
            key.rsplit(".", 1)[-1] for key in limiter._route_limits  # noqa: SLF001
        }
        for name, handler in vars(module).items():
            if not callable(handler) or name not in registered:
                continue
            parameters = inspect.signature(handler).parameters
            assert "response" in parameters, name

    def test_body_models_are_namespaced_to_this_router(self):
        """
        FastAPI keys OpenAPI component schemas by class name. Phases 1 and 2
        each shipped a collision that silently replaced another router's schema
        in the generated contract.
        """
        from routers import config_audit as module

        from pydantic import BaseModel

        models = [
            name
            for name, obj in vars(module).items()
            if isinstance(obj, type)
            and issubclass(obj, BaseModel)
            and obj is not BaseModel
        ]
        assert models
        assert all(name.startswith("ConfigAudit") for name in models), models
