"""
B10: the configuration audit imports no engine.

Two imports put it on top of the credentialed engine: the database collector
took ``normalize_engine`` from ``engines.credentialed.database_executor`` for its
engine backstop, and the SCAP evaluator took ``compare_distro_versions`` from
``engines.credentialed.vuln_matcher`` for every OVAL version comparison. Both are
now injected:

* the collector asks the executor it was handed (``DatabaseSession.
  normalize_engine``);
* the evaluator uses ``CollectionContext.version_compare``, which the two places
  production builds a context (``scans/tasks/credentialed.py``) set to the matcher's
  comparator.

These pin the purpose (statically, and by running both with ``engines`` made
unimportable), that production's contexts carry the comparator, and the
behaviour at the seams: no comparator is unknown, never a verdict, and the
executor's folding is the one used. B10's golden capture, the production audit
paths byte-identical, is recorded in the refactoring log (§6).
"""

import ast
import json
import subprocess
import sys

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.database import DatabaseQueryCollector
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation
from core.scap.evaluate import Outcome, evaluate_definition
from engines.credentialed.database_executor import DatabaseSession, QueryResult
from engines.credentialed.vuln_matcher import compare_distro_versions
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

# ── The purpose ──────────────────────────────────────────────────────────────

#: Edges out of the evaluation path that are not to the check kernel. Empty
#: since G4: the CCI crosswalk read the seeded NIST catalogue through
#: ``core.compliance_seeds``, and the STIG loader passes it in now.
_KNOWN: set = set()


def test_the_audit_engine_and_scap_evaluation_depend_only_on_the_check_kernel():
    """
    The plan's target, for the engine, its collectors and the SCAP compiler and
    evaluator. The benchmark loader and selection are compliance's since C4,
    and the router is the HTTP edge; neither is here. Lazy imports count.
    """
    _, edges = collect_edges()
    beyond = sorted(
        (e.src, e.dst)
        for e in edges
        if e.src.startswith(("core.config_audit", "core.scap"))
        and capability_map.capability_of(e.dst) not in ("config_audit", "check_kernel")
        and (e.src, e.dst) not in _KNOWN
    )
    assert beyond == []
    # Not vacuous: both modules this step changed are in the graph.
    names = {e.src for e in edges}
    assert {"core.config_audit.collectors.database", "core.scap.evaluate"} <= names


def test_no_config_audit_module_imports_an_engine():
    _, edges = collect_edges()
    assert not [
        (e.src, e.dst)
        for e in edges
        if capability_map.capability_of(e.src) == "config_audit"
        and e.dst.split(".")[0] == "engines"
    ]


_WITHOUT_ENGINES = r"""
import json, sys


class NoEngines:
    def find_spec(self, name, path=None, target=None):
        if name == "engines" or name.startswith("engines."):
            raise ModuleNotFoundError(f"blocked for the test: {name}")
        return None


sys.meta_path.insert(0, NoEngines())

from core.config_audit.collection import CollectionContext
from core.config_audit.collectors.database import DatabaseQueryCollector
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation
from core.scap.evaluate import evaluate_definition

# A comparator that orders by length then text: anything injected is used.
def by_length(left, right):
    key = lambda v: (len(v), v)
    return (key(left) > key(right)) - (key(left) < key(right))


class Shell:
    def run(self, command, timeout=None):
        class R:
            stdout = "CCURE::FOUND::Setting 10.0\n"
            stderr = ""
            exit_code = 0
            success = True
        return R()


compiled = {
    "criteria": {"kind": "criteria", "operator": "AND", "negate": False,
                 "children": [{"kind": "test", "test": "t1", "negate": False}]},
    "tests": {"t1": {"type": "independent:textfilecontent54_test", "object": "o1",
                     "states": ["s1"], "check": "all",
                     "check_existence": "at_least_one_exists"}},
    "objects": {"o1": {"type": "independent:textfilecontent54_object",
                       "entities": {"filepath": {"values": ["/etc/x.conf"], "operation": "equals"},
                                    "pattern": {"values": [r"^Setting\s+(\S+)$"],
                                                "operation": "pattern match"}},
                       "behaviors": {}, "filters": []}},
    "states": {"s1": {"operator": "AND", "fields": [
        {"name": "subexpression", "operation": "greater than", "datatype": "version",
         "value": {"values": ["9.0"]}, "entity_check": "all"}]}},
    "variables": {},
}
context = CollectionContext(target="t", platform="linux", executor=Shell(),
                            version_compare=by_length)
scap = evaluate_definition(context, compiled).outcome.value


class Session:
    engine = "postgresql"

    @staticmethod
    def normalize_engine(name):
        return {"postgres": "postgresql", "postgresql": "postgresql", "mysql": "mysql"}.get(
            str(name).lower(), ""
        )

    def query(self, statement, params=None, timeout=None):
        raise AssertionError("a mismatched engine must not be queried")


check = ConfigCheck(check_id="ccure.db.b10.blocked", title="t", check_type="database_query",
                    platforms=("database",), collect={"sql": "SHOW x", "engine": "mysql"},
                    expect=Expectation("equals", "on"), absent=AbsencePolicy.MANUAL_REVIEW)
state = DatabaseQueryCollector().collect(
    check, CollectionContext(target="db", platform="database", executor=Session()))
print(json.dumps({
    "scap": scap,
    "database": state.status.value,
    "engines_loaded": sorted(m for m in sys.modules if m.split(".")[0] == "engines"),
}))
"""


def test_both_run_with_the_engines_unimportable():
    """
    Run, not read: in an interpreter where ``engines`` cannot be imported, the
    SCAP evaluator orders versions with the comparator it is handed, and the
    database collector's backstop folds names with the executor's own. On the
    parent the first raised ``ModuleNotFoundError`` out of the comparison and
    the second silently lost its backstop.
    """
    done = subprocess.run(
        [sys.executable, "-c", _WITHOUT_ENGINES],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen == {"scap": "true", "database": "unsupported", "engines_loaded": []}


# ── Production composes them ─────────────────────────────────────────────────


def test_every_context_production_builds_carries_the_comparator():
    """A context without one would turn every OVAL version comparison into an
    unknown, and every such rule into an ERROR on every host."""
    sites = []
    for path in (BACKEND_ROOT / "scans" / "tasks" / "credentialed.py",):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "id", getattr(node.func, "attr", None))
                == "CollectionContext"
            ):
                given = {k.arg: k.value for k in node.keywords}
                value = given.get("version_compare")
                sites.append((node.lineno, getattr(value, "id", None)))
    assert len(sites) == 2, sites
    assert all(name == "compare_distro_versions" for _, name in sites), sites


def test_no_other_production_module_builds_a_context():
    from scripts.architecture.import_graph import discover_modules

    builders = set()
    for module, path in discover_modules().items():
        if module.split(".")[0] in ("tests", "scripts", "alembic"):
            continue
        source = path.read_text(encoding="utf-8")
        if "CollectionContext(" in source and module != "core.config_audit.collection":
            builders.add(module)
    assert builders == {"scans.tasks.credentialed"}


# ── The seams ────────────────────────────────────────────────────────────────


def _version_definition(actual, operation, expected, datatype="evr_string"):
    import test_scap_evaluation as tse

    compiled = tse.one_test_definition(states=["s1"])
    compiled["states"]["s1"]["fields"][0].update(
        operation=operation, datatype=datatype, value={"values": [expected]}
    )
    shell = tse.FakeShell([("example.conf", tse.found(f"Setting {actual}\n"))])
    return shell, compiled


def test_without_a_comparator_a_version_comparison_is_unknown_never_a_verdict():
    shell, compiled = _version_definition(
        "2.34-266.el9_8", "less than", "2.34-274.el9_8"
    )
    context = CollectionContext(target="t", platform="linux", executor=shell)
    assert context.version_compare is None
    assert evaluate_definition(context, compiled).outcome is Outcome.UNKNOWN


def test_with_the_matchers_comparator_the_matchers_order_decides():
    """A backported fix, an epoch and a tilde: what a naive order gets wrong."""
    for actual, operation, expected, outcome in (
        ("2.34-266.el9_8", "less than", "2.34-274.el9_8", Outcome.TRUE),
        ("1:1.0-1", "greater than", "0:2.0-1", Outcome.TRUE),
        ("1.0~rc1-1", "less than", "1.0-1", Outcome.TRUE),
        ("1.0", "equals", "1.0.0", Outcome.FALSE),
    ):
        shell, compiled = _version_definition(actual, operation, expected)
        context = CollectionContext(
            target="t",
            platform="linux",
            executor=shell,
            version_compare=compare_distro_versions,
        )
        assert evaluate_definition(context, compiled).outcome is outcome, actual


def test_an_object_filter_orders_versions_with_the_injected_comparator():
    """
    The comparator's third use: a filter keeps the items above a version, and
    existence is then decided by how many survive. Without the comparator the
    filter cannot be applied, and that is unknown rather than "none survive".
    """
    import json as _json

    import test_scap_evaluation as tse

    compiled = tse.one_test_definition(states=[])
    state = _json.loads(
        _json.dumps(tse.one_test_definition(states=["s1"])["states"]["s1"])
    )
    state["fields"][0].update(
        operation="greater than", datatype="evr_string", value={"values": ["0:2.0-1"]}
    )
    compiled["states"]["f1"] = state
    compiled["objects"]["o1"]["filters"] = [{"state": "f1", "action": "include"}]
    shell = tse.FakeShell(
        [("example.conf", tse.found("Setting 0:1.9-9\nSetting 1:0.1-1\n"))]
    )

    with_matcher = CollectionContext(
        target="t",
        platform="linux",
        executor=shell,
        version_compare=compare_distro_versions,
    )
    # 1:0.1-1 outranks 0:2.0-1 by epoch, so one item survives and the test holds.
    assert evaluate_definition(with_matcher, compiled).outcome is Outcome.TRUE

    without = CollectionContext(target="t", platform="linux", executor=shell)
    assert evaluate_definition(without, compiled).outcome is Outcome.UNKNOWN


def _db_check(engine):
    return ConfigCheck(
        check_id="ccure.db.b10.example",
        title="example",
        check_type="database_query",
        platforms=("database",),
        collect={"sql": "SHOW x", "engine": engine},
        expect=Expectation("equals", "on"),
        absent=AbsencePolicy.MANUAL_REVIEW,
    )


class _Session:
    def __init__(self, engine, fold=None):
        self.engine = engine
        if fold is not None:
            self.normalize_engine = fold
        self.queried = []

    def query(self, statement, params=None, timeout=None):
        self.queried.append(statement)
        return QueryResult(statement, rows=[("on",)], ok=True)


def _db_ctx(session):
    return CollectionContext(target="db", platform="database", executor=session)


def test_the_executors_folding_is_the_one_used():
    folds_everything = _Session("postgresql", fold=lambda name: "postgresql")
    state = DatabaseQueryCollector().collect(
        _db_check("mysql"), _db_ctx(folds_everything)
    )
    assert isinstance(state, CollectedState)
    assert state.value == "on"  # the executor said "mysql" is itself

    strict = _Session("postgresql", fold=DatabaseSession.normalize_engine)
    state = DatabaseQueryCollector().collect(_db_check("MariaDB"), _db_ctx(strict))
    assert state.status.value == "unsupported" and strict.queried == []


def test_an_executor_that_cannot_fold_names_gets_no_backstop():
    """As when the import failed: the query runs and its answer stands."""
    session = _Session("postgresql")
    state = DatabaseQueryCollector().collect(_db_check("mysql"), _db_ctx(session))
    assert state.value == "on" and session.queried == ["SHOW x"]


def test_the_session_folds_names_exactly_as_the_module_does():
    from engines.credentialed.database_executor import normalize_engine

    for name in (
        "postgres",
        "PostgreSQL",
        "pgsql",
        "MariaDB",
        "SQL Server",
        "oracle",
        "",
    ):
        assert DatabaseSession.normalize_engine(name) == normalize_engine(name)
