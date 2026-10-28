"""
SQL fragments the models' CHECK constraints are built from.

Shared by the compliance catalogue's vocabularies (``db/models/compliance.py``)
and the credential store's (``db/models/credentials.py``). It became a module
of its own when G2 (C5, docs/architecture/MODULAR_REFACTORING_LOG.md §6) moved
the credential model out of the compliance file, so that neither model module
imports the other for it. Standard library only.
"""


def sql_in_list(values) -> str:
    """
    Render a tuple as a SQL ``IN`` list.

    ``str(("key",))`` is ``('key',)`` — Python's one-element tuple repr carries
    a trailing comma that PostgreSQL rejects with "syntax error at or near )".
    Every existing constant of this shape in the codebase escapes the problem
    only by happening to have more than one member, which is luck rather than
    design: adding a fifth severity is safe, dropping to one is not.

    The ``compliance_rules`` vocabularies and the credential constants use it,
    and render byte-identical CHECK constraints to the migrations that created
    them.
    """
    return "(" + ", ".join("'%s'" % v for v in values) + ")"
