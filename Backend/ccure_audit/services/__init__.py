"""
Audit application services.

Each service answers questions about Audit's own data and returns **views**
(``ccure_audit.services.views``): frozen dataclasses of plain values. A service
never returns an ORM object, never imports a contract type, and never serves
HTTP. The integration adapter turns views into contract messages; Audit's own
reports can render the same views, so the two cannot disagree.
"""
