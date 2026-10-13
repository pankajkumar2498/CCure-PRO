"""Platform-owned organisation settings.

The platform stores authorised scan ranges and configured remediation deadlines.
Audit consumes them through ``core.scan_scope`` and ``core.remediation.sla``;
each feature has one consumer so storage and assessment logic stay separate.
"""
