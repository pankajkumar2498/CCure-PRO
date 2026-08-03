"""
core/topology — SNMP-based network topology discovery.

Components:
  identity.py — Endpoint identity: what counts as a MAC, and what a device is
                called when no MAC is available
  client.py   — Low-level SNMP walks (ARP, LLDP/CDP/EDP, FDB) and the liveness
                probe that keeps non-SNMP hosts from costing a full walk
  engine.py   — Correlation engine (walk results → NetworkLink rows → graph)

Validated end to end against an Extreme X670V-48x on EXOS 15.3.1.4: ~900 ARP
entries, ~1000 FDB entries, six EDP neighbours, 31 subnets, in ~15s.
"""
