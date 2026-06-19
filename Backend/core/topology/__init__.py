"""
core/topology — SNMP-based network topology discovery.

Components:
  client.py  — Low-level SNMP walks (ARP, LLDP, CDP, FDB)
  engine.py  — Correlation engine (converts walk results → NetworkLink graph)
"""
