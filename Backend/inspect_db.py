import sys
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models.assets import Asset
from db.models.amt import AMTInventoryRecord
from core.utils import normalize_mac

DATABASE_URL = "postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/ccure_test"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

try:
    print("--- Scanned Assets ---")
    assets = db.query(Asset).all()
    print(f"Total active assets in DB: {len(assets)}")
    for a in assets:
        print(f"ID: {a.id}")
        print(f"  IP: {a.ip_address}")
        print(f"  MAC: {a.mac_address} (type: {type(a.mac_address)})")
        print(f"  Normalized MAC: {normalize_mac(str(a.mac_address))}")
        print(f"  Owner: {a.owner}")
        print(f"  CustomAttributes: {a.custom_attributes}")
        print(f"  Provenance: {a.provenance}")

    print("\n--- AMT Inventory Records ---")
    amt_recs = db.query(AMTInventoryRecord).all()
    print(f"Total AMT records in DB: {len(amt_recs)}")
    for r in amt_recs:
        print(f"ID: {r.id}")
        print(f"  Tag: {r.asset_tag}")
        print(f"  MAC1: {r.mac_address_1} (type: {type(r.mac_address_1)})")
        print(f"  Normalized MAC1: {normalize_mac(str(r.mac_address_1))}")
        print(f"  MAC2: {r.mac_address_2} (type: {type(r.mac_address_2)})")
        print(f"  Normalized MAC2: {normalize_mac(str(r.mac_address_2))}")
        print(f"  User: {r.asset_user}")
        print(f"  EmpID: {r.emp_id}")
        print(f"  Serial: {r.serial}")
finally:
    db.close()
