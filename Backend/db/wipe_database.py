"""
db/wipe_database.py
──────────────────────────────────────────────────────────────────────────────
Drops all tables by dynamically reflecting them, ignoring permission errors
on dropping the schema itself.
"""

import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from sqlalchemy import MetaData
from db.base import engine

def wipe_database():
    print("WARNING: Dropping all tables...")
    
    meta = MetaData()
    meta.reflect(bind=engine)
    
    meta.drop_all(bind=engine)
        
    print("All tables dropped via reflection. Ready for fresh production migration.")

if __name__ == "__main__":
    wipe_database()
