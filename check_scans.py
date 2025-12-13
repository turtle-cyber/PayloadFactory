"""Quick script to check recent scans in MongoDB"""
from ml_engine.db_manager import DatabaseManager

db = DatabaseManager()

if db.connected:
    scans = list(db.db['scans'].find().sort('timestamps.submitted_at', -1).limit(5))
    print("Recent scans:")
    for s in scans:
        print(f"  ID: {s['_id']}")
        print(f"    remote_host: {s.get('remote_host', 'NOT SET')}")
        print(f"    remote_port: {s.get('remote_port', 'NOT SET')}")
        print(f"    status: {s.get('status')}")
        print(f"    auto_execute: {s.get('auto_execute')}")
        print("")
else:
    print("Database not connected")
