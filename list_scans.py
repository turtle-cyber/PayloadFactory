"""List all scans in the database"""
from ml_engine.db_manager import DatabaseManager

db = DatabaseManager()

if db.connected:
    scans = list(db.db['scans'].find({}, {'project_name': 1, 'status': 1, '_id': 1}))
    print("SCANS IN DATABASE:")
    for s in scans:
        print(f"  {s['_id']}: {s.get('project_name', 'N/A')} - {s.get('status', 'N/A')}")
    print(f"\nTotal scans: {len(scans)}")
else:
    print("MongoDB not connected!")
